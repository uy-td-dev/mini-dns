//! Shared server state and the top-level query resolution logic.

use crate::cache::Cache;
use crate::config::{load_zone_file, Zone};
use crate::dns::header::DnsHeader;
use crate::dns::packet::DnsPacket;
use crate::dns::record::DnsRecord;
use crate::forwarder::Forwarder;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// A shared, reference-counted forwarded response (for single-flight sharing).
type SharedReply = Arc<Vec<u8>>;

/// The transport a request arrived on, which determines response framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP: responses are capped at 512 bytes (TC bit set if larger).
    Udp,
    /// TCP: responses may be any size.
    Tcp,
}

const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

/// Outcome of the synchronous, allocation-light first pass over a query.
///
/// Splitting the synchronous part ([`ServerState::resolve_local`]) from the
/// async forwarding part lets the UDP fast path answer local/cached queries
/// inline — no task spawn, no request copy — and only spawn when a query must
/// actually be forwarded upstream (the one path that awaits).
pub enum Resolution {
    /// A response is ready to send.
    Ready(Vec<u8>),
    /// The query must be forwarded upstream (carries the work to do so).
    Forward(ForwardCtx),
    /// The query was dropped (rate-limited or unparseable); send nothing.
    Drop,
}

/// Everything needed to forward a query upstream and frame the reply.
pub struct ForwardCtx {
    request: DnsPacket,
    raw: Vec<u8>,
    name: String,
    qtype: u16,
    transport: Transport,
}

/// All shared state needed to answer queries: the zone (hot-swappable), an
/// optional upstream forwarder, a cache, a rate limiter, and metrics.
pub struct ServerState {
    zone: ArcSwap<Zone>,
    zone_path: Option<String>,
    forwarder: Option<Forwarder>,
    cache: Cache,
    limiter: RateLimiter,
    /// In-flight forwarded queries, keyed by `(name, qtype)`, for single-flight
    /// coalescing of concurrent identical misses.
    inflight: DashMap<(String, u16), watch::Receiver<Option<SharedReply>>>,
    pub metrics: Metrics,
}

impl ServerState {
    /// Builds full server state.
    pub fn new(
        zone: Zone,
        zone_path: Option<String>,
        forwarder: Option<Forwarder>,
        cache: Cache,
        limiter: RateLimiter,
    ) -> Self {
        ServerState {
            zone: ArcSwap::from_pointee(zone),
            zone_path,
            forwarder,
            cache,
            limiter,
            inflight: DashMap::new(),
            metrics: Metrics::default(),
        }
    }

    /// Convenience constructor for a purely authoritative server (no forwarding,
    /// no rate limiting). Handy for tests.
    pub fn authoritative(zone: Zone) -> Arc<Self> {
        Arc::new(Self::new(
            zone,
            None,
            None,
            Cache::new(1024),
            RateLimiter::disabled(),
        ))
    }

    /// Returns a cheap, lock-free snapshot handle to the current zone.
    fn zone(&self) -> Arc<Zone> {
        self.zone.load_full()
    }

    /// Reloads the zone from disk (if a path was configured) and swaps it in
    /// atomically. In-flight requests keep using the previous snapshot.
    pub fn reload(&self) -> Result<()> {
        if let Some(path) = &self.zone_path {
            let zone = load_zone_file(path)?;
            let count: usize = zone.values().map(Vec::len).sum();
            self.zone.store(Arc::new(zone));
            info!(path, records = count, "zone reloaded");
        } else {
            warn!("reload requested but no zone file path is configured");
        }
        Ok(())
    }

    /// Whether this server offers recursion (i.e. a forwarder is configured).
    fn recursion_available(&self) -> bool {
        self.forwarder.is_some()
    }

    /// Reclaims rate-limiter state for clients whose window has elapsed.
    ///
    /// Called periodically by a background task to bound memory under a flood of
    /// many distinct (e.g. spoofed) source addresses.
    pub fn cleanup_rate_limiter(&self) {
        self.limiter.cleanup();
    }

    /// Resolves a raw request, awaiting upstream forwarding when needed.
    ///
    /// Connection-based transports (TCP/DoT/DoH) use this directly. The UDP
    /// fast path instead calls [`resolve_local`](Self::resolve_local) and only
    /// awaits [`forward_ctx`](Self::forward_ctx) for the forward case.
    pub async fn resolve(&self, req: &[u8], client: IpAddr, transport: Transport) -> Option<Vec<u8>> {
        match self.resolve_local(req, client, transport) {
            Resolution::Ready(bytes) => Some(bytes),
            Resolution::Drop => None,
            Resolution::Forward(ctx) => Some(self.forward_ctx(ctx).await),
        }
    }

    /// Synchronous first pass: rate-limit, parse, answer from the zone or cache.
    ///
    /// Does no I/O and allocates the request copy only on the forward path, so
    /// the common local/cached case is cheap enough to run inline on the
    /// receiving worker without spawning a task.
    pub fn resolve_local(&self, req: &[u8], client: IpAddr, transport: Transport) -> Resolution {
        self.metrics.inc_total();

        if !self.limiter.allow(client) {
            self.metrics.inc_rate_limited();
            debug!(%client, "query dropped by rate limiter");
            return Resolution::Drop;
        }

        let request = match DnsPacket::from_bytes(req) {
            Ok(packet) => packet,
            Err(e) => {
                self.metrics.inc_error();
                warn!(%client, error = %e, "failed to parse DNS packet");
                return Resolution::Drop;
            }
        };
        debug!(%client, questions = ?request.questions, "received query");

        let zone = self.zone();
        let mut response = request.build_response(&zone);
        let rcode = response.header.flags & 0x000F;
        let rd_set = request.header.flags & FLAG_RD != 0;

        // Forward only when the name is unknown locally, recursion is offered,
        // and the client actually requested recursion.
        if rcode == RCODE_NXDOMAIN && rd_set && self.recursion_available() {
            if let Some(question) = request.questions.first() {
                let name = question.qname.to_lowercase();
                let qtype = question.qtype;

                if let Some(cached) = self.cache.get(&name, qtype) {
                    self.metrics.inc_cache_hit();
                    debug!(%name, qtype, "cache hit");
                    let mut bytes = (*cached).clone();
                    patch_transaction_id(&mut bytes, request.header.id);
                    return Resolution::Ready(bytes);
                }

                return Resolution::Forward(ForwardCtx {
                    request,
                    raw: req.to_vec(),
                    name,
                    qtype,
                    transport,
                });
            }
        }

        // Local (authoritative) answer.
        self.metrics.inc_authoritative();
        if self.recursion_available() {
            response.header.flags |= FLAG_RA;
        }
        Resolution::Ready(encode(&response, transport))
    }

    /// Forwards the query upstream and returns the bytes to relay to the client.
    ///
    /// Single-flight: the first caller for a `(name, qtype)` performs the upstream
    /// query; concurrent callers for the same key wait for and share that one
    /// response (each gets its own copy with its transaction ID patched in). This
    /// prevents a "thundering herd" of identical upstream queries on a cache miss.
    pub async fn forward_ctx(&self, ctx: ForwardCtx) -> Vec<u8> {
        enum Role {
            Leader(watch::Sender<Option<SharedReply>>),
            Follower(watch::Receiver<Option<SharedReply>>),
        }

        let key = (ctx.name.clone(), ctx.qtype);
        let role = match self.inflight.entry(key.clone()) {
            Entry::Occupied(e) => Role::Follower(e.get().clone()),
            Entry::Vacant(e) => {
                let (tx, rx) = watch::channel(None);
                e.insert(rx);
                Role::Leader(tx)
            }
        };

        match role {
            // Leader: do the real upstream query, publish the result, clean up.
            Role::Leader(tx) => {
                let bytes = self.forward_and_cache(&ctx).await;
                let _ = tx.send(Some(Arc::new(bytes.clone())));
                self.inflight.remove(&key);
                bytes
            }
            // Follower: wait for the leader's shared result, then patch our ID.
            Role::Follower(mut rx) => {
                self.metrics.inc_coalesced();
                let shared = loop {
                    if let Some(reply) = rx.borrow().clone() {
                        break Some(reply);
                    }
                    if rx.changed().await.is_err() {
                        break rx.borrow().clone(); // sender dropped; take final value
                    }
                };
                match shared {
                    Some(reply) => {
                        let mut bytes = (*reply).clone();
                        patch_transaction_id(&mut bytes, ctx.request.header.id);
                        bytes
                    }
                    None => {
                        // Leader vanished without publishing; fail closed.
                        let servfail =
                            self.synth_response(&ctx.request, Vec::new(), RCODE_SERVFAIL);
                        encode(&servfail, ctx.transport)
                    }
                }
            }
        }
    }

    /// Performs the actual upstream query, caches any parseable answers, and
    /// returns the bytes to relay (SERVFAIL on failure).
    async fn forward_and_cache(&self, ctx: &ForwardCtx) -> Vec<u8> {
        let forwarder = self.forwarder.as_ref().expect("forwarder present");
        match forwarder.forward(&ctx.raw).await {
            Ok(response_bytes) => {
                self.metrics.inc_forwarded();
                debug!(name = %ctx.name, qtype = ctx.qtype, upstream = %forwarder.upstream(), "forwarded query");

                // Cache the raw response (positive answers and negative
                // NXDOMAIN/NODATA results); relayed bytes are unaffected.
                if let Ok(parsed) = DnsPacket::from_bytes(&response_bytes) {
                    if let Some(ttl) = cache_ttl(&parsed) {
                        self.cache.insert(&ctx.name, ctx.qtype, response_bytes.clone(), ttl);
                    }
                }
                response_bytes
            }
            Err(e) => {
                self.metrics.inc_error();
                warn!(name = %ctx.name, error = %e, "upstream forwarding failed");
                let servfail = self.synth_response(&ctx.request, Vec::new(), RCODE_SERVFAIL);
                encode(&servfail, ctx.transport)
            }
        }
    }

    /// Builds a non-authoritative response (cache hit or error) echoing the
    /// request's questions, with RA set since recursion is available here.
    fn synth_response(
        &self,
        request: &DnsPacket,
        answers: Vec<crate::dns::record::DnsRecord>,
        rcode: u16,
    ) -> DnsPacket {
        let flags = 0x8000 | (request.header.flags & FLAG_RD) | FLAG_RA | rcode;
        DnsPacket {
            header: DnsHeader {
                id: request.header.id,
                flags,
                questions: request.questions.len() as u16,
                answers: answers.len() as u16,
                authorities: 0,
                additionals: 0,
            },
            questions: request.questions.clone(),
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

/// Encodes a synthesized response for the given transport.
fn encode(packet: &DnsPacket, transport: Transport) -> Vec<u8> {
    match transport {
        Transport::Udp => packet.to_udp_bytes(),
        Transport::Tcp => packet.to_bytes(),
    }
}

/// Overwrites the 2-byte transaction ID at the start of a DNS message.
///
/// A single-flight follower shares the leader's response bytes, which carry the
/// leader's ID; this patches in the follower's own ID so the client accepts it.
fn patch_transaction_id(bytes: &mut [u8], id: u16) {
    if bytes.len() >= 2 {
        bytes[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Default TTL (seconds) for caching a negative result that lacks an SOA.
const NEG_TTL_DEFAULT: u32 = 30;
/// Upper bound (seconds) on negative-cache TTL derived from an SOA minimum.
const NEG_TTL_MAX: u32 = 3600;

/// Computes the cache TTL for a forwarded response, or `None` if it should not
/// be cached.
///
/// Positive answers use the smallest answer TTL. Negative results (NXDOMAIN or
/// NODATA) use the SOA minimum from the authority section (capped), or a small
/// default. SERVFAIL and other rcodes are not cached.
fn cache_ttl(packet: &DnsPacket) -> Option<u32> {
    let rcode = packet.header.flags & 0x000F;
    if !packet.answers.is_empty() {
        return Some(packet.answers.iter().map(|r| r.ttl()).min().unwrap_or(0));
    }
    if rcode == RCODE_NXDOMAIN || rcode == 0 {
        let soa_minimum = packet.authorities.iter().find_map(|r| match r {
            DnsRecord::SOA { minimum, .. } => Some(*minimum),
            _ => None,
        });
        return Some(soa_minimum.map(|m| m.min(NEG_TTL_MAX)).unwrap_or(NEG_TTL_DEFAULT));
    }
    None
}
