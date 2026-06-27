//! Shared server state and the top-level query resolution logic.

use crate::acl::Acl;
use crate::blocklist::Blocklist;
use crate::cache::Cache;
use crate::config::{load_zone_file, ForwardRules, ZoneSet};
use crate::dns::header::DnsHeader;
use crate::dns::packet::DnsPacket;
use crate::dns::record::DnsRecord;
use crate::dnssec::DnssecKeys;
use crate::forwarder::MultiForwarder;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::recursive::RecursiveResolver;
use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// The upstream resolver chosen for this query (via conditional forwarding).
    upstream: SocketAddr,
    transport: Transport,
}

/// All shared state needed to answer queries: the zone set (hot-swappable),
/// conditional forwarding rules, an upstream forwarder, a cache, a rate
/// limiter, and metrics.
pub struct ServerState {
    zones: ArcSwap<ZoneSet>,
    /// Path(s) for hot-reload. When using a config file this is the config
    /// path (so SIGHUP reloads all zones from it); with a single `--zone` it
    /// is that zone file's path.
    zone_path: Option<String>,
    /// Conditional forwarding rules (per-domain upstream selection).
    forward_rules: ForwardRules,
    forwarder: Option<MultiForwarder>,
    /// Optional full recursive resolver (iterative, root-hints based).
    /// When present, unknown names are resolved iteratively instead of
    /// forwarded to a stub upstream. Conditional forwarding rules still take
    /// precedence (matched names go to their configured upstream).
    recursive: Option<Arc<RecursiveResolver>>,
    cache: Cache,
    limiter: RateLimiter,
    /// Optional domain blocklist (RPZ-style filtering).
    pub blocklist: Blocklist,
    /// Optional NAT64 prefix for DNS64 AAAA synthesis (RFC 6147).
    /// When set, AAAA queries for names that have only A records get
    /// synthesized AAAA records by embedding the IPv4 address in the prefix.
    dns64_prefix: Option<Ipv6Addr>,
    /// ACL controlling which client IPs may request AXFR (zone transfer).
    axfr_acl: Acl,
    /// Optional DNSSEC signing keys. When present, responses include DNSKEY
    /// records at zone apexes and RRSIG records over answer RRsets.
    dnssec_keys: Option<Arc<DnssecKeys>>,
    /// In-flight forwarded queries, keyed by `(name, qtype)`, for single-flight
    /// coalescing of concurrent identical misses.
    inflight: DashMap<(String, u16), watch::Receiver<Option<SharedReply>>>,
    pub metrics: Metrics,
}

impl ServerState {
    /// Builds full server state.
    pub fn new(
        zones: ZoneSet,
        zone_path: Option<String>,
        forward_rules: ForwardRules,
        forwarder: Option<MultiForwarder>,
        cache: Cache,
        limiter: RateLimiter,
    ) -> Self {
        ServerState {
            zones: ArcSwap::from_pointee(zones),
            zone_path,
            forward_rules,
            forwarder,
            recursive: None,
            cache,
            limiter,
            blocklist: Blocklist::empty(),
            dns64_prefix: None,
            axfr_acl: Acl::deny_all(),
            dnssec_keys: None,
            inflight: DashMap::new(),
            metrics: Metrics::default(),
        }
    }

    /// Sets the domain blocklist (builder-style chaining).
    pub fn with_blocklist(mut self, blocklist: Blocklist) -> Self {
        self.blocklist = blocklist;
        self
    }

    /// Enables DNS64 AAAA synthesis with the given NAT64 prefix (builder-style).
    pub fn with_dns64(mut self, prefix: Ipv6Addr) -> Self {
        self.dns64_prefix = Some(prefix);
        self
    }

    /// Sets the AXFR (zone transfer) ACL (builder-style chaining).
    pub fn with_axfr_acl(mut self, acl: Acl) -> Self {
        self.axfr_acl = acl;
        self
    }

    /// Enables full iterative recursive resolution (builder-style).
    /// When set, unknown names are resolved from root instead of forwarded.
    pub fn with_recursive(mut self) -> Self {
        self.recursive = Some(Arc::new(RecursiveResolver::new()));
        self
    }

    /// Enables DNSSEC signing of responses (builder-style).
    /// When set, the server publishes DNSKEY records and signs answer RRsets.
    pub fn with_dnssec(mut self, keys: DnssecKeys) -> Self {
        self.dnssec_keys = Some(Arc::new(keys));
        self
    }

    /// Convenience constructor for a purely authoritative server (no forwarding,
    /// no rate limiting). Handy for tests.
    pub fn authoritative(zones: ZoneSet) -> Arc<Self> {
        Arc::new(Self::new(
            zones,
            None,
            ForwardRules::none(),
            None,
            Cache::new(1024),
            RateLimiter::disabled(),
        ))
    }

    /// Returns a cheap, lock-free snapshot handle to the current zone set.
    fn zones(&self) -> Arc<ZoneSet> {
        self.zones.load_full()
    }

    /// Reloads the zones from disk (if a path was configured) and swaps them in
    /// atomically. In-flight requests keep using the previous snapshot.
    ///
    /// When a config file path is stored, SIGHUP reloads the entire config
    /// (all zones + forwarding rules) from it; with a single `--zone` flag,
    /// just that zone file is reloaded.
    pub fn reload(&self) -> Result<()> {
        let Some(path) = &self.zone_path else {
            warn!("reload requested but no zone/config path is configured");
            return Ok(());
        };

        // If the path looks like a TOML config, reload everything from it;
        // otherwise treat it as a single zone file (legacy --zone mode).
        if path.ends_with(".toml") {
            let settings = crate::config::load_settings(path)?;
            let new_zones = crate::config::load_zones_from_settings(&settings)?;
            let count = new_zones.record_count();
            let zone_count = new_zones.len();
            self.zones.store(Arc::new(new_zones));
            // Also reload the blocklist if configured.
            if let Some(_bl) = settings.blocklist.as_ref()
                && let Err(e) = self.blocklist.reload()
            {
                warn!(error = %e, "blocklist reload failed");
            }
            info!(path, zones = zone_count, records = count, "zones reloaded from config");
        } else {
            let zone = load_zone_file(path)?;
            let count: usize = zone.values().map(Vec::len).sum();
            // Single-zone legacy mode: wrap into a one-element ZoneSet.
            let origin = zone
                .values()
                .flatten()
                .find_map(|r| match r {
                    DnsRecord::SOA { domain, .. } => Some(domain.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            self.zones
                .store(Arc::new(ZoneSet::from_single(origin, zone)));
            info!(path, records = count, "zone reloaded");
        }
        Ok(())
    }

    /// Whether this server offers recursion (forwarding or recursive mode).
    fn recursion_available(&self) -> bool {
        self.forward_rules.is_enabled() || self.recursive.is_some()
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
        // AXFR (zone transfer) is only valid over TCP-based transports and
        // requires ACL authorization. Handle it before the normal path.
        if transport == Transport::Tcp
            && let Some(resp) = self.try_axfr(req, client)
        {
            return Some(resp);
        }
        match self.resolve_local(req, client, transport) {
            Resolution::Ready(bytes) => Some(bytes),
            Resolution::Drop => None,
            Resolution::Forward(ctx) => Some(self.forward_ctx(ctx).await),
        }
    }

    /// Handles an AXFR (zone transfer) request if this is one, returning the
    /// serialized response (all zone records framed by SOA) or `None` if the
    /// request is not an AXFR query.
    ///
    /// Returns a REFUSED response if the client is not in the ACL.
    fn try_axfr(&self, req: &[u8], client: IpAddr) -> Option<Vec<u8>> {
        let request = DnsPacket::from_bytes(req).ok()?;
        let question = request.questions.first()?;
        if question.qtype != DnsRecord::TYPE_AXFR {
            return None;
        }
        self.metrics.inc_total();

        // Authorization check.
        if !self.axfr_acl.is_allowed(&client) {
            self.metrics.inc_error();
            debug!(%client, "AXFR denied by ACL");
            let refused = self.synth_response(&request, Vec::new(), 5); // REFUSED
            return Some(refused.to_bytes());
        }

        // Find the zone matching the queried name.
        let zones = self.zones();
        let name = question.qname.to_lowercase();
        let zone = zones.find(&name);
        let Some(zone) = zone else {
            // Not authoritative for this zone.
            let nxdomain = self.synth_response(&request, Vec::new(), 3);
            return Some(nxdomain.to_bytes());
        };

        // AXFR response: SOA first, all records, SOA last (per RFC 5936).
        let mut records: Vec<DnsRecord> = Vec::new();
        // Collect SOA first (start of transfer).
        if let Some(soa) = zone.records.values().flatten().find(|r| matches!(r, DnsRecord::SOA { .. })) {
            records.push(soa.clone());
        }
        // Collect all other records sorted by owner name for deterministic output.
        let mut names: Vec<&String> = zone.records.keys().collect();
        names.sort();
        for owner in names {
            for r in &zone.records[owner] {
                if !matches!(r, DnsRecord::SOA { .. }) {
                    records.push(r.clone());
                }
            }
        }
        // SOA last (end of transfer).
        if let Some(soa) = zone.records.values().flatten().find(|r| matches!(r, DnsRecord::SOA { .. })) {
            records.push(soa.clone());
        }

        let flags = 0x8000 | (request.header.flags & FLAG_RD) | 0x0400; // QR + AA
        let response = DnsPacket {
            header: DnsHeader {
                id: request.header.id,
                flags,
                questions: 1,
                answers: records.len() as u16,
                authorities: 0,
                additionals: 0,
            },
            questions: request.questions.clone(),
            answers: records,
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        self.metrics.inc_authoritative();
        Some(response.to_bytes())
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

        // Blocklist check: if the queried name is on the blocklist, return
        // a synthesized NXDOMAIN immediately (before any zone lookup or
        // forwarding). This prevents blocked domains from being forwarded
        // upstream or answered from the local zone.
        if let Some(question) = request.questions.first()
            && self.blocklist.is_active()
            && self.blocklist.is_blocked(&question.qname)
        {
            self.metrics.inc_blocked();
            debug!(%client, name = %question.qname, "query blocked");
            let synth = self.synth_response(&request, Vec::new(), RCODE_NXDOMAIN);
            return Resolution::Ready(encode(&synth, transport));
        }

        let zones = self.zones();
        let mut response = request.build_response(&zones);
        let rcode = response.header.flags & 0x000F;
        let rd_set = request.header.flags & FLAG_RD != 0;

        // DNSSEC: if signing is enabled, add DNSKEY records for DNSKEY queries
        // at a zone apex, and sign answer RRsets with RRSIG.
        if let Some(ref keys) = self.dnssec_keys
            && let Some(question) = request.questions.first()
        {
            apply_dnssec(&mut response, &zones, &question.qname, question.qtype, keys);
        }

        // DNS64: if this was an AAAA query that got no AAAA answers but the
        // zone has A records for the name, synthesize AAAA records by
        // embedding the IPv4 address in the NAT64 prefix (RFC 6147).
        if let Some(ref prefix) = self.dns64_prefix
            && let Some(question) = request.questions.first()
            && question.qtype == DnsRecord::TYPE_AAAA
        {
            apply_dns64(&mut response, &zones, &question.qname, prefix);
        }

        // Forward only when the name is unknown locally, recursion is offered,
        // and the client actually requested recursion.
        if rcode == RCODE_NXDOMAIN && rd_set && self.recursion_available()
            && let Some(question) = request.questions.first()
        {
            let name = question.qname.to_lowercase();
            let qtype = question.qtype;

            if let Some(cached) = self.cache.get(&name, qtype) {
                self.metrics.inc_cache_hit();
                debug!(%name, qtype, "cache hit");
                return Resolution::Ready(replay(&cached, &request, transport));
            }

            // Check conditional forwarding rules first. If a rule matches,
            // forward to that specific upstream. Otherwise, if recursive mode
            // is enabled, resolve iteratively from root. If neither, the name
            // is truly unknown -> NXDOMAIN.
            if let Some(upstream) = self.forward_rules.match_name(&name) {
                return Resolution::Forward(ForwardCtx {
                    request,
                    raw: req.to_vec(),
                    name,
                    qtype,
                    upstream,
                    transport,
                });
            }

            // No forwarding rule matched. Try recursive resolution if enabled.
            if let Some(_resolver) = &self.recursive {
                return Resolution::Forward(ForwardCtx {
                    request,
                    raw: req.to_vec(),
                    name,
                    qtype,
                    // Use a sentinel address to signal recursive mode.
                    upstream: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    transport,
                });
            }

            // No forwarding and no recursive resolver: NXDOMAIN.
            self.metrics.inc_authoritative();
            return Resolution::Ready(encode(&response, transport));
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
            // The guard removes the single-flight entry on drop — even if the
            // task is cancelled mid-query — so the DashMap can't leak entries.
            Role::Leader(tx) => {
                let _guard = InflightGuard {
                    key,
                    inflight: &self.inflight,
                };
                let raw = self.forward_and_cache(&ctx).await;
                let shared = Arc::new(raw);
                let _ = tx.send(Some(Arc::clone(&shared)));
                replay(&shared, &ctx.request, ctx.transport)
            }
            // Follower: wait for the leader's shared result, then re-encode for
            // this client's transport and EDNS size.
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
                    Some(reply) => replay(&reply, &ctx.request, ctx.transport),
                    None => {
                        // Leader vanished without publishing; fail closed.
                        let servfail =
                            self.synth_response(&ctx.request, Vec::new(), RCODE_SERVFAIL);
                        replay(&servfail.to_bytes(), &ctx.request, ctx.transport)
                    }
                }
            }
        }
    }

    /// Performs the actual upstream query, caches any parseable answers, and
    /// returns the bytes to relay (SERVFAIL on failure).
    ///
    /// If the upstream is the sentinel `0.0.0.0:0`, this uses the iterative
    /// recursive resolver instead of forwarding to a stub upstream.
    async fn forward_and_cache(&self, ctx: &ForwardCtx) -> Vec<u8> {
        // Sentinel address signals recursive mode.
        let is_recursive = ctx.upstream.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            && ctx.upstream.port() == 0;

        let result = if is_recursive {
            // Iterative recursive resolution from root.
            let resolver = self.recursive.as_ref().expect("recursive resolver present");
            self.metrics.inc_forwarded();
            debug!(name = %ctx.name, qtype = ctx.qtype, "recursive resolution");
            resolver.resolve(&ctx.name, ctx.qtype, ctx.request.header.id).await
        } else {
            // Stub forwarding to a configured upstream.
            let forwarder = self.forwarder.as_ref().expect("forwarder present");
            let upstream = ctx.upstream;
            self.metrics.inc_forwarded();
            debug!(name = %ctx.name, qtype = ctx.qtype, upstream = %upstream, "forwarded query");
            forwarder.forward(&ctx.raw, upstream).await
        };

        match result {
            Ok(response_bytes) => {
                // Cache the raw response (positive answers and negative
                // NXDOMAIN/NODATA results); relayed bytes are unaffected.
                if let Ok(parsed) = DnsPacket::from_bytes(&response_bytes)
                    && let Some(ttl) = cache_ttl(&parsed)
                {
                    self.cache.insert(&ctx.name, ctx.qtype, response_bytes.clone(), ttl);
                }
                response_bytes
            }
            Err(e) => {
                self.metrics.inc_error();
                warn!(name = %ctx.name, error = %e, "upstream resolution failed");
                let servfail = self.synth_response(&ctx.request, Vec::new(), RCODE_SERVFAIL);
                // Return raw DNS message bytes (not transport-encoded); the
                // caller's replay() handles UDP truncation and EDNS echo.
                servfail.to_bytes()
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

/// Re-encodes a cached or forwarded raw DNS response for the current client's
/// transport and EDNS(0) UDP payload size.
///
/// For TCP the raw bytes are relayed with the transaction ID patched in (no
/// size limit). For UDP the response is parsed and re-encoded via
/// [`DnsPacket::to_udp_bytes`] using *this client's* EDNS size — not the
/// original querier's or the upstream's — so the TC (truncation) bit is set
/// correctly when the response exceeds what this client can receive.
fn replay(raw: &[u8], request: &DnsPacket, transport: Transport) -> Vec<u8> {
    match transport {
        Transport::Tcp => {
            let mut bytes = raw.to_vec();
            patch_transaction_id(&mut bytes, request.header.id);
            bytes
        }
        Transport::Udp => match DnsPacket::from_bytes(raw) {
            Ok(mut packet) => {
                packet.header.id = request.header.id;
                align_edns(&mut packet, request);
                packet.to_udp_bytes()
            }
            Err(_) => {
                // Should not happen (we only cache parseable responses), but
                // fail safe: relay raw bytes with the ID patched.
                let mut bytes = raw.to_vec();
                patch_transaction_id(&mut bytes, request.header.id);
                bytes
            }
        },
    }
}

/// Aligns the response's OPT record with the current client's EDNS(0) negotiation.
///
/// The cached/forwarded response may carry an OPT record advertising a different
/// UDP payload size than this client (the upstream's receive size, or a previous
/// querier's). This replaces, adds, or strips the OPT record so that
/// [`DnsPacket::to_udp_bytes`] truncates at the right boundary for *this* client.
fn align_edns(packet: &mut DnsPacket, request: &DnsPacket) {
    match request.edns_udp_size() {
        Some(client_size) => {
            let negotiated = client_size.clamp(
                DnsPacket::MAX_UDP_SIZE as u16,
                DnsPacket::MAX_EDNS_UDP as u16,
            );
            if let Some(opt) = packet
                .additionals
                .iter_mut()
                .find(|r| matches!(r, DnsRecord::OPT { .. }))
            {
                *opt = DnsRecord::OPT {
                    udp_size: negotiated,
                };
            } else {
                packet.additionals.push(DnsRecord::OPT {
                    udp_size: negotiated,
                });
            }
        }
        None => {
            // Client didn't send EDNS: strip any OPT so the response fits within
            // the classic 512-byte UDP limit.
            packet
                .additionals
                .retain(|r| !matches!(r, DnsRecord::OPT { .. }));
        }
    }
}

/// RAII guard that removes a single-flight entry from the `inflight` map when
/// dropped — even if the leader task is cancelled mid-query — preventing
/// DashMap entries from leaking under task cancellation.
struct InflightGuard<'a> {
    key: (String, u16),
    inflight: &'a DashMap<(String, u16), watch::Receiver<Option<SharedReply>>>,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
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

/// The well-known DNS64 NAT64 prefix (RFC 6052 §2.1).
pub const DNS64_WELL_KNOWN_PREFIX: Ipv6Addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);

/// DNS64 AAAA synthesis (RFC 6147).
///
/// When an AAAA query gets no native AAAA answers, this looks up A records for
/// the same name in the zone. If A records exist, it synthesizes AAAA records
/// by embedding the IPv4 address into the last 32 bits of the NAT64 `prefix`.
/// The synthesized records replace any NODATA response, and the AA bit is set
/// since the server is authoritative for the zone.
fn apply_dns64(response: &mut DnsPacket, zones: &ZoneSet, qname: &str, prefix: &Ipv6Addr) {
    // Only synthesize when there are no native AAAA answers.
    if response
        .answers
        .iter()
        .any(|r| r.record_type() == DnsRecord::TYPE_AAAA)
    {
        return;
    }
    // Find the zone for this name and look up A records.
    let name = qname.to_lowercase();
    let Some(zone) = zones.find(&name) else {
        return;
    };
    let Some(records) = zone.records.get(&name) else {
        return;
    };
    let a_records: Vec<&DnsRecord> = records
        .iter()
        .filter(|r| r.record_type() == DnsRecord::TYPE_A)
        .collect();
    if a_records.is_empty() {
        return;
    }

    // Synthesize AAAA records: embed the IPv4 in the last 32 bits of the prefix.
    // The owner name is the queried name (not the stored A record's owner, which
    // may differ after CNAME chasing).
    let mut synthesized = Vec::with_capacity(a_records.len());
    for r in &a_records {
        if let DnsRecord::A { addr, ttl, .. } = r {
            let aaa = synthesize_aaaa(prefix, *addr, *ttl, &name);
            synthesized.push(aaa);
        }
    }

    // Replace the response: NOERROR with synthesized AAAA answers, AA set.
    response.answers = synthesized;
    response.authorities.clear();
    response.header.flags = (response.header.flags & !0x000F) | 0x0400; // clear rcode, set AA
    response.header.answers = response.answers.len() as u16;
    response.header.authorities = 0;
}

/// Embeds an IPv4 address in the last 32 bits of a NAT64 prefix to produce
/// a synthesized AAAA record with the given owner name.
fn synthesize_aaaa(prefix: &Ipv6Addr, ipv4: Ipv4Addr, ttl: u32, owner: &str) -> DnsRecord {
    let octets = prefix.octets();
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(&octets[..12]);
    let v4 = ipv4.octets();
    bytes[12..16].copy_from_slice(&v4);
    DnsRecord::AAAA {
        domain: owner.to_string(),
        addr: Ipv6Addr::from(bytes),
        ttl,
    }
}

/// Applies DNSSEC signing to a response (RFC 4034/4035).
///
/// - For DNSKEY queries at a zone apex: injects the zone's DNSKEY records.
/// - For any query with answers: signs each distinct RRset (grouped by owner
///   name + type) and appends RRSIG records to the answer section.
///
/// Signing uses the current time as inception and a 30-day expiry. The signer
/// name is the zone apex.
fn apply_dnssec(
    response: &mut DnsPacket,
    zones: &ZoneSet,
    qname: &str,
    qtype: u16,
    keys: &DnssecKeys,
) {
    let name = qname.to_lowercase();

    // If this is a DNSKEY query at a zone apex, inject the DNSKEY records.
    if qtype == DnsRecord::TYPE_DNSKEY
        && let Some(zone) = zones.find(&name)
        && zone.origin == name
    {
        let dnskey_records = keys.dnskey_records(3600);
        if !dnskey_records.is_empty() {
            response.answers = dnskey_records.clone();
            response.header.flags |= 0x0400; // AA
            response.header.flags &= !0x000F; // NOERROR
            response.header.answers = dnskey_records.len() as u16;
            response.authorities.clear();
            response.header.authorities = 0;

            // Sign the DNSKEY RRset and add the RRSIG.
            if let Ok(rrsig) = keys.sign_rrset(
                &dnskey_records,
                &name,
                3600,
                now_as_u32(),
                now_as_u32() + 2_592_000, // 30 days
            ) {
                response.answers.push(rrsig);
                response.header.answers = response.answers.len() as u16;
            }
            return;
        }
    }

    // Sign each answer RRset: group by (owner, type) and sign each group.
    if response.answers.is_empty() {
        return;
    }

    // Group answers by (owner, type) to form RRsets.
    let mut rrsets: std::collections::HashMap<(String, u16), Vec<DnsRecord>> = std::collections::HashMap::new();
    for r in response.answers.clone() {
        let key = (r.domain().to_string(), r.record_type());
        rrsets.entry(key).or_default().push(r);
    }

    // Find the zone apex to use as the signer name.
    let signer_name = zones
        .find(&name)
        .map(|z| z.origin.clone())
        .unwrap_or_default();

    if signer_name.is_empty() {
        return;
    }

    // Sign each RRset and collect RRSIG records.
    let mut rrsigs = Vec::new();
    for ((owner, rtype), records) in &rrsets {
        // Use the minimum TTL of the RRset as the signature's original_ttl.
        let ttl = records.iter().map(|r| r.ttl()).min().unwrap_or(3600);
        if let Ok(rrsig) = keys.sign_rrset(
            records,
            &signer_name,
            ttl,
            now_as_u32(),
            now_as_u32() + 2_592_000, // 30 days
        ) {
            // Fix the RRSIG owner name to match the RRset owner.
            let rrsig = match rrsig {
                DnsRecord::RRSIG { domain: _, .. } => {
                    let mut fixed = rrsig;
                    if let DnsRecord::RRSIG { domain, .. } = &mut fixed {
                        *domain = owner.clone();
                    }
                    fixed
                }
                other => other,
            };
            rrsigs.push(rrsig);
            let _ = rtype; // suppress unused warning
        }
    }

    // Append RRSIG records to the answer section.
    if !rrsigs.is_empty() {
        response.answers.extend(rrsigs);
        response.header.answers = response.answers.len() as u16;
    }
}

/// Returns the current time as a Unix timestamp (seconds since epoch), suitable
/// for RRSIG inception/expiration fields.
fn now_as_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}
