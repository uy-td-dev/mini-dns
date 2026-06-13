//! Shared server state and the top-level query resolution logic.

use crate::cache::Cache;
use crate::config::{load_zone_file, Zone};
use crate::dns::header::DnsHeader;
use crate::dns::packet::DnsPacket;
use crate::forwarder::Forwarder;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

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

/// All shared state needed to answer queries: the zone (hot-swappable), an
/// optional upstream forwarder, a cache, a rate limiter, and metrics.
pub struct ServerState {
    zone: RwLock<Arc<Zone>>,
    zone_path: Option<String>,
    forwarder: Option<Forwarder>,
    cache: Cache,
    limiter: RateLimiter,
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
            zone: RwLock::new(Arc::new(zone)),
            zone_path,
            forwarder,
            cache,
            limiter,
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

    /// Returns a cheap snapshot handle to the current zone.
    fn zone(&self) -> Arc<Zone> {
        self.zone.read().unwrap().clone()
    }

    /// Reloads the zone from disk (if a path was configured) and swaps it in
    /// atomically. In-flight requests keep using the previous snapshot.
    pub fn reload(&self) -> Result<()> {
        if let Some(path) = &self.zone_path {
            let zone = load_zone_file(path)?;
            let count: usize = zone.values().map(Vec::len).sum();
            *self.zone.write().unwrap() = Arc::new(zone);
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

    /// Resolves a raw request and returns the response bytes ready to send, or
    /// `None` if the request was dropped (rate-limited or unparseable).
    pub async fn resolve(&self, req: &[u8], client: IpAddr, transport: Transport) -> Option<Vec<u8>> {
        self.metrics.inc_total();

        if !self.limiter.allow(client) {
            self.metrics.inc_rate_limited();
            debug!(%client, "query dropped by rate limiter");
            return None;
        }

        let request = match DnsPacket::from_bytes(req) {
            Ok(packet) => packet,
            Err(e) => {
                self.metrics.inc_error();
                warn!(%client, error = %e, "failed to parse DNS packet");
                return None;
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

                if let Some(records) = self.cache.get(&name, qtype) {
                    self.metrics.inc_cache_hit();
                    debug!(%name, qtype, "cache hit");
                    let synth = self.synth_response(&request, records, 0);
                    return Some(encode(&synth, transport));
                }

                return Some(self.forward(&request, req, &name, qtype, transport).await);
            }
        }

        // Local (authoritative) answer.
        self.metrics.inc_authoritative();
        if self.recursion_available() {
            response.header.flags |= FLAG_RA;
        }
        Some(encode(&response, transport))
    }

    /// Forwards `raw` upstream, caches any parseable answers, and returns the
    /// bytes to relay to the client (SERVFAIL on failure).
    async fn forward(
        &self,
        request: &DnsPacket,
        raw: &[u8],
        name: &str,
        qtype: u16,
        transport: Transport,
    ) -> Vec<u8> {
        let forwarder = self.forwarder.as_ref().expect("forwarder present");
        match forwarder.forward(raw).await {
            Ok(response_bytes) => {
                self.metrics.inc_forwarded();
                debug!(%name, qtype, upstream = %forwarder.upstream(), "forwarded query");

                // Best-effort caching: only records we can model are cached. The
                // raw bytes are relayed regardless so unknown types pass through.
                if let Ok(parsed) = DnsPacket::from_bytes(&response_bytes) {
                    let min_ttl = parsed.answers.iter().map(|r| r.ttl()).min().unwrap_or(0);
                    self.cache.insert(name, qtype, parsed.answers, min_ttl);
                }
                response_bytes
            }
            Err(e) => {
                self.metrics.inc_error();
                warn!(%name, error = %e, "upstream forwarding failed");
                let servfail = self.synth_response(request, Vec::new(), RCODE_SERVFAIL);
                encode(&servfail, transport)
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
