//! Full iterative recursive resolver (RFC 1034 §5.3.3).
//!
//! Instead of forwarding to an upstream recursive resolver (8.8.8.8 etc.),
//! this module resolves queries by walking the DNS delegation chain from the
//! root servers down:
//!
//! 1. Start with root hints (the 13 root name servers).
//! 2. Send the query to a root server; it returns either an answer or a
//!    delegation (NS records + glue A/AAAA).
//! 3. Follow the delegation to the next authoritative server.
//! 4. Repeat until an answer is received or NXDOMAIN.
//!
//! Delegations are cached with their TTL to avoid re-querying the root on every
//! request. A separate response cache (the existing `Cache`) is used by the
//! caller to cache final answers.
//!
//! QNAME minimization (RFC 9156) is applied: at each delegation step, only the
//! minimal suffix needed for the next delegation is queried, improving privacy.

use crate::dns::header::DnsHeader;
use crate::dns::packet::DnsPacket;
use crate::dns::question::DnsQuestion;
use crate::dns::record::DnsRecord;
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Per-query timeout when querying an authoritative server.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum delegation depth (root → TLD → ... → authoritative). RFC 1034
/// suggests 20 as a safe upper bound.
const MAX_DELEGATION_DEPTH: usize = 20;
/// Maximum UDP payload size we advertise via EDNS(0) when querying auth servers.
const EDNS_UDP_SIZE: u16 = 1232;
/// How many concurrent recursive resolutions run at once.
const MAX_CONCURRENT: usize = 128;

/// Root hint records (RFC 1035 §13.1). These are the 13 root name servers'
/// A records, used to bootstrap the delegation chain. They rarely change;
/// the latest list is at <https://www.iana.org/domains/root/servers>.
const ROOT_HINTS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

/// A cached delegation: NS names for a zone + their resolved addresses (glue).
#[derive(Clone, Debug)]
struct Delegation {
    /// NS hostnames authoritative for this zone suffix.
    ns_names: Vec<String>,
    /// Resolved A/AAAA addresses for those NS names (glue or separately resolved).
    ns_addrs: Vec<SocketAddr>,
    /// When this delegation entry expires.
    expires_at: std::time::Instant,
}

impl Delegation {
    /// Whether this delegation entry has expired.
    fn is_expired(&self) -> bool {
        std::time::Instant::now() >= self.expires_at
    }
}

/// An iterative recursive resolver that walks the DNS delegation chain.
///
/// Uses a `DashMap` to cache delegations (NS records) keyed by zone suffix,
/// so repeated queries for names under the same TLD don't re-hit the root.
pub struct RecursiveResolver {
    /// Cached delegations keyed by zone suffix (e.g. "com.", "example.com.").
    delegations: DashMap<String, Delegation>,
    /// Bounds concurrent resolutions to avoid flooding authoritative servers.
    permits: Arc<Semaphore>,
    /// Transaction ID counter for outgoing queries.
    next_id: std::sync::atomic::AtomicU16,
}

impl Default for RecursiveResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl RecursiveResolver {
    /// Creates a new recursive resolver with empty delegation cache.
    pub fn new() -> Self {
        RecursiveResolver {
            delegations: DashMap::new(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            next_id: std::sync::atomic::AtomicU16::new(1),
        }
    }

    /// Resolves `name` / `qtype` iteratively, returning the final response
    /// bytes (a complete DNS response message ready to relay to the client).
    ///
    /// The response's transaction ID is set to `client_id` so the client
    /// accepts it.
    pub async fn resolve(
        &self,
        name: &str,
        qtype: u16,
        client_id: u16,
    ) -> Result<Vec<u8>> {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .context("recursive resolver semaphore closed")?;

        let name = name.to_lowercase();
        let name = name.trim_end_matches('.');

        debug!(name = %name, qtype, "recursive resolution starting");

        // Check for a cached delegation for this name's parent zone. If found
        // and not expired, start from those servers instead of root.
        let parent = name.split_once('.').map(|(_, parent)| parent).unwrap_or("");
        let mut servers = if let Some(entry) = self.delegations.get(parent) {
            if entry.is_expired() {
                debug!(zone = %parent, "delegation cache entry expired, starting from root");
                drop(entry);
                self.delegations.remove(parent);
                self.root_servers()
            } else {
                debug!(zone = %parent, "delegation cache hit");
                entry.ns_addrs.clone()
            }
        } else {
            self.root_servers()
        };
        let mut depth = 0;
        // Track the current zone we're querying (starts empty = root).
        let mut current_zone: String = String::new();

        loop {
            depth += 1;
            if depth > MAX_DELEGATION_DEPTH {
                warn!(name = %name, "recursive resolution exceeded max depth");
                return Ok(self.synth_servfail(name, qtype, client_id));
            }

            // QNAME minimization (RFC 9156): instead of querying the full name
            // at every delegation level, query only the minimal suffix needed
            // to get the next delegation. At root we query the TLD; at the TLD
            // we query the TLD + one label; and so on. Once the current servers
            // are authoritative for the full name's zone, query the full name.
            let query_name = minimized_qname(name, &current_zone);

            // Query the current set of authoritative servers.
            let response = match self.query_servers(&query_name, qtype, &servers).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(name = %name, query = %query_name, error = %e, "recursive query failed at depth {depth}");
                    return Ok(self.synth_servfail(name, qtype, client_id));
                }
            };

            let rcode = response.header.flags & 0x000F;

            // If we got a definitive answer (NOERROR with answers, or NXDOMAIN),
            // return it to the caller. But only if we were querying the full
            // name — a minimized query that returns answers means the server is
            // authoritative for a shorter name, which is unexpected; treat it
            // as an answer anyway since it's still valid.
            if !response.answers.is_empty() || rcode == 3 {
                let mut resp = response;
                resp.header.id = client_id;
                // Clear AA bit — we're a recursive resolver, not authoritative.
                resp.header.flags &= !0x0400;
                // Set RA bit — recursion was available (and performed).
                resp.header.flags |= 0x0080;
                // If we got an answer for a minimized query (not the full name),
                // re-query with the full name to get the actual answer.
                if query_name != name {
                    debug!(name = %name, query = %query_name, "got answer for minimized query, re-querying full name");
                    servers = self.root_servers();
                    current_zone = String::new();
                    continue;
                }
                return Ok(resp.to_bytes());
            }

            // No answers but NOERROR: check for a delegation in the authority section.
            if rcode == 0 {
                if let Some(delegation) = self.extract_delegation(&response) {
                    // Cache the delegation for future queries under this zone.
                    let zone = delegation_zone(&query_name, &delegation.ns_names);
                    debug!(name = %name, query = %query_name, zone = %zone, ns = ?delegation.ns_names, "following delegation");
                    self.delegations.insert(zone.clone(), delegation.clone());
                    servers = delegation.ns_addrs;
                    current_zone = zone;
                    continue;
                }

                // NOERROR with no answers and no delegation = NODATA.
                // Only return NODATA if we were querying the full name.
                if query_name == name {
                    let mut resp = response;
                    resp.header.id = client_id;
                    resp.header.flags &= !0x0400;
                    resp.header.flags |= 0x0080;
                    return Ok(resp.to_bytes());
                }

                // We were querying a minimized name and got NODATA with no
                // delegation. This shouldn't happen at a non-authoritative
                // level — treat it as an error and fall through to the full
                // name query by resetting to root.
                debug!(name = %name, query = %query_name, "unexpected NODATA for minimized query, resetting to root");
                servers = self.root_servers();
                current_zone = String::new();
                continue;
            }

            // Any other rcode: return as-is.
            let mut resp = response;
            resp.header.id = client_id;
            resp.header.flags &= !0x0400;
            resp.header.flags |= 0x0080;
            return Ok(resp.to_bytes());
        }
    }

    /// Returns the root server addresses from the built-in hints.
    fn root_servers(&self) -> Vec<SocketAddr> {
        ROOT_HINTS
            .iter()
            .filter_map(|(_, ip)| {
                let ip: std::net::IpAddr = ip.parse().ok()?;
                Some(SocketAddr::new(ip, 53))
            })
            .collect()
    }

    /// Queries a list of authoritative servers in order, returning the first
    /// successful response.
    async fn query_servers(
        &self,
        name: &str,
        qtype: u16,
        servers: &[SocketAddr],
    ) -> Result<DnsPacket> {
        let mut last_err = anyhow!("no servers available");
        for server in servers {
            match self.query_one(name, qtype, *server).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    debug!(server = %server, error = %e, "query failed, trying next");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    /// Sends a single DNS query to `server` over UDP and returns the parsed response.
    ///
    /// QNAME minimization (RFC 9156): when following a delegation, we query for
    /// the full name but with RD=0 (no recursion desired — we're asking the
    /// authoritative server directly).
    async fn query_one(
        &self,
        name: &str,
        qtype: u16,
        server: SocketAddr,
    ) -> Result<DnsPacket> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Build the query with EDNS(0) OPT record for larger UDP responses.
        let query = DnsPacket {
            header: DnsHeader {
                id,
                flags: 0x0010, // RD=0 (we're querying authoritatively), AD=1
                questions: 1,
                answers: 0,
                authorities: 0,
                additionals: 1,
            },
            questions: vec![DnsQuestion {
                qname: name.to_string(),
                qtype,
                qclass: 1, // IN
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![DnsRecord::OPT {
                udp_size: EDNS_UDP_SIZE,
            }],
        };

        let query_bytes = query.to_bytes();

        // Use a fresh UDP socket per query (connected to the server).
        let bind_addr = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("failed to bind resolver socket")?;
        socket
            .connect(server)
            .await
            .with_context(|| format!("failed to connect to {server}"))?;

        socket
            .send(&query_bytes)
            .await
            .with_context(|| format!("failed to send query to {server}"))?;

        let mut buf = vec![0u8; 65535];
        let len = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .context("recursive query timed out")?
            .context("failed to receive from server")?;

        buf.truncate(len);

        // Check TC (truncation) bit — if set, retry over TCP to get the full response.
        if buf.len() >= 4 && (buf[2] & 0x02) != 0 {
            debug!(server = %server, "UDP response truncated, retrying over TCP");
            return self.query_one_tcp(&query_bytes, server, id).await;
        }

        let response = DnsPacket::from_bytes(&buf).context("failed to parse response")?;

        // Verify the transaction ID matches.
        if response.header.id != id {
            return Err(anyhow!("transaction ID mismatch"));
        }

        Ok(response)
    }

    /// Sends a query over TCP (2-byte length framing) as a fallback for
    /// truncated UDP responses.
    async fn query_one_tcp(
        &self,
        query_bytes: &[u8],
        server: SocketAddr,
        expected_id: u16,
    ) -> Result<DnsPacket> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = timeout(QUERY_TIMEOUT, TcpStream::connect(server))
            .await
            .context("TCP connect timed out")?
            .context("failed to connect over TCP")?;

        let len = (query_bytes.len() as u16).to_be_bytes();
        timeout(QUERY_TIMEOUT, stream.write_all(&len))
            .await
            .context("TCP write length timed out")?
            .context("failed to write length over TCP")?;
        timeout(QUERY_TIMEOUT, stream.write_all(query_bytes))
            .await
            .context("TCP write query timed out")?
            .context("failed to write query over TCP")?;

        let mut len_buf = [0u8; 2];
        timeout(QUERY_TIMEOUT, stream.read_exact(&mut len_buf))
            .await
            .context("TCP read length timed out")?
            .context("failed to read length over TCP")?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        timeout(QUERY_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .context("TCP read response timed out")?
            .context("failed to read response over TCP")?;

        let response = DnsPacket::from_bytes(&resp).context("failed to parse TCP response")?;
        if response.header.id != expected_id {
            return Err(anyhow!("transaction ID mismatch (TCP)"));
        }
        Ok(response)
    }

    /// Extracts a delegation (NS records + glue) from a response's authority
    /// and additional sections.
    fn extract_delegation(&self, response: &DnsPacket) -> Option<Delegation> {
        // Collect NS names from the authority section.
        // Collect NS names and their TTL from the authority section.
        let mut ns_ttl: u32 = 3600; // default if no TTL found
        let ns_names: Vec<String> = response
            .authorities
            .iter()
            .filter_map(|r| match r {
                DnsRecord::NS { nameserver, ttl, .. } => {
                    ns_ttl = ns_ttl.min(*ttl);
                    Some(nameserver.clone())
                }
                _ => None,
            })
            .collect();

        if ns_names.is_empty() {
            return None;
        }

        // Collect glue addresses from the additional section.
        let mut ns_addrs: Vec<SocketAddr> = Vec::new();
        for r in &response.additionals {
            match r {
                DnsRecord::A { domain, addr, .. } => {
                    if ns_names.iter().any(|ns| ns.eq_ignore_ascii_case(domain)) {
                        ns_addrs.push(SocketAddr::new((*addr).into(), 53));
                    }
                }
                DnsRecord::AAAA { domain, addr, .. }
                    if ns_names.iter().any(|ns| ns.eq_ignore_ascii_case(domain)) => {
                        ns_addrs.push(SocketAddr::new((*addr).into(), 53));
                    }
                _ => {}
            }
        }

        // If no glue, try to resolve NS addresses from our delegation cache.
        if ns_addrs.is_empty() {
            for ns in &ns_names {
                if let Some(entry) = self.delegations.get(ns)
                    && !entry.is_expired()
                {
                    ns_addrs.extend(entry.ns_addrs.iter().copied());
                }
            }
        }

        if ns_addrs.is_empty() {
            // Can't follow a delegation without addresses.
            return None;
        }

        Some(Delegation {
            ns_names,
            ns_addrs,
            expires_at: std::time::Instant::now() + Duration::from_secs(ns_ttl as u64),
        })
    }

    /// Synthesizes a SERVFAIL response for the given query.
    fn synth_servfail(&self, name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let packet = DnsPacket {
            header: DnsHeader {
                id,
                flags: 0x8182, // QR=1, RA=1, SERVFAIL
                questions: 1,
                answers: 0,
                authorities: 0,
                additionals: 0,
            },
            questions: vec![DnsQuestion {
                qname: name.to_string(),
                qtype,
                qclass: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        packet.to_bytes()
    }

    /// Whether the resolver has a cached delegation for `zone`.
    #[cfg(test)]
    fn has_delegation(&self, zone: &str) -> bool {
        self.delegations.contains_key(zone)
    }
}

/// Determines the zone suffix from the queried name and the NS names.
/// Returns the parent domain of the queried name (the zone that delegated).
fn delegation_zone(name: &str, _ns_names: &[String]) -> String {
    // Use the parent domain of the queried name.
    // E.g. querying "www.example.com" -> delegation zone is "example.com".
    if let Some(pos) = name.find('.') {
        return name[pos + 1..].to_string();
    }
    name.to_string()
}

/// Computes the minimized query name for QNAME minimization (RFC 9156).
///
/// Given the full `name` and the `current_zone` we're querying from, returns
/// the name with one more label than the current zone. For example:
/// - current_zone = "" (root), name = "www.example.com" → "com"
/// - current_zone = "com", name = "www.example.com" → "example.com"
/// - current_zone = "example.com", name = "www.example.com" → "www.example.com" (full)
///
/// If the current zone already encompasses the full name, the full name is
/// returned (no further minimization possible).
fn minimized_qname(name: &str, current_zone: &str) -> String {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return name.to_string();
    }
    if current_zone.is_empty() {
        // At root: query the TLD (last label).
        return labels[labels.len() - 1].to_string();
    }
    // Count labels in the current zone.
    let zone_labels = current_zone.split('.').filter(|l| !l.is_empty()).count();
    // Query with zone_labels + 1 labels (from the right).
    let query_labels = zone_labels + 1;
    if query_labels >= labels.len() {
        return name.to_string();
    }
    // Take the last `query_labels` labels and join them.
    let start = labels.len() - query_labels;
    labels[start..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_hints_are_valid_addresses() {
        assert_eq!(ROOT_HINTS.len(), 13);
        for (name, ip) in ROOT_HINTS {
            assert!(ip.parse::<std::net::Ipv4Addr>().is_ok(), "invalid IP for {name}: {ip}");
        }
    }

    #[test]
    fn resolver_starts_empty() {
        let r = RecursiveResolver::new();
        assert!(!r.has_delegation("com"));
    }

    #[test]
    fn delegation_zone_strips_first_label() {
        assert_eq!(
            delegation_zone("www.example.com", &["ns1.example.com".to_string()]),
            "example.com"
        );
        assert_eq!(
            delegation_zone("example.com", &["a.gtld-servers.net".to_string()]),
            "com"
        );
    }

    #[test]
    fn minimized_qname_at_root_queries_tld() {
        // At root (empty current_zone), query the TLD only.
        assert_eq!(minimized_qname("www.example.com", ""), "com");
        assert_eq!(minimized_qname("example.com", ""), "com");
        assert_eq!(minimized_qname("com", ""), "com");
    }

    #[test]
    fn minimized_qname_at_tld_queries_next_label() {
        // At .com zone, query example.com (2 labels).
        assert_eq!(minimized_qname("www.example.com", "com"), "example.com");
        assert_eq!(minimized_qname("a.b.example.com", "com"), "example.com");
    }

    #[test]
    fn minimized_qname_at_authoritative_queries_full_name() {
        // At example.com zone, query the full name.
        assert_eq!(minimized_qname("www.example.com", "example.com"), "www.example.com");
        assert_eq!(minimized_qname("example.com", "example.com"), "example.com");
    }

    #[test]
    fn minimized_qname_deep_subdomain() {
        // a.b.c.example.com at root → "com"
        assert_eq!(minimized_qname("a.b.c.example.com", ""), "com");
        // at "com" → "example.com"
        assert_eq!(minimized_qname("a.b.c.example.com", "com"), "example.com");
        // at "example.com" → "c.example.com" (one more label)
        assert_eq!(minimized_qname("a.b.c.example.com", "example.com"), "c.example.com");
        // at "c.example.com" → "b.c.example.com"
        assert_eq!(minimized_qname("a.b.c.example.com", "c.example.com"), "b.c.example.com");
        // at "b.c.example.com" → full name
        assert_eq!(minimized_qname("a.b.c.example.com", "b.c.example.com"), "a.b.c.example.com");
    }
}
