//! Forwards queries to an upstream recursive resolver over UDP.
//!
//! Uses a small pool of long-lived, connected UDP sockets (instead of binding a
//! fresh socket per query) and a semaphore to bound how many upstream queries
//! run concurrently. Responses are matched to their query by transaction ID so
//! a stale datagram on a reused socket is never mistaken for the answer.
//!
//! [`MultiForwarder`] manages one [`Forwarder`] per upstream address so that
//! conditional forwarding rules can target different resolvers.

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Default number of concurrent in-flight upstream queries (and pooled sockets).
const DEFAULT_POOL: usize = 64;
/// How many mismatched/stale datagrams to skip before giving up on a query.
const MAX_STALE: usize = 4;

/// Relays raw DNS query bytes to a configured upstream resolver and returns the
/// raw response bytes. Raw bytes are relayed verbatim so record types this
/// server doesn't model still pass through to the client untouched.
pub struct Forwarder {
    upstream: SocketAddr,
    timeout: Duration,
    permits: Arc<Semaphore>,
    pool: Mutex<Vec<UdpSocket>>,
}

impl Forwarder {
    /// Creates a forwarder targeting `upstream` with the given per-query timeout.
    pub fn new(upstream: SocketAddr, timeout: Duration) -> Self {
        Self::with_concurrency(upstream, timeout, DEFAULT_POOL)
    }

    /// Creates a forwarder bounding concurrent upstream queries to `max_concurrent`.
    pub fn with_concurrency(upstream: SocketAddr, timeout: Duration, max_concurrent: usize) -> Self {
        Forwarder {
            upstream,
            timeout,
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
            pool: Mutex::new(Vec::new()),
        }
    }

    /// The upstream resolver address this forwarder targets.
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Forwards `query` to the upstream resolver and returns the response bytes.
    pub async fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < 2 {
            return Err(anyhow!("query too short to forward"));
        }
        // Bound concurrency; the permit is held for the whole request-response.
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .context("forwarder semaphore closed")?;

        let socket = self.checkout().await?;
        let result = self.query_once(&socket, query).await;
        // Only healthy sockets go back to the pool; a broken one is dropped.
        if result.is_ok() {
            self.pool.lock().unwrap().push(socket);
        }
        result
    }

    /// Takes a connected socket from the pool, creating one if the pool is empty.
    async fn checkout(&self) -> Result<UdpSocket> {
        if let Some(socket) = self.pool.lock().unwrap().pop() {
            return Ok(socket);
        }
        let bind_addr = if self.upstream.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("failed to bind upstream socket")?;
        socket
            .connect(self.upstream)
            .await
            .context("failed to connect upstream socket")?;
        Ok(socket)
    }

    /// Sends one query on a connected socket and reads the matching response.
    /// If the response is truncated (TC bit set), retries over TCP.
    async fn query_once(&self, socket: &UdpSocket, query: &[u8]) -> Result<Vec<u8>> {
        socket
            .send(query)
            .await
            .context("failed to send to upstream")?;
        let want = [query[0], query[1]];

        let mut buf = vec![0u8; 65535];
        for _ in 0..MAX_STALE {
            let len = timeout(self.timeout, socket.recv(&mut buf))
                .await
                .context("upstream query timed out")?
                .context("failed to receive from upstream")?;
            // Match the transaction ID; ignore stale datagrams from a prior query.
            if len >= 2 && buf[0] == want[0] && buf[1] == want[1] {
                buf.truncate(len);
                // Check TC (truncation) bit — if set, retry over TCP.
                if len >= 4 && (buf[2] & 0x02) != 0 {
                    return self.query_tcp(query).await;
                }
                return Ok(buf);
            }
        }
        Err(anyhow!("no matching upstream response (transaction ID mismatch)"))
    }

    /// Sends a query over TCP (2-byte length framing) and returns the response.
    /// Used as a fallback when a UDP response is truncated (TC bit set).
    async fn query_tcp(&self, query: &[u8]) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = timeout(self.timeout, TcpStream::connect(self.upstream))
            .await
            .context("TCP connect to upstream timed out")?
            .context("failed to connect to upstream over TCP")?;

        // Send 2-byte length prefix + query.
        let len = (query.len() as u16).to_be_bytes();
        timeout(self.timeout, stream.write_all(&len))
            .await
            .context("TCP write length timed out")?
            .context("failed to write length to upstream over TCP")?;
        timeout(self.timeout, stream.write_all(query))
            .await
            .context("TCP write query timed out")?
            .context("failed to write query to upstream over TCP")?;

        // Read 2-byte length prefix + response.
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .context("TCP read length timed out")?
            .context("failed to read length from upstream over TCP")?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        timeout(self.timeout, stream.read_exact(&mut resp))
            .await
            .context("TCP read response timed out")?
            .context("failed to read response from upstream over TCP")?;
        Ok(resp)
    }
}

/// Manages a [`Forwarder`] per upstream address, so conditional forwarding
/// rules (each pointing at a different resolver) can share one concurrency
/// budget while keeping per-upstream socket pools isolated.
///
/// A `Forwarder` is created lazily the first time an upstream is queried and
/// reused for subsequent queries to the same upstream.
pub struct MultiForwarder {
    forwarders: DashMap<SocketAddr, Arc<Forwarder>>,
    timeout: Duration,
}

impl MultiForwarder {
    /// Creates a multi-forwarder with the given per-query timeout.
    pub fn new(timeout: Duration) -> Self {
        MultiForwarder {
            forwarders: DashMap::new(),
            timeout,
        }
    }

    /// Returns the [`Forwarder`] for `upstream`, creating one on first use.
    fn get_or_create(&self, upstream: SocketAddr) -> Arc<Forwarder> {
        self.forwarders
            .entry(upstream)
            .or_insert_with(|| Arc::new(Forwarder::new(upstream, self.timeout)))
            .clone()
    }

    /// Forwards `query` to `upstream` and returns the response bytes.
    pub async fn forward(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let forwarder = self.get_or_create(upstream);
        forwarder.forward(query).await
    }

    /// The upstream resolvers currently active (for logging/diagnostics).
    pub fn active_upstreams(&self) -> Vec<SocketAddr> {
        self.forwarders.iter().map(|e| *e.key()).collect()
    }
}
