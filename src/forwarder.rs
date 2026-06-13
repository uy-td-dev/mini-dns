//! Forwards queries to an upstream recursive resolver over UDP.
//!
//! Uses a small pool of long-lived, connected UDP sockets (instead of binding a
//! fresh socket per query) and a semaphore to bound how many upstream queries
//! run concurrently. Responses are matched to their query by transaction ID so
//! a stale datagram on a reused socket is never mistaken for the answer.

use anyhow::{anyhow, Context, Result};
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
    async fn query_once(&self, socket: &UdpSocket, query: &[u8]) -> Result<Vec<u8>> {
        socket
            .send(query)
            .await
            .context("failed to send to upstream")?;
        let want = [query[0], query[1]];

        let mut buf = vec![0u8; 4096];
        for _ in 0..MAX_STALE {
            let len = timeout(self.timeout, socket.recv(&mut buf))
                .await
                .context("upstream query timed out")?
                .context("failed to receive from upstream")?;
            // Match the transaction ID; ignore stale datagrams from a prior query.
            if len >= 2 && buf[0] == want[0] && buf[1] == want[1] {
                buf.truncate(len);
                return Ok(buf);
            }
        }
        Err(anyhow!("no matching upstream response (transaction ID mismatch)"))
    }
}
