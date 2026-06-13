//! Forwards queries to an upstream recursive resolver over UDP.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Relays raw DNS query bytes to a configured upstream resolver and returns the
/// raw response bytes.
///
/// Raw bytes are relayed verbatim (rather than re-encoded) so that record types
/// this server doesn't model are still passed through to the client untouched.
#[derive(Debug, Clone)]
pub struct Forwarder {
    upstream: SocketAddr,
    timeout: Duration,
}

impl Forwarder {
    /// Creates a forwarder targeting `upstream` with the given query timeout.
    pub fn new(upstream: SocketAddr, timeout: Duration) -> Self {
        Forwarder { upstream, timeout }
    }

    /// The upstream resolver address this forwarder targets.
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Forwards `query` to the upstream resolver and returns the response bytes.
    pub async fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        // An ephemeral local socket per query keeps response correlation simple.
        let bind_addr = if self.upstream.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("failed to bind upstream socket")?;
        socket
            .send_to(query, self.upstream)
            .await
            .context("failed to send to upstream")?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(self.timeout, socket.recv(&mut buf))
            .await
            .context("upstream query timed out")?
            .context("failed to receive from upstream")?;
        buf.truncate(len);
        Ok(buf)
    }
}
