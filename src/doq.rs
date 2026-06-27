//! DNS-over-QUIC (DoQ) support, per RFC 9250.
//!
//! Each DNS query is sent over its own QUIC stream (client-initiated,
//! bidirectional). The server reads the 2-byte length prefix + DNS message,
//! resolves it, and writes the response back on the same stream with the same
//! 2-byte length framing. The ALPN identifier is `doq`.
//!
//! Unlike DoT, QUIC streams are independent so a single QUIC connection can
//! carry many concurrent queries without head-of-line blocking.

use crate::state::{ServerState, Transport};
use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

/// The ALPN protocol identifier for DNS-over-QUIC (RFC 9250 §8.1).
pub const DOQ_ALPN: &[u8] = b"doq";

/// Ensures the rustls config advertises the `doq` ALPN. Returns a cloned config
/// with the ALPN set (does not mutate the input).
pub fn with_doq_alpn(mut config: rustls::ServerConfig) -> rustls::ServerConfig {
    config.alpn_protocols = vec![DOQ_ALPN.to_vec()];
    config
}

/// Builds a QUIC `Endpoint` bound to `addr` with the given rustls config.
pub fn build_endpoint(
    rustls_config: Arc<rustls::ServerConfig>,
    addr: &str,
) -> Result<Endpoint> {
    let quic_config = QuicServerConfig::try_from(rustls_config)
        .context("building QUIC server config")?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_config));
    let parsed: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid DoQ address `{addr}`"))?;
    Endpoint::server(server_config, parsed).context("binding QUIC endpoint")
}

/// Accepts QUIC connections and serves DNS queries on each stream. Stops
/// accepting new connections when `shutdown` fires.
pub async fn serve(
    state: Arc<ServerState>,
    endpoint: Endpoint,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    info!(addr = %endpoint.local_addr()?, "DNS-over-QUIC listening");
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = handle_connection(&state, conn).await {
                                warn!(error = %e, "DoQ connection error");
                            }
                        }
                        Err(e) => warn!(error = %e, "DoQ connection handshake failed"),
                    }
                });
            }
            _ = shutdown.changed() => {
                info!("DoQ listener shutting down");
                endpoint.close(0u32.into(), b"shutdown");
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Handles one QUIC connection: accepts streams and serves a DNS query on each.
async fn handle_connection(state: &ServerState, conn: quinn::Connection) -> Result<()> {
    let client: IpAddr = conn.remote_address().ip();
    loop {
        // Each query arrives on its own bidirectional stream (RFC 9250 §4.1).
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // Read the 2-byte length prefix, then the DNS message (RFC 9250 §4.2).
        let mut len_buf = [0u8; 2];
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            match e {
                quinn::ReadExactError::FinishedEarly(_) => return Ok(()), // clean close
                quinn::ReadExactError::ReadError(e) => return Err(e.into()),
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        recv.read_exact(&mut msg).await?;

        // Resolve and write the response on the same stream.
        if let Some(resp) = state.resolve(&msg, client, Transport::Tcp).await {
            send.write_all(&(resp.len() as u16).to_be_bytes()).await?;
            send.write_all(&resp).await?;
        }
        // Signal end-of-stream; the client may open another on the same conn.
        let _ = send.finish();
    }
}
