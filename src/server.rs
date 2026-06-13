use crate::doh;
use crate::state::{ServerState, Transport};
use anyhow::{Context, Result};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// The address the server binds to when none is provided.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8888";

/// How often the server logs a metrics summary.
const METRICS_INTERVAL: Duration = Duration::from_secs(60);

/// Optional encrypted-transport listeners (DoT / DoH), sharing one TLS config.
pub struct TlsOptions {
    pub acceptor: TlsAcceptor,
    pub dot_addr: Option<String>,
    pub doh_addr: Option<String>,
}

/// Binds a UDP socket to `addr` and returns it.
///
/// Pass a port of `0` (e.g. `"127.0.0.1:0"`) to let the OS choose a free port;
/// the chosen address can then be read via [`UdpSocket::local_addr`].
pub async fn bind(addr: &str) -> Result<Arc<UdpSocket>> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("Failed to bind UDP socket to {addr}"))?;
    Ok(Arc::new(socket))
}

/// Binds a TCP listener to `addr` (used for DNS-over-TCP, DoT and DoH).
pub async fn bind_tcp(addr: &str) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener to {addr}"))
}

/// `run` binds UDP and TCP on `addr` (and optionally DoT/DoH), serving DNS
/// queries on all transports, plus a metrics reporter and SIGHUP reload handler.
pub async fn run(state: Arc<ServerState>, addr: &str, tls: Option<TlsOptions>) -> Result<()> {
    let udp = bind(addr).await?;
    let local = udp.local_addr()?;
    let tcp = bind_tcp(addr).await?;
    info!(%local, "DNS server listening (UDP + TCP)");

    if let Some(tls) = tls {
        if let Some(dot_addr) = &tls.dot_addr {
            let listener = bind_tcp(dot_addr).await?;
            info!(addr = %dot_addr, "DNS-over-TLS listening");
            tokio::spawn(serve_dot(
                Arc::clone(&state),
                listener,
                tls.acceptor.clone(),
            ));
        }
        if let Some(doh_addr) = &tls.doh_addr {
            let listener = bind_tcp(doh_addr).await?;
            info!(addr = %doh_addr, "DNS-over-HTTPS listening");
            tokio::spawn(serve_doh(
                Arc::clone(&state),
                listener,
                tls.acceptor.clone(),
            ));
        }
    }

    spawn_metrics_reporter(Arc::clone(&state));
    spawn_reload_handler(Arc::clone(&state));

    tokio::try_join!(
        serve(Arc::clone(&state), udp),
        serve_tcp(Arc::clone(&state), tcp),
    )?;
    Ok(())
}

/// `serve` listens on an already-bound UDP socket and handles DNS requests.
///
/// Each request is processed in its own Tokio task to keep the server
/// responsive. Splitting this out from [`run`] lets callers (such as tests)
/// bind first, learn the chosen address, and then start serving.
pub async fn serve(state: Arc<ServerState>, socket: Arc<UdpSocket>) -> Result<()> {
    let mut buf = [0u8; 512];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req_buf = buf[..len].to_vec();
        let state = Arc::clone(&state);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            if let Some(resp) = state.resolve(&req_buf, addr.ip(), Transport::Udp).await {
                if let Err(e) = socket.send_to(&resp, addr).await {
                    warn!(%addr, error = %e, "failed to send UDP response");
                }
            }
        });
    }
}

/// `serve_tcp` accepts plaintext DNS-over-TCP connections.
pub async fn serve_tcp(state: Arc<ServerState>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_dns_stream(&state, stream, peer.ip()).await {
                warn!(%peer, error = %e, "TCP connection error");
            }
        });
    }
}

/// `serve_dot` accepts DNS-over-TLS connections, performing the TLS handshake
/// before handing the (length-framed) stream to the shared DNS handler.
pub async fn serve_dot(
    state: Arc<ServerState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    if let Err(e) = handle_dns_stream(&state, tls, peer.ip()).await {
                        warn!(%peer, error = %e, "DoT connection error");
                    }
                }
                Err(e) => warn!(%peer, error = %e, "DoT TLS handshake failed"),
            }
        });
    }
}

/// `serve_doh` accepts DNS-over-HTTPS connections (HTTP/1.1 over TLS).
pub async fn serve_doh(
    state: Arc<ServerState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    if let Err(e) = doh::handle_connection(&state, tls, peer.ip()).await {
                        warn!(%peer, error = %e, "DoH connection error");
                    }
                }
                Err(e) => warn!(%peer, error = %e, "DoH TLS handshake failed"),
            }
        });
    }
}

/// Handles length-framed DNS messages on a stream (TCP or TLS).
///
/// A connection may carry multiple queries; each is framed by a 2-byte
/// big-endian length prefix (RFC 1035 §4.2.2).
pub async fn handle_dns_stream<S>(state: &ServerState, mut stream: S, client: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            // A clean EOF between messages just means the client is done.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;

        if let Some(resp) = state.resolve(&msg, client, Transport::Tcp).await {
            stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
            stream.write_all(&resp).await?;
        }
    }
}

/// Periodically logs a metrics summary.
fn spawn_metrics_reporter(state: Arc<ServerState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(METRICS_INTERVAL);
        ticker.tick().await; // first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            info!(metrics = %state.metrics.summary(), "metrics");
        }
    });
}

/// On Unix, reloads the zone file when SIGHUP is received.
#[cfg(unix)]
fn spawn_reload_handler(state: Arc<ServerState>) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            info!("SIGHUP received, reloading zone");
            if let Err(e) = state.reload() {
                warn!(error = %e, "zone reload failed");
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_reload_handler(_state: Arc<ServerState>) {
    // SIGHUP-based reload is only available on Unix platforms.
}
