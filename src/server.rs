use crate::doh;
use crate::state::{Resolution, ServerState, Transport};
use anyhow::{anyhow, Context, Result};
use std::io::ErrorKind;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{header, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
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

/// Binds a UDP socket with `SO_REUSEPORT` so multiple sockets can share `addr`.
///
/// Binding one such socket per worker lets the kernel load-balance incoming
/// datagrams across cores, instead of funnelling all ingress through a single
/// `recv` loop. Requires a concrete address (not port 0).
pub fn bind_reuseport(addr: &str) -> Result<Arc<UdpSocket>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sa = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .next()
        .ok_or_else(|| anyhow!("no socket address for {addr}"))?;
    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket
        .bind(&sa.into())
        .with_context(|| format!("Failed to bind UDP socket to {addr}"))?;

    let std_sock: std::net::UdpSocket = socket.into();
    Ok(Arc::new(UdpSocket::from_std(std_sock)?))
}

/// `run` binds UDP and TCP on `addr` (and optionally DoT/DoH), serving DNS
/// queries on all transports, plus a metrics reporter and SIGHUP reload handler.
pub async fn run(
    state: Arc<ServerState>,
    addr: &str,
    tls: Option<TlsOptions>,
    metrics_addr: Option<&str>,
) -> Result<()> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // One SO_REUSEPORT UDP socket per worker; the kernel spreads ingress across
    // cores rather than serialising it through a single recv loop.
    let mut udp_sockets = Vec::with_capacity(workers);
    for _ in 0..workers {
        udp_sockets.push(bind_reuseport(addr)?);
    }
    let local = udp_sockets[0].local_addr()?;
    let tcp = bind_tcp(addr).await?;
    info!(%local, workers, "DNS server listening (UDP + TCP)");

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

    if let Some(metrics_addr) = metrics_addr {
        let listener = bind_tcp(metrics_addr).await?;
        info!(addr = %metrics_addr, "Prometheus metrics listening at /metrics");
        tokio::spawn(serve_metrics(Arc::clone(&state), listener));
    }

    spawn_metrics_reporter(Arc::clone(&state));
    spawn_reload_handler(Arc::clone(&state));

    // One recv loop per UDP socket; the TCP acceptor runs in the foreground.
    for socket in udp_sockets {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = serve(state, socket).await {
                warn!(error = %e, "UDP worker stopped");
            }
        });
    }
    serve_tcp(Arc::clone(&state), tcp).await
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

        // Fast path: local/cached answers are resolved synchronously and sent
        // inline — no task spawn, no per-packet allocation. Only queries that
        // must be forwarded upstream (which awaits) are handed to a task.
        match state.resolve_local(&buf[..len], addr.ip(), Transport::Udp) {
            Resolution::Ready(resp) => {
                if let Err(e) = socket.send_to(&resp, addr).await {
                    warn!(%addr, error = %e, "failed to send UDP response");
                }
            }
            Resolution::Drop => {}
            Resolution::Forward(ctx) => {
                let state = Arc::clone(&state);
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    let resp = state.forward_ctx(ctx).await;
                    if let Err(e) = socket.send_to(&resp, addr).await {
                        warn!(%addr, error = %e, "failed to send UDP response");
                    }
                });
            }
        }
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

/// `serve_doh` accepts DNS-over-HTTPS connections (HTTP/1.1 and HTTP/2 over TLS).
///
/// `hyper`'s auto builder negotiates the HTTP version and keeps the connection
/// alive, so a client can multiplex many queries over one HTTP/2 connection.
pub async fn serve_doh(
    state: Arc<ServerState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let acceptor = acceptor.clone();
        let client = peer.ip();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    warn!(%peer, error = %e, "DoH TLS handshake failed");
                    return;
                }
            };
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { doh::handle_http(&state, req, client).await }
            });
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                warn!(%peer, error = %e, "DoH connection error");
            }
        });
    }
}

/// `serve_metrics` serves Prometheus metrics over plain HTTP at `/metrics`.
pub async fn serve_metrics(state: Arc<ServerState>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move {
                    let (status, body) = if req.uri().path() == "/metrics" {
                        (200u16, state.metrics.prometheus())
                    } else {
                        (404, String::new())
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(body)))
                            .expect("valid response"),
                    )
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
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
