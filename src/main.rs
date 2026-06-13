//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

use anyhow::{Context, Result};
use clap::Parser;
use mini_dns::cache::Cache;
use mini_dns::config;
use mini_dns::forwarder::Forwarder;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::server::{self, TlsOptions};
use mini_dns::state::ServerState;
use mini_dns::tls;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// A lightweight DNS server with optional recursive forwarding.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the zone file to serve.
    #[arg(short, long, env = "MINI_DNS_ZONE", default_value = "zones/example.zone")]
    zone: String,

    /// Address to bind to (UDP and TCP).
    #[arg(short, long, env = "MINI_DNS_ADDR", default_value = server::DEFAULT_ADDR)]
    addr: String,

    /// Upstream resolver for recursion (host:port, port defaults to 53).
    #[arg(short, long, env = "MINI_DNS_UPSTREAM", default_value = "8.8.8.8:53")]
    upstream: String,

    /// Disable recursive forwarding (serve only the local zone).
    #[arg(long)]
    no_recurse: bool,

    /// Max queries per client IP per second (0 disables rate limiting).
    #[arg(long, env = "MINI_DNS_RATE_LIMIT", default_value_t = 0)]
    rate_limit: u32,

    /// Maximum number of cached entries for forwarded answers.
    #[arg(long, default_value_t = 1024)]
    cache_size: usize,

    /// Enable DNS-over-TLS on this address (e.g. 127.0.0.1:8853).
    #[arg(long, env = "MINI_DNS_DOT_ADDR")]
    dot_addr: Option<String>,

    /// Enable DNS-over-HTTPS on this address (e.g. 127.0.0.1:8443).
    #[arg(long, env = "MINI_DNS_DOH_ADDR")]
    doh_addr: Option<String>,

    /// TLS certificate (PEM). If omitted with DoT/DoH, a self-signed cert is generated.
    #[arg(long, env = "MINI_DNS_TLS_CERT")]
    tls_cert: Option<String>,

    /// TLS private key (PEM). Required together with --tls-cert.
    #[arg(long, env = "MINI_DNS_TLS_KEY")]
    tls_key: Option<String>,

    /// Expose Prometheus metrics over plain HTTP at /metrics on this address.
    #[arg(long, env = "MINI_DNS_METRICS_ADDR")]
    metrics_addr: Option<String>,

    /// Increase log verbosity (use -v for debug, -vv for trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Parses `host:port`, defaulting the port to 53 if omitted.
fn parse_upstream(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    format!("{s}:53")
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid upstream address `{s}`"))
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Thread-per-core: one runtime worker per core, each pinned to a distinct
    // core. Combined with the SO_REUSEPORT sockets, this keeps each core's recv
    // loop on its own CPU and reduces cross-core thread migration. Pinning is
    // best-effort (a no-op where the OS doesn't support it).
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let worker_threads = core_ids.len().max(1);
    let next_core = AtomicUsize::new(0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .on_thread_start(move || {
            if core_ids.is_empty() {
                return;
            }
            let idx = next_core.fetch_add(1, Ordering::Relaxed) % core_ids.len();
            core_affinity::set_for_current(core_ids[idx]);
        })
        .build()
        .context("failed to build Tokio runtime")?;

    runtime.block_on(run_server(args))
}

async fn run_server(args: Args) -> Result<()> {
    // Log level: default to INFO, then RUST_LOG overrides, then -v/-vv overrides.
    let default_level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("mini_dns={default_level}")));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load the zone file into a `Zone` configuration.
    let zone = config::load_zone_file(&args.zone)?;

    // Configure recursive forwarding unless disabled.
    let forwarder = if args.no_recurse {
        info!("recursion disabled; serving local zone only");
        None
    } else {
        let upstream = parse_upstream(&args.upstream)?;
        info!(%upstream, "recursion enabled; forwarding unknown names");
        Some(Forwarder::new(upstream, Duration::from_secs(5)))
    };

    let limiter = if args.rate_limit == 0 {
        RateLimiter::disabled()
    } else {
        RateLimiter::new(args.rate_limit, Duration::from_secs(1))
    };

    let state = Arc::new(ServerState::new(
        zone,
        Some(args.zone.clone()),
        forwarder,
        Cache::new(args.cache_size),
        limiter,
    ));

    // Configure encrypted transports (DoT / DoH) if any address was given.
    let tls = if args.dot_addr.is_some() || args.doh_addr.is_some() {
        // ALPN advertises DoT plus HTTP/2 and HTTP/1.1 for DoH; each client
        // negotiates its own protocol per connection.
        let assets = tls::build(
            args.tls_cert.as_deref(),
            args.tls_key.as_deref(),
            vec![b"dot".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()],
        )?;
        if args.tls_cert.is_none() {
            info!("no TLS certificate provided; using a generated self-signed cert");
        }
        Some(TlsOptions {
            acceptor: TlsAcceptor::from(assets.config),
            dot_addr: args.dot_addr.clone(),
            doh_addr: args.doh_addr.clone(),
        })
    } else {
        None
    };

    // Start the DNS server.
    server::run(state, &args.addr, tls, args.metrics_addr.as_deref()).await
}
