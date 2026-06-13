//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

use anyhow::{Context, Result};
use clap::Parser;
use mini_dns::cache::Cache;
use mini_dns::config;
use mini_dns::forwarder::Forwarder;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::server;
use mini_dns::state::ServerState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    // Start the DNS server.
    server::run(state, &args.addr).await
}
