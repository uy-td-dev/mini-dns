//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

use anyhow::{Context, Result};
use clap::Parser;
use mini_dns::acl::Acl;
use mini_dns::blocklist::Blocklist;
use mini_dns::cache::Cache;
use mini_dns::config::{self, forward_rules_from_settings, load_zones_from_settings, ForwardRules, ZoneSet};
use mini_dns::forwarder::MultiForwarder;
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
    /// Path to a TOML config file. When given, file values are used as defaults
    /// and individual CLI flags override them.
    #[arg(long, env = "MINI_DNS_CONFIG")]
    config: Option<String>,

    /// Path to the zone file to serve (single-zone mode; ignored when --config
    /// is given, since the config declares its own zones).
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

    /// Enable DNS-over-QUIC on this address (e.g. 127.0.0.1:8853).
    #[arg(long, env = "MINI_DNS_DOQ_ADDR")]
    doq_addr: Option<String>,

    /// TLS certificate (PEM). If omitted with DoT/DoH/DoQ, a self-signed cert is generated.
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

    // Load TOML config (if any). CLI flags override config-file values, so the
    // config is the base layer and each CLI flag that was explicitly set wins.
    let settings = match args.config.as_deref() {
        Some(path) => Some(config::load_settings(path)?),
        None => None,
    };

    // --- Zones -------------------------------------------------------------
    let (zones, zone_path) = if let Some(settings) = &settings {
        let z = load_zones_from_settings(settings)?;
        (z, args.config.clone())
    } else {
        // Single-zone legacy mode: load one zone file, infer origin from SOA.
        let az = config::load_zone_with_inferred_origin(&args.zone)?;
        let origin = az.origin.clone();
        let count: usize = az.records.values().map(Vec::len).sum();
        info!(origin = %origin, records = count, "loaded zone");
        (ZoneSet::from_single(origin, az.records), Some(args.zone.clone()))
    };

    // --- Forwarding / Recursion -------------------------------------------
    let (forward_rules, forwarder) = if args.no_recurse {
        info!("recursion disabled; serving local zone only");
        (ForwardRules::none(), None)
    } else {
        // Build forwarding rules: config-file rules as the base, then the CLI
        // --upstream as the default (overriding the config's default).
        let rules = if let Some(s) = &settings {
            forward_rules_from_settings(s)?
        } else {
            ForwardRules::none()
        };
        // CLI --upstream overrides the config's default upstream.
        let cli_upstream = parse_upstream(&args.upstream)?;

        // Check if recursive mode is enabled in config. When recursive, the
        // default upstream is NOT used (the recursive resolver handles unmatched
        // names). Only conditional forwarding rules (specific suffix → specific
        // upstream) are kept.
        let recursive_mode = settings
            .as_ref()
            .and_then(|s| s.upstream.as_ref())
            .map(|u| u.recursive)
            .unwrap_or(false);

        let rules = if recursive_mode {
            // Keep only per-domain rules; drop the default so unmatched names
            // fall through to the recursive resolver.
            let rule_list = rules.rules().to_vec();
            ForwardRules::new(None, rule_list)
        } else {
            rules.with_default(cli_upstream)
        };

        if rules.is_enabled() {
            info!(default = ?rules.default_upstream(), "recursion enabled; forwarding unknown names");
        }
        let timeout = settings
            .as_ref()
            .and_then(|s| s.upstream.as_ref())
            .and_then(|u| u.timeout_secs)
            .unwrap_or(5);
        (rules, Some(MultiForwarder::new(Duration::from_secs(timeout))))
    };

    // Check if recursive mode is enabled in config.
    let recursive_mode = settings
        .as_ref()
        .and_then(|s| s.upstream.as_ref())
        .map(|u| u.recursive)
        .unwrap_or(false);
    if recursive_mode {
        info!("recursive mode enabled; resolving iteratively from root");
    }

    // --- Rate limiter ------------------------------------------------------
    let limiter = if args.rate_limit == 0 {
        RateLimiter::disabled()
    } else {
        RateLimiter::new(args.rate_limit, Duration::from_secs(1))
    };

    // --- Blocklist (optional) ---------------------------------------------
    let blocklist = if let Some(s) = &settings
        && let Some(bl_cfg) = s.blocklist.as_ref()
    {
        match Blocklist::from_file(&bl_cfg.file) {
            Ok(bl) => {
                info!(path = %bl_cfg.file, "blocklist loaded");
                bl
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to load blocklist; continuing without it");
                Blocklist::empty()
            }
        }
    } else {
        Blocklist::empty()
    };

    // --- DNS64 (optional) --------------------------------------------------
    let dns64_prefix = if let Some(s) = &settings
        && let Some(d64) = s.dns64.as_ref()
    {
        d64.prefix.as_deref().and_then(|p| p.parse().ok())
    } else {
        None
    };
    if let Some(ref prefix) = dns64_prefix {
        info!(%prefix, "DNS64 AAAA synthesis enabled");
    }

    let mut state = ServerState::new(
        zones,
        zone_path,
        forward_rules,
        forwarder,
        Cache::new(args.cache_size),
        limiter,
    );
    if blocklist.is_active() {
        state = state.with_blocklist(blocklist);
    }
    if let Some(prefix) = dns64_prefix {
        state = state.with_dns64(prefix);
    }

    // --- AXFR ACL (optional) ----------------------------------------------
    let axfr_acl = if let Some(s) = &settings
        && let Some(axfr) = s.axfr.as_ref()
    {
        match Acl::parse(&axfr.allow) {
            Ok(acl) => {
                if !axfr.allow.is_empty() {
                    info!(entries = axfr.allow.len(), "AXFR ACL configured");
                }
                acl
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse AXFR ACL; denying all transfers");
                Acl::deny_all()
            }
        }
    } else {
        Acl::deny_all()
    };
    state = state.with_axfr_acl(axfr_acl);

    if recursive_mode {
        state = state.with_recursive();
    }

    // --- DNSSEC signing (optional) ----------------------------------------
    if let Some(s) = &settings
        && let Some(dnssec) = s.dnssec.as_ref()
        && dnssec.enabled
    {
        match mini_dns::dnssec::DnssecKeys::single("example.com") {
            Ok(keys) => {
                info!("DNSSEC signing enabled (ED25519)");
                state = state.with_dnssec(keys);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to generate DNSSEC keys; signing disabled");
            }
        }
    }

    let state = Arc::new(state);

    // --- TLS / encrypted transports ---------------------------------------
    // CLI flags override config-file values for DoT/DoH/DoQ/cert/key.
    let dot_addr = args.dot_addr.or_else(|| {
        settings.as_ref().and_then(|s| s.tls.as_ref()).and_then(|t| t.dot_addr.clone())
    });
    let doh_addr = args.doh_addr.or_else(|| {
        settings.as_ref().and_then(|s| s.tls.as_ref()).and_then(|t| t.doh_addr.clone())
    });
    let doq_addr = args.doq_addr.or_else(|| {
        settings.as_ref().and_then(|s| s.tls.as_ref()).and_then(|t| t.doq_addr.clone())
    });
    let tls_cert = args.tls_cert.or_else(|| {
        settings.as_ref().and_then(|s| s.tls.as_ref()).and_then(|t| t.cert.clone())
    });
    let tls_key = args.tls_key.or_else(|| {
        settings.as_ref().and_then(|s| s.tls.as_ref()).and_then(|t| t.key.clone())
    });

    let tls = if dot_addr.is_some() || doh_addr.is_some() || doq_addr.is_some() {
        let assets = tls::build(
            tls_cert.as_deref(),
            tls_key.as_deref(),
            vec![b"dot".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()],
        )?;
        if tls_cert.is_none() {
            info!("no TLS certificate provided; using a generated self-signed cert");
        }
        Some(TlsOptions {
            acceptor: TlsAcceptor::from(assets.config.clone()),
            dot_addr,
            doh_addr,
            doq_addr,
            rustls_config: Some(assets.config),
        })
    } else {
        None
    };

    // --- Metrics -----------------------------------------------------------
    let metrics_addr = args.metrics_addr.or_else(|| {
        settings.as_ref().and_then(|s| s.metrics.as_ref()).and_then(|m| m.addr.clone())
    });

    // --- Bind address ------------------------------------------------------
    let addr = args.addr;

    // Start the DNS server.
    server::run(state, &addr, tls, metrics_addr.as_deref()).await
}
