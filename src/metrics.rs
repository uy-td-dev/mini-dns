//! Sharded, cache-line-padded counters for observability.
//!
//! Under heavy load many cores increment the same counters. A single shared
//! atomic per counter would bounce its cache line between cores. Instead each
//! counter is sharded N ways, every thread writes to its own shard (so writes
//! rarely collide), and reads sum across shards. Shards are cache-line padded
//! to avoid false sharing.

use crossbeam_utils::CachePadded;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Number of counter shards. A power of two comfortably above typical core counts.
const SHARDS: usize = 32;

#[derive(Default)]
struct Counters {
    total: AtomicU64,
    authoritative: AtomicU64,
    cache_hits: AtomicU64,
    forwarded: AtomicU64,
    coalesced: AtomicU64,
    rate_limited: AtomicU64,
    blocked: AtomicU64,
    errors: AtomicU64,
}

/// Per-query counters, sharded across cores.
pub struct Metrics {
    shards: Vec<CachePadded<Counters>>,
}

thread_local! {
    /// A stable shard index for the current thread, assigned round-robin.
    static SHARD: usize = {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed) % SHARDS
    };
    /// Avoids re-reading the thread-local on every increment.
    static CACHED: Cell<Option<usize>> = const { Cell::new(None) };
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            shards: (0..SHARDS)
                .map(|_| CachePadded::new(Counters::default()))
                .collect(),
        }
    }
}

impl Metrics {
    fn shard_index() -> usize {
        CACHED.with(|c| match c.get() {
            Some(i) => i,
            None => {
                let i = SHARD.with(|&i| i);
                c.set(Some(i));
                i
            }
        })
    }

    fn bump(&self, select: impl Fn(&Counters) -> &AtomicU64) {
        let shard = &self.shards[Self::shard_index()];
        select(shard).fetch_add(1, Ordering::Relaxed);
    }

    fn sum(&self, select: impl Fn(&Counters) -> &AtomicU64) -> u64 {
        self.shards
            .iter()
            .map(|s| select(s).load(Ordering::Relaxed))
            .sum()
    }

    pub fn inc_total(&self) {
        self.bump(|c| &c.total);
    }
    pub fn inc_authoritative(&self) {
        self.bump(|c| &c.authoritative);
    }
    pub fn inc_cache_hit(&self) {
        self.bump(|c| &c.cache_hits);
    }
    pub fn inc_forwarded(&self) {
        self.bump(|c| &c.forwarded);
    }
    pub fn inc_coalesced(&self) {
        self.bump(|c| &c.coalesced);
    }
    pub fn inc_rate_limited(&self) {
        self.bump(|c| &c.rate_limited);
    }
    pub fn inc_blocked(&self) {
        self.bump(|c| &c.blocked);
    }
    pub fn inc_error(&self) {
        self.bump(|c| &c.errors);
    }

    pub fn total(&self) -> u64 {
        self.sum(|c| &c.total)
    }
    pub fn authoritative(&self) -> u64 {
        self.sum(|c| &c.authoritative)
    }
    pub fn cache_hits(&self) -> u64 {
        self.sum(|c| &c.cache_hits)
    }
    pub fn forwarded(&self) -> u64 {
        self.sum(|c| &c.forwarded)
    }
    pub fn coalesced(&self) -> u64 {
        self.sum(|c| &c.coalesced)
    }
    pub fn rate_limited(&self) -> u64 {
        self.sum(|c| &c.rate_limited)
    }
    pub fn blocked(&self) -> u64 {
        self.sum(|c| &c.blocked)
    }
    pub fn errors(&self) -> u64 {
        self.sum(|c| &c.errors)
    }

    /// Renders the counters in Prometheus text exposition format.
    pub fn prometheus(&self) -> String {
        let mut out = String::new();
        let counters = [
            ("mini_dns_queries_total", "Total queries received", self.total()),
            (
                "mini_dns_authoritative_total",
                "Queries answered from the local zone",
                self.authoritative(),
            ),
            (
                "mini_dns_cache_hits_total",
                "Queries answered from the cache",
                self.cache_hits(),
            ),
            (
                "mini_dns_forwarded_total",
                "Queries forwarded upstream",
                self.forwarded(),
            ),
            (
                "mini_dns_coalesced_total",
                "Queries coalesced by single-flight",
                self.coalesced(),
            ),
            (
                "mini_dns_rate_limited_total",
                "Queries dropped by the rate limiter",
                self.rate_limited(),
            ),
            (
                "mini_dns_blocked_total",
                "Queries blocked by the blocklist",
                self.blocked(),
            ),
            (
                "mini_dns_errors_total",
                "Packets that failed to parse or forward",
                self.errors(),
            ),
        ];
        for (name, help, value) in counters {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out
    }

    /// Returns a human-readable one-line snapshot of the current counters.
    pub fn summary(&self) -> String {
        format!(
            "total={} authoritative={} cache_hits={} forwarded={} coalesced={} rate_limited={} blocked={} errors={}",
            self.total(),
            self.authoritative(),
            self.cache_hits(),
            self.forwarded(),
            self.coalesced(),
            self.rate_limited(),
            self.blocked(),
            self.errors(),
        )
    }
}
