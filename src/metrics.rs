//! Lightweight in-process counters for observability.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters tracking how the server handled queries.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total queries received (before rate limiting).
    pub total: AtomicU64,
    /// Queries answered from the local zone.
    pub authoritative: AtomicU64,
    /// Queries answered from the forwarding cache.
    pub cache_hits: AtomicU64,
    /// Queries forwarded to the upstream resolver.
    pub forwarded: AtomicU64,
    /// Queries dropped by the rate limiter.
    pub rate_limited: AtomicU64,
    /// Packets that failed to parse or forward.
    pub errors: AtomicU64,
}

impl Metrics {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_total(&self) {
        Self::bump(&self.total);
    }
    pub fn inc_authoritative(&self) {
        Self::bump(&self.authoritative);
    }
    pub fn inc_cache_hit(&self) {
        Self::bump(&self.cache_hits);
    }
    pub fn inc_forwarded(&self) {
        Self::bump(&self.forwarded);
    }
    pub fn inc_rate_limited(&self) {
        Self::bump(&self.rate_limited);
    }
    pub fn inc_error(&self) {
        Self::bump(&self.errors);
    }

    /// Returns a human-readable one-line snapshot of the current counters.
    pub fn summary(&self) -> String {
        format!(
            "total={} authoritative={} cache_hits={} forwarded={} rate_limited={} errors={}",
            self.total.load(Ordering::Relaxed),
            self.authoritative.load(Ordering::Relaxed),
            self.cache_hits.load(Ordering::Relaxed),
            self.forwarded.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}
