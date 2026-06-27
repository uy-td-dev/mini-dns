//! A simple per-client fixed-window rate limiter.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct Window {
    started_at: Instant,
    count: u32,
}

/// Limits each client IP to at most `max_per_window` queries per `window`.
///
/// A `max_per_window` of zero disables limiting (all queries are allowed). This
/// guards against floods and DNS amplification abuse. Per-IP state lives in a
/// `DashMap` so different clients hit different shards instead of one mutex.
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    clients: DashMap<IpAddr, Window>,
}

impl RateLimiter {
    /// Creates a limiter allowing `max_per_window` queries per `window`.
    /// Pass `max_per_window = 0` to disable limiting entirely.
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        RateLimiter {
            max_per_window,
            window,
            clients: DashMap::new(),
        }
    }

    /// A disabled limiter that allows every query.
    pub fn disabled() -> Self {
        Self::new(0, Duration::from_secs(1))
    }

    /// Records a query from `ip` and returns `true` if it is within the limit.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let now = Instant::now();
        let mut window = self.clients.entry(ip).or_insert(Window {
            started_at: now,
            count: 0,
        });

        if now.checked_duration_since(window.started_at).is_some_and(|d| d >= self.window) {
            window.started_at = now;
            window.count = 0;
        }
        window.count += 1;
        window.count <= self.max_per_window
    }

    /// The number of distinct clients currently tracked.
    pub fn tracked_clients(&self) -> usize {
        self.clients.len()
    }

    /// Drops clients whose current window has fully elapsed.
    ///
    /// Such a client would have its window reset on its next query anyway, so
    /// removing it frees memory without changing rate-limiting behaviour. A
    /// background task calls this periodically to bound memory under a flood of
    /// many distinct (e.g. spoofed) source addresses.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.clients
            .retain(|_, window| now.duration_since(window.started_at) < self.window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    #[test]
    fn disabled_allows_everything() {
        let limiter = RateLimiter::disabled();
        for _ in 0..1000 {
            assert!(limiter.allow(ip(1)));
        }
    }

    #[test]
    fn enforces_limit_per_client() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(1)));
        assert!(!limiter.allow(ip(1))); // 4th exceeds the limit

        // A different client has its own budget.
        assert!(limiter.allow(ip(2)));
    }

    #[test]
    fn cleanup_drops_idle_clients_bounding_memory() {
        let limiter = RateLimiter::new(5, Duration::from_millis(10));
        for i in 0..50 {
            limiter.allow(ip(i));
        }
        assert_eq!(limiter.tracked_clients(), 50);

        // Once every window has elapsed, cleanup must reclaim all of them.
        std::thread::sleep(Duration::from_millis(25));
        limiter.cleanup();
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[test]
    fn cleanup_keeps_clients_within_their_window() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        limiter.allow(ip(1));
        limiter.cleanup(); // window still open -> kept
        assert_eq!(limiter.tracked_clients(), 1);
    }
}
