//! A TTL-based response cache for forwarded (recursive) queries.
//!
//! Caches the raw upstream response bytes (positive answers *and* negative
//! NXDOMAIN/NODATA results), keyed by `(name, qtype)`. Replaying raw bytes
//! preserves record types the server doesn't model; callers patch in the
//! client's transaction ID before sending.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cache key: the lowercase query name and the query type.
type Key = (String, u16);

struct Entry {
    response: Arc<Vec<u8>>,
    expires_at: Instant,
}

/// A bounded, TTL-aware cache mapping `(name, type)` to a raw response message.
///
/// Backed by a `DashMap` (sharded locking) so concurrent lookups across cores
/// don't serialise on a single mutex.
pub struct Cache {
    map: DashMap<Key, Entry>,
    capacity: usize,
}

impl Cache {
    /// Creates a cache holding up to `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Cache {
            map: DashMap::new(),
            capacity,
        }
    }

    /// Returns the cached response for `(name, qtype)` if present and not expired.
    pub fn get(&self, name: &str, qtype: u16) -> Option<Arc<Vec<u8>>> {
        let key = (name.to_lowercase(), qtype);
        // The shard ref is released at the end of this statement, before remove.
        let expired = match self.map.get(&key) {
            Some(entry) if entry.expires_at > Instant::now() => {
                return Some(Arc::clone(&entry.response));
            }
            Some(_) => true,
            None => false,
        };
        if expired {
            self.map.remove(&key);
        }
        None
    }

    /// The number of entries currently held (including any not-yet-evicted
    /// expired ones).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the cache currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Caches `response` for `(name, qtype)`, expiring after `ttl_secs` seconds.
    /// A `ttl_secs` of zero (or empty response) is not cached.
    pub fn insert(&self, name: &str, qtype: u16, response: Vec<u8>, ttl_secs: u32) {
        if response.is_empty() || ttl_secs == 0 {
            return;
        }
        let key = (name.to_lowercase(), qtype);
        if !self.map.contains_key(&key) {
            self.evict_if_full();
        }
        self.map.insert(
            key,
            Entry {
                response: Arc::new(response),
                expires_at: Instant::now() + Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    /// Keeps the cache within `capacity` before inserting a new key.
    ///
    /// Reclaims expired entries first; if that doesn't free space, drops a
    /// single live entry. This avoids the "wipe everything" cliff a naive
    /// `clear()` would cause, so a burst of misses can't evict the whole hot
    /// set at once. Eviction of a live entry is approximate (not strict LRU),
    /// which is an acceptable trade-off for a small response cache.
    fn evict_if_full(&self) {
        if self.map.len() < self.capacity {
            return;
        }
        let now = Instant::now();
        self.map.retain(|_, entry| entry.expires_at > now);
        if self.map.len() >= self.capacity {
            // Still full of live entries: drop one to make room. The key is
            // cloned out first so the iterator's shard lock is released before
            // `remove` runs.
            let victim = self.map.iter().next().map(|e| e.key().clone());
            if let Some(victim) = victim {
                self.map.remove(&victim);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_and_case_insensitive() {
        let cache = Cache::new(8);
        cache.insert("Example.com", 1, vec![1, 2, 3], 3600);
        assert_eq!(*cache.get("example.com", 1).unwrap(), vec![1, 2, 3]);
        assert!(cache.get("example.com", 28).is_none()); // wrong type
    }

    #[test]
    fn zero_ttl_not_cached() {
        let cache = Cache::new(8);
        cache.insert("example.com", 1, vec![1, 2, 3], 0);
        assert!(cache.get("example.com", 1).is_none());
    }

    #[test]
    fn empty_response_not_cached() {
        let cache = Cache::new(8);
        cache.insert("example.com", 1, vec![], 3600);
        assert!(cache.get("example.com", 1).is_none());
    }

    #[test]
    fn full_cache_evicts_incrementally_not_wholesale() {
        let cache = Cache::new(4);
        for i in 0..4u8 {
            cache.insert(&format!("d{i}.example"), 1, vec![i], 3600);
        }
        // Cache is now full of live entries; inserting one more must make room
        // incrementally, not wipe the entire hot set (the old `clear()` cliff).
        cache.insert("new.example", 1, vec![99], 3600);

        // Size stays bounded at capacity.
        assert_eq!(cache.len(), 4);
        // The newest entry is present.
        assert_eq!(*cache.get("new.example", 1).unwrap(), vec![99]);
        // We dropped at most one prior entry — not all of them.
        let survivors = (0..4u8)
            .filter(|i| cache.get(&format!("d{i}.example"), 1).is_some())
            .count();
        assert!(
            survivors >= 3,
            "expected incremental eviction, only {survivors} of 4 survived"
        );
    }
}
