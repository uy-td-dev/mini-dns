//! A simple TTL-based answer cache for forwarded (recursive) queries.

use crate::dns::record::DnsRecord;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Cache key: the lowercase query name and the query type.
type Key = (String, u16);

struct Entry {
    records: Vec<DnsRecord>,
    expires_at: Instant,
}

/// A bounded, TTL-aware cache mapping `(name, type)` to answer records.
///
/// Entries expire based on the smallest TTL among their records. The cache is
/// guarded by a `Mutex`; locks are held only briefly and never across `.await`.
pub struct Cache {
    map: Mutex<HashMap<Key, Entry>>,
    capacity: usize,
}

impl Cache {
    /// Creates a cache holding up to `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Cache {
            map: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Returns cached records for `(name, qtype)` if present and not expired.
    pub fn get(&self, name: &str, qtype: u16) -> Option<Vec<DnsRecord>> {
        let key = (name.to_lowercase(), qtype);
        let mut map = self.map.lock().unwrap();
        match map.get(&key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.records.clone()),
            Some(_) => {
                map.remove(&key); // expired
                None
            }
            None => None,
        }
    }

    /// Inserts records for `(name, qtype)`, expiring after `ttl_secs` seconds.
    ///
    /// A `ttl_secs` of zero (or empty records) is not cached.
    pub fn insert(&self, name: &str, qtype: u16, records: Vec<DnsRecord>, ttl_secs: u32) {
        if records.is_empty() || ttl_secs == 0 {
            return;
        }
        let mut map = self.map.lock().unwrap();
        // Naive capacity bound: clear when full. Adequate for a small cache.
        if map.len() >= self.capacity && !map.contains_key(&(name.to_lowercase(), qtype)) {
            map.clear();
        }
        map.insert(
            (name.to_lowercase(), qtype),
            Entry {
                records,
                expires_at: Instant::now() + Duration::from_secs(ttl_secs as u64),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn a_record(ttl: u32) -> DnsRecord {
        DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl,
        }
    }

    #[test]
    fn hit_and_case_insensitive() {
        let cache = Cache::new(8);
        cache.insert("Example.com", 1, vec![a_record(3600)], 3600);
        assert_eq!(cache.get("example.com", 1).unwrap().len(), 1);
        assert!(cache.get("example.com", 28).is_none()); // wrong type
    }

    #[test]
    fn zero_ttl_not_cached() {
        let cache = Cache::new(8);
        cache.insert("example.com", 1, vec![a_record(0)], 0);
        assert!(cache.get("example.com", 1).is_none());
    }

    #[test]
    fn empty_records_not_cached() {
        let cache = Cache::new(8);
        cache.insert("example.com", 1, vec![], 3600);
        assert!(cache.get("example.com", 1).is_none());
    }
}
