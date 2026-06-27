//! Domain blocklist with wildcard support (RPZ-style filtering).
//!
//! Loads a list of domain names from a file (one per line, `;` or `#` comments
//! supported). A name is blocked if it matches exactly or falls under a
//! wildcard entry (`*.example.com` blocks `anything.example.com` but not
//! `example.com` itself).
//!
//! Blocked queries get a synthesized NXDOMAIN response, so the client stops
//! retrying. The blocklist is stored behind `ArcSwap` so it can be hot-reloaded
//! on `SIGHUP` without dropping in-flight queries.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use tracing::warn;

/// A domain blocklist, hot-reloadable via `ArcSwap`.
pub struct Blocklist {
    entries: ArcSwap<HashSet<String>>,
    /// The file path the blocklist was loaded from (for reload), if any.
    path: Option<String>,
}

impl Blocklist {
    /// Creates an empty blocklist (nothing blocked).
    pub fn empty() -> Self {
        Blocklist {
            entries: ArcSwap::from_pointee(HashSet::new()),
            path: None,
        }
    }

    /// Loads a blocklist from `path`, one domain per line.
    pub fn from_file(path: &str) -> Result<Self> {
        let set = load_blocklist_file(path)?;
        Ok(Blocklist {
            entries: ArcSwap::from_pointee(set),
            path: Some(path.to_string()),
        })
    }

    /// Builds a blocklist from an in-memory list of domains (for tests).
    pub fn from_domains(domains: Vec<String>) -> Self {
        let set: HashSet<String> = domains.into_iter().map(|d| d.to_lowercase()).collect();
        Blocklist {
            entries: ArcSwap::from_pointee(set),
            path: None,
        }
    }

    /// Whether blocking is active (a non-empty blocklist was loaded).
    pub fn is_active(&self) -> bool {
        !self.entries.load().is_empty()
    }

    /// Whether `name` is blocked, checking exact and wildcard matches.
    ///
    /// A wildcard entry `*.example.com` blocks `sub.example.com` and
    /// `a.b.example.com` but not `example.com` itself.
    pub fn is_blocked(&self, name: &str) -> bool {
        let entries = self.entries.load();
        let name = name.to_lowercase();
        if entries.contains(&name) {
            return true;
        }
        // Try wildcard matches: for each parent suffix, check if `*.<suffix>`
        // is in the blocklist.
        let mut remainder = &name[..];
        while let Some(pos) = remainder.find('.') {
            remainder = &remainder[pos + 1..];
            if entries.contains(&format!("*.{remainder}")) {
                return true;
            }
        }
        false
    }

    /// Reloads the blocklist from disk (if a path was configured).
    pub fn reload(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let set = load_blocklist_file(path)?;
        let count = set.len();
        self.entries.store(Arc::new(set));
        tracing::info!(path, entries = count, "blocklist reloaded");
        Ok(())
    }
}

/// Parses a blocklist file: one domain per line, `;` or `#` start a comment.
fn load_blocklist_file(path: &str) -> Result<HashSet<String>> {
    let content = fs::read_to_string(path).with_context(|| format!("reading blocklist {path}"))?;
    let mut set = HashSet::new();
    for (idx, line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let domain = line.to_lowercase();
        if domain.is_empty() {
            continue;
        }
        if !is_valid_domain(&domain) {
            warn!("{path}:{lineno}: invalid domain `{domain}`; skipping");
            continue;
        }
        set.insert(domain);
    }
    Ok(set)
}

/// Minimal validation: domain labels are alphanumeric, hyphens, or a leading `*`.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return false;
        }
        // Allow a leading wildcard in the first label only.
        let check = label.strip_prefix('*').unwrap_or(label);
        if check.is_empty() {
            // `*.` is valid (wildcard); `*.example.com` -> first label is `*`
            continue;
        }
        if !check
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_wildcard_match() {
        let bl = Blocklist::from_domains(vec![
            "ads.example.com".to_string(),
            "*.tracker.com".to_string(),
        ]);
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("sub.tracker.com"));
        assert!(bl.is_blocked("a.b.tracker.com"));
        // Wildcard does not match the apex itself.
        assert!(!bl.is_blocked("tracker.com"));
        // Unrelated names are not blocked.
        assert!(!bl.is_blocked("example.com"));
    }

    #[test]
    fn case_insensitive() {
        let bl = Blocklist::from_domains(vec!["Ads.Example.COM".to_string()]);
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("ADS.EXAMPLE.COM"));
    }

    #[test]
    fn empty_blocklist_blocks_nothing() {
        let bl = Blocklist::empty();
        assert!(!bl.is_blocked("anything.com"));
        assert!(!bl.is_active());
    }
}
