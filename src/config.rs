use crate::dns::record::DnsRecord;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::cmp::Reverse;
use std::fs;
use std::net::SocketAddr;
use tracing::warn;

/// A `Zone` represents a collection of DNS records, keyed by domain name.
pub type Zone = HashMap<String, Vec<DnsRecord>>;

/// An authoritative zone: its origin (apex) name and its records.
#[derive(Debug, Clone)]
pub struct AuthZone {
    /// The apex name of this zone (e.g. `example.com`).
    pub origin: String,
    /// Records keyed by owner name (lowercase, trailing dot stripped).
    pub records: Zone,
}

/// A collection of authoritative zones, supporting longest-suffix lookup so
/// a query for `www.corp.example.com` matches the `corp.example.com` zone
/// before the `example.com` zone.
#[derive(Debug, Clone, Default)]
pub struct ZoneSet {
    /// Sorted by origin length descending so the longest-suffix match wins.
    zones: Vec<AuthZone>,
}

impl ZoneSet {
    /// Builds a zone set from the given zones, sorting for longest-match lookup.
    pub fn new(mut zones: Vec<AuthZone>) -> Self {
        zones.sort_by_key(|b| Reverse(b.origin.len()));
        ZoneSet { zones }
    }

    /// Convenience for the single-zone case (backward compatible).
    pub fn from_single(origin: String, records: Zone) -> Self {
        Self::new(vec![AuthZone { origin, records }])
    }

    /// Builds a single-zone `ZoneSet`, inferring the origin from the SOA
    /// record if present (empty origin otherwise). Handy for tests and the
    /// legacy `--zone` single-file mode.
    pub fn from_records(records: Zone) -> Self {
        let origin = records
            .values()
            .flatten()
            .find_map(|r| match r {
                DnsRecord::SOA { domain, .. } => Some(domain.clone()),
                _ => None,
            })
            .unwrap_or_default();
        Self::from_single(origin, records)
    }

    /// An empty zone set (nothing served authoritatively).
    pub fn empty() -> Self {
        ZoneSet { zones: Vec::new() }
    }

    /// Whether no zones are configured.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// The number of zones.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Finds the zone authoritative for `name` via longest-suffix match on
    /// each zone's origin. `name` matches a zone if it equals the origin or
    /// is a descendant of it (`<name>.<origin>`). A zone with an empty origin
    /// (the legacy single-zone mode with no SOA) matches every name, but only
    /// after more specific zones have been tried (it sorts last by length).
    pub fn find(&self, name: &str) -> Option<&AuthZone> {
        self.zones.iter().find(|z| {
            z.origin.is_empty() || name == z.origin || name.ends_with(&format!(".{}", z.origin))
        })
    }

    /// All zones, in longest-origin-first order.
    pub fn zones(&self) -> &[AuthZone] {
        &self.zones
    }

    /// Total record count across all zones (for logging).
    pub fn record_count(&self) -> usize {
        self.zones.iter().map(|z| z.records.values().map(Vec::len).sum::<usize>()).sum()
    }
}

/// A conditional forwarding rule: queries for names ending in `suffix` are
/// forwarded to `upstream` instead of the default resolver.
#[derive(Debug, Clone)]
pub struct ForwardRule {
    /// Domain suffix that triggers this rule (e.g. `corp.example.com`).
    pub suffix: String,
    /// The upstream resolver to forward matching queries to.
    pub upstream: SocketAddr,
}

/// Conditional forwarding rules with longest-suffix matching.
///
/// A query name is matched against each rule's suffix; the longest matching
/// suffix wins. Names that match no rule use the default upstream (if any).
#[derive(Debug, Clone, Default)]
pub struct ForwardRules {
    /// Sorted by suffix length descending so the longest match wins.
    rules: Vec<ForwardRule>,
    /// The upstream used when no rule matches (the "default recursive" target).
    default: Option<SocketAddr>,
}

impl ForwardRules {
    /// Builds forwarding rules from a default upstream and a list of rules.
    pub fn new(default: Option<SocketAddr>, mut rules: Vec<ForwardRule>) -> Self {
        rules.sort_by_key(|b| Reverse(b.suffix.len()));
        ForwardRules { rules, default }
    }

    /// A single default upstream, no per-domain rules.
    pub fn single(default: SocketAddr) -> Self {
        ForwardRules::new(Some(default), Vec::new())
    }

    /// No forwarding at all.
    pub fn none() -> Self {
        ForwardRules::default()
    }

    /// Returns the upstream resolver for `name`, or `None` if forwarding is
    /// not configured for it.
    pub fn match_name(&self, name: &str) -> Option<SocketAddr> {
        for rule in &self.rules {
            if name == rule.suffix || name.ends_with(&format!(".{}", rule.suffix)) {
                return Some(rule.upstream);
            }
        }
        self.default
    }

    /// Whether any forwarding is configured (default or rules).
    pub fn is_enabled(&self) -> bool {
        self.default.is_some() || !self.rules.is_empty()
    }

    /// Returns a new `ForwardRules` with the default upstream replaced, keeping
    /// the existing per-domain rules.
    pub fn with_default(self, default: SocketAddr) -> Self {
        ForwardRules::new(Some(default), self.rules)
    }

    /// The per-domain rules (for logging/diagnostics).
    pub fn rules(&self) -> &[ForwardRule] {
        &self.rules
    }

    /// The default upstream, if any.
    pub fn default_upstream(&self) -> Option<SocketAddr> {
        self.default
    }
}

/// Loads a zone file and infers the origin from the SOA record (if present),
/// falling back to an empty origin (single-zone legacy mode).
pub fn load_zone_with_inferred_origin(path: &str) -> Result<AuthZone> {
    let records = load_zone_file(path)?;
    let origin = records
        .values()
        .flatten()
        .find_map(|r| match r {
            DnsRecord::SOA { domain, .. } => Some(domain.clone()),
            _ => None,
        })
        .unwrap_or_default();
    Ok(AuthZone { origin, records })
}

/// Top-level server configuration, deserialisable from a TOML file.
///
/// All fields are optional; any omitted section falls back to the CLI/env
/// defaults. Example:
///
/// ```toml
/// [server]
/// addr = "0.0.0.0:53"
/// rate_limit = 50
///
/// [upstream]
/// default = "1.1.1.1:53"
/// timeout_secs = 5
///
/// [[upstream.rules]]
/// suffix = "corp.example.com"
/// upstream = "10.0.0.53:53"
///
/// [[zone]]
/// origin = "example.com"
/// file = "zones/example.zone"
///
/// [[zone]]
/// origin = "internal"
/// file = "zones/internal.zone"
///
/// [tls]
/// dot_addr = "0.0.0.0:853"
/// doh_addr = "0.0.0.0:443"
///
/// [metrics]
/// addr = "0.0.0.0:9153"
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct Settings {
    pub server: Option<ServerSettings>,
    pub upstream: Option<UpstreamSettings>,
    pub zone: Option<Vec<ZoneSettings>>,
    pub tls: Option<TlsSettings>,
    pub metrics: Option<MetricsSettings>,
    pub blocklist: Option<BlocklistSettings>,
    pub dns64: Option<Dns64Settings>,
    pub axfr: Option<AxfrSettings>,
    pub dnssec: Option<DnssecSettings>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServerSettings {
    pub addr: Option<String>,
    pub no_recurse: Option<bool>,
    pub rate_limit: Option<u32>,
    pub cache_size: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpstreamSettings {
    pub default: Option<String>,
    pub timeout_secs: Option<u64>,
    pub rules: Option<Vec<ForwardRuleSettings>>,
    /// When true, resolve queries iteratively from root instead of forwarding
    /// to a stub upstream. This makes mini-dns a full recursive resolver that
    /// doesn't depend on 8.8.8.8/1.1.1.1. Conditional forwarding rules still
    /// apply (matched names go to their specific upstream).
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct ForwardRuleSettings {
    pub suffix: String,
    pub upstream: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ZoneSettings {
    pub origin: String,
    pub file: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct TlsSettings {
    pub dot_addr: Option<String>,
    pub doh_addr: Option<String>,
    pub doq_addr: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MetricsSettings {
    pub addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct BlocklistSettings {
    /// Path to a blocklist file (one domain per line, `;`/`#` comments).
    pub file: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Dns64Settings {
    /// The NAT64 prefix to use for AAAA synthesis (default: `64:ff9b::/96`).
    pub prefix: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AxfrSettings {
    /// CIDR ranges or single IPs allowed to request zone transfers.
    /// Example: `["10.0.0.0/8", "192.168.1.5"]`. Empty = deny all.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DnssecSettings {
    /// Enable DNSSEC signing. Generates an ED25519 key at startup, publishes
    /// DNSKEY records at zone apexes, and signs answer RRsets with RRSIG.
    #[serde(default)]
    pub enabled: bool,
}

/// Parses a TOML config file into `Settings`.
pub fn load_settings(path: &str) -> Result<Settings> {
    let content = fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    toml::from_str(&content).with_context(|| format!("parsing config {path}"))
}

/// Loads all zones declared in `Settings` into a `ZoneSet`.
pub fn load_zones_from_settings(settings: &Settings) -> Result<ZoneSet> {
    let zone_cfgs = settings.zone.as_ref();
    let Some(zone_cfgs) = zone_cfgs else {
        return Ok(ZoneSet::empty());
    };
    let mut zones = Vec::with_capacity(zone_cfgs.len());
    for z in zone_cfgs {
        let records = load_zone_file(&z.file)
            .with_context(|| format!("loading zone {} from {}", z.origin, z.file))?;
        zones.push(AuthZone {
            origin: z.origin.to_lowercase(),
            records,
        });
    }
    Ok(ZoneSet::new(zones))
}

/// Parses `host:port`, defaulting the port to 53 if omitted.
pub fn parse_upstream_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    format!("{s}:53")
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid upstream address `{s}`"))
}

/// Builds `ForwardRules` from `Settings`, resolving rule upstreams.
pub fn forward_rules_from_settings(settings: &Settings) -> Result<ForwardRules> {
    let Some(up) = settings.upstream.as_ref() else {
        return Ok(ForwardRules::none());
    };
    let default = match up.default.as_deref() {
        Some(s) => Some(parse_upstream_addr(s)?),
        None => None,
    };
    let mut rules = Vec::new();
    if let Some(rule_cfgs) = up.rules.as_ref() {
        for r in rule_cfgs {
            rules.push(ForwardRule {
                suffix: r.suffix.to_lowercase(),
                upstream: parse_upstream_addr(&r.upstream)?,
            });
        }
    }
    Ok(ForwardRules::new(default, rules))
}

/// `load_zone_file` parses a zone file and loads the DNS records into a `Zone`.
///
/// The zone file has a simple line-based format where each line is one record:
/// `domain ttl type data`. Lines that are blank or start with `;` are ignored.
/// A malformed line is logged with its line number and skipped, so a single bad
/// entry never prevents the rest of the zone from loading.
///
/// For example:
/// ```text
/// example.com.     3600 A     192.0.2.1
/// example.com.     3600 AAAA  2001:db8::1
/// www.example.com. 3600 CNAME example.com.
/// example.com.     3600 MX    10 mail.example.com.
/// example.com.     3600 TXT   "v=spf1 -all"
/// example.com.     3600 NS    ns1.example.com.
/// example.com.     3600 SOA   ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
/// *.example.com.   3600 A     192.0.2.9
/// ```
pub fn load_zone_file(path: &str) -> Result<Zone> {
    let content = fs::read_to_string(path).context("Failed to read zone file")?;
    let mut zone = Zone::new();

    for (idx, line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        match parse_line(line) {
            Ok(Some((domain, record))) => zone.entry(domain).or_default().push(record),
            Ok(None) => {} // unsupported record type, silently skipped
            Err(e) => warn!("{path}:{lineno}: {e}; skipping line"),
        }
    }

    Ok(zone)
}

/// Parses a single zone-file line into an optional `(domain_key, record)` pair.
///
/// Returns `Ok(None)` for a recognised-but-unsupported record type, and `Err`
/// for a malformed line.
fn parse_line(line: &str) -> Result<Option<(String, DnsRecord)>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        bail!("expected at least 4 fields (domain ttl type data)");
    }

    // DNS names are case-insensitive, so normalize the key to lowercase.
    let domain = strip_trailing_dot(&parts[0].to_lowercase());
    let ttl = parts[1]
        .parse::<u32>()
        .with_context(|| format!("invalid TTL `{}`", parts[1]))?;
    let record_type = parts[2];
    let data = parts[3..].join(" ");

    let record = match record_type {
        "A" => DnsRecord::A {
            domain: domain.clone(),
            addr: data.parse().context("invalid IPv4 address for A record")?,
            ttl,
        },
        "AAAA" => DnsRecord::AAAA {
            domain: domain.clone(),
            addr: data.parse().context("invalid IPv6 address for AAAA record")?,
            ttl,
        },
        "CNAME" => DnsRecord::CNAME {
            domain: domain.clone(),
            alias: strip_trailing_dot(&data),
            ttl,
        },
        "NS" => DnsRecord::NS {
            domain: domain.clone(),
            nameserver: strip_trailing_dot(&data),
            ttl,
        },
        "MX" => {
            // MX data is "<preference> <exchange>".
            if parts.len() < 5 {
                bail!("MX record requires a preference and an exchange");
            }
            let preference = parts[3]
                .parse::<u16>()
                .context("invalid preference for MX record")?;
            DnsRecord::MX {
                domain: domain.clone(),
                preference,
                exchange: strip_trailing_dot(parts[4]),
                ttl,
            }
        }
        "TXT" => DnsRecord::TXT {
            domain: domain.clone(),
            // Strip optional surrounding double quotes from the text value.
            text: data.trim_matches('"').to_string(),
            ttl,
        },
        "PTR" => DnsRecord::PTR {
            domain: domain.clone(),
            ptrdname: strip_trailing_dot(&data),
            ttl,
        },
        "SRV" => {
            // SRV data is "<priority> <weight> <port> <target>".
            if parts.len() < 7 {
                bail!("SRV record requires priority, weight, port and target");
            }
            DnsRecord::SRV {
                domain: domain.clone(),
                priority: parts[3].parse().context("invalid SRV priority")?,
                weight: parts[4].parse().context("invalid SRV weight")?,
                port: parts[5].parse().context("invalid SRV port")?,
                target: strip_trailing_dot(parts[6]),
                ttl,
            }
        }
        "CAA" => {
            // CAA data is "<flags> <tag> <value>".
            if parts.len() < 6 {
                bail!("CAA record requires flags, tag and value");
            }
            DnsRecord::CAA {
                domain: domain.clone(),
                flags: parts[3].parse().context("invalid CAA flags")?,
                tag: parts[4].to_string(),
                value: parts[5..].join(" ").trim_matches('"').to_string(),
                ttl,
            }
        }
        "SOA" => {
            // SOA data is "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>".
            if parts.len() < 10 {
                bail!("SOA record requires 7 fields (mname rname serial refresh retry expire minimum)");
            }
            DnsRecord::SOA {
                domain: domain.clone(),
                mname: strip_trailing_dot(parts[3]),
                rname: strip_trailing_dot(parts[4]),
                serial: parts[5].parse().context("invalid SOA serial")?,
                refresh: parts[6].parse().context("invalid SOA refresh")?,
                retry: parts[7].parse().context("invalid SOA retry")?,
                expire: parts[8].parse().context("invalid SOA expire")?,
                minimum: parts[9].parse().context("invalid SOA minimum")?,
                ttl,
            }
        }
        _ => return Ok(None),
    };

    Ok(Some((domain, record)))
}

/// Removes a single trailing dot from a domain name, if present
/// (e.g. `example.com.` -> `example.com`).
fn strip_trailing_dot(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_string()
}
