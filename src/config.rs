use crate::dns::record::DnsRecord;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use tracing::warn;

/// A `Zone` represents a collection of DNS records, keyed by domain name.
pub type Zone = HashMap<String, Vec<DnsRecord>>;

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
