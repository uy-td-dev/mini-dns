use crate::dns::record::DnsRecord;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;

/// A `Zone` represents a collection of DNS records for a particular domain.
pub type Zone = HashMap<String, Vec<DnsRecord>>;

/// `load_zone_file` parses a zone file and loads the DNS records into a `Zone`.
///
/// The zone file is expected to have a simple format where each line represents a DNS record:
/// `domain ttl type data`
///
/// For example:
/// `example.com. 3600 A 192.0.2.1`
/// `www.example.com. 3600 CNAME example.com.`
///
pub fn load_zone_file(path: &str) -> Result<Zone> {
    let content = fs::read_to_string(path).context("Failed to read zone file")?;
    let mut zone = Zone::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let mut domain = parts[0].to_string();
        if domain.ends_with('.') {
            domain.pop();
        }
        let ttl = parts[1].parse::<u32>()?;
        let record_type = parts[2];
        let data = parts[3..].join(" ");

        let record = match record_type {
            "A" => DnsRecord::A {
                domain: domain.clone(),
                addr: data.parse().context("Invalid IP address for A record")?,
                ttl,
            },
            "CNAME" => {
                let mut alias = data.to_string();
                if alias.ends_with('.') {
                    alias.pop();
                }
                DnsRecord::CNAME {
                    domain: domain.clone(),
                    alias,
                    ttl,
                }
            }
            _ => continue,
        };

        zone.entry(domain).or_default().push(record);
    }

    Ok(zone)
}