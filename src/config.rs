use crate::dns::record::DnsRecord;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;

pub type Zone = HashMap<String, Vec<DnsRecord<'static>>>;

pub fn load_zone_file(path: &str) -> Result<Zone> {
    let content = fs::read_to_string(path).context("Failed to read zone file")?;
    let mut zone = Zone::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let domain = parts[0].to_string();
        let ttl = parts[1].parse::<u32>()?;
        let kind = parts[2];
        let data = parts[3];

        let record = match kind {
            "A" => DnsRecord::A {
                domain: Box::leak(domain.clone().into_boxed_str()),
                addr: data.parse().context("Invalid IP")?,
                ttl,
            },
            "CNAME" => DnsRecord::CNAME {
                domain: Box::leak(domain.clone().into_boxed_str()),
                alias: Box::leak(data.to_string().into_boxed_str()),
                ttl,
            },
            _ => continue,
        };
        zone.entry(domain).or_default().push(record);
    }

    Ok(zone)
}