//! IP-based access control lists for zone transfer (AXFR) authorization.
//!
//! A list of allowed CIDR ranges (or single IPs); `is_allowed` checks whether
//! a client IP falls within any of them. Empty list = deny all.

use anyhow::{Context, Result};
use std::net::IpAddr;

/// A CIDR network entry in the ACL.
#[derive(Debug, Clone)]
enum Cidr {
    V4 { addr: [u8; 4], prefix: u8 },
    V6 { addr: [u8; 16], prefix: u8 },
}

/// An ACL: a list of CIDR ranges that are permitted.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    entries: Vec<Cidr>,
}

impl Acl {
    /// Parses a list of CIDR strings (e.g. `["10.0.0.0/8", "192.168.1.5"]`).
    /// A bare IP is treated as `/32` (v4) or `/128` (v6).
    pub fn parse(specs: &[String]) -> Result<Self> {
        let mut entries = Vec::with_capacity(specs.len());
        for s in specs {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            entries.push(parse_cidr(s).with_context(|| format!("parsing ACL entry `{s}`"))?);
        }
        Ok(Acl { entries })
    }

    /// An ACL that denies everything.
    pub fn deny_all() -> Self {
        Acl { entries: Vec::new() }
    }

    /// Whether `ip` is permitted by this ACL.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        for cidr in &self.entries {
            if match (cidr, ip) {
                (Cidr::V4 { addr, prefix }, IpAddr::V4(v4)) => {
                    matches_v4(addr, *prefix, &v4.octets())
                }
                (Cidr::V6 { addr, prefix }, IpAddr::V6(v6)) => {
                    matches_v6(addr, *prefix, &v6.octets())
                }
                _ => false, // v4 entry vs v6 client or vice versa
            } {
                return true;
            }
        }
        false
    }
}

fn parse_cidr(s: &str) -> Result<Cidr> {
    if let Some((addr_part, prefix_part)) = s.split_once('/') {
        let prefix: u8 = prefix_part.parse().context("invalid prefix length")?;
        if let Ok(v4) = addr_part.parse::<std::net::Ipv4Addr>() {
            if prefix > 32 {
                anyhow::bail!("IPv4 prefix length {prefix} > 32");
            }
            return Ok(Cidr::V4 {
                addr: v4.octets(),
                prefix,
            });
        }
        if let Ok(v6) = addr_part.parse::<std::net::Ipv6Addr>() {
            if prefix > 128 {
                anyhow::bail!("IPv6 prefix length {prefix} > 128");
            }
            return Ok(Cidr::V6 {
                addr: v6.octets(),
                prefix,
            });
        }
        anyhow::bail!("not a valid IP address: {addr_part}");
    }
    // No prefix -> single host (/32 or /128).
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        return Ok(Cidr::V4 {
            addr: v4.octets(),
            prefix: 32,
        });
    }
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        return Ok(Cidr::V6 {
            addr: v6.octets(),
            prefix: 128,
        });
    }
    anyhow::bail!("not a valid CIDR or IP: {s}");
}

fn matches_v4(net: &[u8; 4], prefix: u8, ip: &[u8; 4]) -> bool {
    let bits = prefix as usize;
    let full_bytes = bits / 8;
    let rem = bits % 8;
    if ip[..full_bytes] != net[..full_bytes] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (ip[full_bytes] & mask) == (net[full_bytes] & mask)
}

fn matches_v6(net: &[u8; 16], prefix: u8, ip: &[u8; 16]) -> bool {
    let bits = prefix as usize;
    let full_bytes = bits / 8;
    let rem = bits % 8;
    if ip[..full_bytes] != net[..full_bytes] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (ip[full_bytes] & mask) == (net[full_bytes] & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_cidr_match() {
        let acl = Acl::parse(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(acl.is_allowed(&"10.1.2.3".parse().unwrap()));
        assert!(acl.is_allowed(&"10.255.255.255".parse().unwrap()));
        assert!(!acl.is_allowed(&"11.0.0.0".parse().unwrap()));
    }

    #[test]
    fn single_host_match() {
        let acl = Acl::parse(&["192.168.1.5".to_string()]).unwrap();
        assert!(acl.is_allowed(&"192.168.1.5".parse().unwrap()));
        assert!(!acl.is_allowed(&"192.168.1.6".parse().unwrap()));
    }

    #[test]
    fn deny_all_when_empty() {
        let acl = Acl::deny_all();
        assert!(!acl.is_allowed(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn v6_cidr_match() {
        let acl = Acl::parse(&["2001:db8::/32".to_string()]).unwrap();
        assert!(acl.is_allowed(&"2001:db8::1".parse().unwrap()));
        assert!(!acl.is_allowed(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn mixed_v4_v6_entries() {
        let acl = Acl::parse(&[
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
        ])
        .unwrap();
        assert!(acl.is_allowed(&"10.1.1.1".parse().unwrap()));
        assert!(acl.is_allowed(&"2001:db8::1".parse().unwrap()));
        assert!(!acl.is_allowed(&"8.8.8.8".parse().unwrap()));
    }
}
