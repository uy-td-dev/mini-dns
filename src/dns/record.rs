use std::net::Ipv4Addr;

/// `DnsRecord` represents a DNS resource record.
///
/// This enum defines the types of DNS records supported by the server,
/// such as A records for IPv4 addresses and CNAME records for aliases.
#[derive(Debug, Clone)]
pub enum DnsRecord {
    /// An A record, which maps a domain name to an IPv4 address.
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    /// A CNAME record, which maps a domain name to an alias.
    CNAME {
        domain: String,
        alias: String,
        ttl: u32,
    },
}