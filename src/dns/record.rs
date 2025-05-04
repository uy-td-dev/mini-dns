use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum DnsRecord<'a> {
    A {
        domain: &'a str,
        addr: Ipv4Addr,
        ttl: u32,
    },
    CNAME {
        domain: &'a str,
        alias: &'a str,
        ttl: u32,
    },
}