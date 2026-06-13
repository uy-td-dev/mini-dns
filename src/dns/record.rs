use std::net::{Ipv4Addr, Ipv6Addr};

/// `DnsRecord` represents a DNS resource record.
///
/// This enum defines the types of DNS records supported by the server.
#[derive(Debug, Clone)]
pub enum DnsRecord {
    /// An A record, which maps a domain name to an IPv4 address.
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    /// An AAAA record, which maps a domain name to an IPv6 address.
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    /// A CNAME record, which maps a domain name to an alias.
    CNAME {
        domain: String,
        alias: String,
        ttl: u32,
    },
    /// An MX record, which names a mail exchange for the domain along with a
    /// preference (lower is preferred).
    MX {
        domain: String,
        preference: u16,
        exchange: String,
        ttl: u32,
    },
    /// A TXT record, which holds arbitrary descriptive text.
    TXT {
        domain: String,
        text: String,
        ttl: u32,
    },
    /// An NS record, which delegates a zone to an authoritative name server.
    NS {
        domain: String,
        nameserver: String,
        ttl: u32,
    },
    /// An SOA record, which holds administrative information about a zone.
    SOA {
        domain: String,
        /// Primary name server for the zone.
        mname: String,
        /// Mailbox of the zone administrator.
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32,
    },
    /// An SRV record, locating the host/port for a service.
    SRV {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
        ttl: u32,
    },
    /// A PTR record, mapping a name (typically reverse-DNS) to another name.
    PTR {
        domain: String,
        ptrdname: String,
        ttl: u32,
    },
    /// A CAA record, which authorizes certificate issuance for the domain.
    CAA {
        domain: String,
        flags: u8,
        tag: String,
        value: String,
        ttl: u32,
    },
    /// An EDNS(0) OPT pseudo-record (RFC 6891). Carries the sender's advertised
    /// UDP payload size rather than zone data; never stored in a zone.
    OPT {
        udp_size: u16,
    },
}

impl DnsRecord {
    /// The numeric type code for an A record.
    pub const TYPE_A: u16 = 1;
    /// The numeric type code for an NS record.
    pub const TYPE_NS: u16 = 2;
    /// The numeric type code for a CNAME record.
    pub const TYPE_CNAME: u16 = 5;
    /// The numeric type code for an SOA record.
    pub const TYPE_SOA: u16 = 6;
    /// The numeric type code for an MX record.
    pub const TYPE_MX: u16 = 15;
    /// The numeric type code for a TXT record.
    pub const TYPE_TXT: u16 = 16;
    /// The numeric type code for an AAAA record.
    pub const TYPE_AAAA: u16 = 28;
    /// The numeric type code for a PTR record.
    pub const TYPE_PTR: u16 = 12;
    /// The numeric type code for an SRV record.
    pub const TYPE_SRV: u16 = 33;
    /// The numeric type code for an OPT (EDNS) pseudo-record.
    pub const TYPE_OPT: u16 = 41;
    /// The numeric type code for a CAA record.
    pub const TYPE_CAA: u16 = 257;

    /// Returns the DNS type code for this record.
    pub fn record_type(&self) -> u16 {
        match self {
            DnsRecord::A { .. } => Self::TYPE_A,
            DnsRecord::AAAA { .. } => Self::TYPE_AAAA,
            DnsRecord::CNAME { .. } => Self::TYPE_CNAME,
            DnsRecord::MX { .. } => Self::TYPE_MX,
            DnsRecord::TXT { .. } => Self::TYPE_TXT,
            DnsRecord::NS { .. } => Self::TYPE_NS,
            DnsRecord::SOA { .. } => Self::TYPE_SOA,
            DnsRecord::SRV { .. } => Self::TYPE_SRV,
            DnsRecord::PTR { .. } => Self::TYPE_PTR,
            DnsRecord::CAA { .. } => Self::TYPE_CAA,
            DnsRecord::OPT { .. } => Self::TYPE_OPT,
        }
    }

    /// Returns the TTL (time-to-live, in seconds) of this record.
    pub fn ttl(&self) -> u32 {
        match self {
            DnsRecord::A { ttl, .. }
            | DnsRecord::AAAA { ttl, .. }
            | DnsRecord::CNAME { ttl, .. }
            | DnsRecord::MX { ttl, .. }
            | DnsRecord::TXT { ttl, .. }
            | DnsRecord::NS { ttl, .. }
            | DnsRecord::SOA { ttl, .. }
            | DnsRecord::SRV { ttl, .. }
            | DnsRecord::PTR { ttl, .. }
            | DnsRecord::CAA { ttl, .. } => *ttl,
            DnsRecord::OPT { .. } => 0,
        }
    }

    /// Returns the domain name (owner) this record belongs to (empty for OPT).
    pub fn domain(&self) -> &str {
        match self {
            DnsRecord::A { domain, .. }
            | DnsRecord::AAAA { domain, .. }
            | DnsRecord::CNAME { domain, .. }
            | DnsRecord::MX { domain, .. }
            | DnsRecord::TXT { domain, .. }
            | DnsRecord::NS { domain, .. }
            | DnsRecord::SOA { domain, .. }
            | DnsRecord::SRV { domain, .. }
            | DnsRecord::PTR { domain, .. }
            | DnsRecord::CAA { domain, .. } => domain,
            DnsRecord::OPT { .. } => "",
        }
    }

    /// Returns a clone of this record with its owner name replaced.
    ///
    /// Used for wildcard synthesis, where a record stored under `*.example.com`
    /// must be returned with the actual queried name as its owner. OPT has no
    /// owner, so it is returned unchanged.
    pub fn with_domain(&self, domain: String) -> DnsRecord {
        let mut record = self.clone();
        match &mut record {
            DnsRecord::A { domain: d, .. }
            | DnsRecord::AAAA { domain: d, .. }
            | DnsRecord::CNAME { domain: d, .. }
            | DnsRecord::MX { domain: d, .. }
            | DnsRecord::TXT { domain: d, .. }
            | DnsRecord::NS { domain: d, .. }
            | DnsRecord::SOA { domain: d, .. }
            | DnsRecord::SRV { domain: d, .. }
            | DnsRecord::PTR { domain: d, .. }
            | DnsRecord::CAA { domain: d, .. } => *d = domain,
            DnsRecord::OPT { .. } => {}
        }
        record
    }
}
