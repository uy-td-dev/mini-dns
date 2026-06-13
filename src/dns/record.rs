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
            | DnsRecord::SOA { ttl, .. } => *ttl,
        }
    }

    /// Returns the domain name (owner) this record belongs to.
    pub fn domain(&self) -> &str {
        match self {
            DnsRecord::A { domain, .. }
            | DnsRecord::AAAA { domain, .. }
            | DnsRecord::CNAME { domain, .. }
            | DnsRecord::MX { domain, .. }
            | DnsRecord::TXT { domain, .. }
            | DnsRecord::NS { domain, .. }
            | DnsRecord::SOA { domain, .. } => domain,
        }
    }

    /// Returns a clone of this record with its owner name replaced.
    ///
    /// Used for wildcard synthesis, where a record stored under `*.example.com`
    /// must be returned with the actual queried name as its owner.
    pub fn with_domain(&self, domain: String) -> DnsRecord {
        let mut record = self.clone();
        match &mut record {
            DnsRecord::A { domain: d, .. }
            | DnsRecord::AAAA { domain: d, .. }
            | DnsRecord::CNAME { domain: d, .. }
            | DnsRecord::MX { domain: d, .. }
            | DnsRecord::TXT { domain: d, .. }
            | DnsRecord::NS { domain: d, .. }
            | DnsRecord::SOA { domain: d, .. } => *d = domain,
        }
        record
    }
}
