/// `DnsQuestion` represents a question in the question section of a DNS packet.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// The domain name being queried.
    pub qname: String,
    /// The type of the query (e.g., A, CNAME).
    pub qtype: u16,
    /// The class of the query, which is typically IN for internet addresses.
    pub qclass: u16,
}