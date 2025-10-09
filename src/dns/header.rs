/// `DnsHeader` represents the header of a DNS packet.
///
/// The header contains metadata about the DNS query or response, such as the
/// transaction ID, flags, and the number of questions and records.
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    /// A 16-bit identifier assigned by the program that generates any kind of query.
    pub id: u16,
    /// A 16-bit field that specifies control flags.
    pub flags: u16,
    /// The number of entries in the question section.
    pub questions: u16,
    /// The number of resource records in the answer section.
    pub answers: u16,
    /// The number of name server resource records in the authority records section.
    pub authorities: u16,
    /// The number of resource records in the additional records section.
    pub additionals: u16,
}