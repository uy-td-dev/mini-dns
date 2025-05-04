pub struct DnsQuestion<'a> {
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
}