use crate::config::Zone;
use crate::dns::encoder::DnsPacketEncoder;
use crate::dns::header::DnsHeader;
use crate::dns::question::DnsQuestion;
use crate::dns::record::DnsRecord;
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

/// `DnsPacket` represents a DNS packet, including the header, questions, and resource records.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// The DNS header.
    pub header: DnsHeader,
    /// A list of questions in the packet.
    pub questions: Vec<DnsQuestion>,
    /// A list of answer records.
    pub answers: Vec<DnsRecord>,
    /// A list of authority records.
    pub authorities: Vec<DnsRecord>,
    /// A list of additional records.
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Creates a new `DnsPacket` from a byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            bail!("Buffer too small for DNS header");
        }

        let header = DnsHeader {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            questions: u16::from_be_bytes([buf[4], buf[5]]),
            answers: u16::from_be_bytes([buf[6], buf[7]]),
            authorities: u16::from_be_bytes([buf[8], buf[9]]),
            additionals: u16::from_be_bytes([buf[10], buf[11]]),
        };

        let mut offset = 12;

        let mut questions = Vec::new();
        for _ in 0..header.questions {
            let (qname, new_offset) = Self::parse_qname(buf, offset)?;
            offset = new_offset;

            if offset + 4 > buf.len() {
                bail!("Buffer too small for question");
            }
            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::new();
        for _ in 0..header.answers {
            let (record, new_offset) = Self::parse_record(buf, offset)?;
            answers.push(record);
            offset = new_offset;
        }

        // Note: Authority and Additional records are not parsed for simplicity.

        Ok(DnsPacket {
            header,
            questions,
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    /// Parses a single resource record from the buffer.
    fn parse_record(buf: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
        let (domain, mut new_offset) = Self::parse_qname(buf, offset)?;

        if new_offset + 10 > buf.len() {
            bail!("Buffer too small for record header");
        }

        let record_type = u16::from_be_bytes([buf[new_offset], buf[new_offset + 1]]);
        let ttl = u32::from_be_bytes([
            buf[new_offset + 4],
            buf[new_offset + 5],
            buf[new_offset + 6],
            buf[new_offset + 7],
        ]);
        let data_len = u16::from_be_bytes([buf[new_offset + 8], buf[new_offset + 9]]) as usize;
        new_offset += 10;

        if new_offset + data_len > buf.len() {
            bail!("Buffer overflow reading record data");
        }

        let record_data_start = new_offset;
        let record = match record_type {
            DnsRecord::TYPE_A => {
                if data_len != 4 {
                    bail!("Invalid A record data length");
                }
                let addr = Ipv4Addr::new(
                    buf[record_data_start],
                    buf[record_data_start + 1],
                    buf[record_data_start + 2],
                    buf[record_data_start + 3],
                );
                DnsRecord::A { domain, addr, ttl }
            }
            DnsRecord::TYPE_AAAA => {
                if data_len != 16 {
                    bail!("Invalid AAAA record data length");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[record_data_start..record_data_start + 16]);
                DnsRecord::AAAA {
                    domain,
                    addr: Ipv6Addr::from(octets),
                    ttl,
                }
            }
            DnsRecord::TYPE_CNAME => {
                let (alias, _) = Self::parse_qname(buf, record_data_start)?;
                DnsRecord::CNAME { domain, alias, ttl }
            }
            DnsRecord::TYPE_MX => {
                if data_len < 3 {
                    bail!("Invalid MX record data length");
                }
                let preference =
                    u16::from_be_bytes([buf[record_data_start], buf[record_data_start + 1]]);
                let (exchange, _) = Self::parse_qname(buf, record_data_start + 2)?;
                DnsRecord::MX {
                    domain,
                    preference,
                    exchange,
                    ttl,
                }
            }
            DnsRecord::TYPE_TXT => {
                let text = Self::parse_character_strings(
                    &buf[record_data_start..record_data_start + data_len],
                )?;
                DnsRecord::TXT { domain, text, ttl }
            }
            DnsRecord::TYPE_NS => {
                let (nameserver, _) = Self::parse_qname(buf, record_data_start)?;
                DnsRecord::NS {
                    domain,
                    nameserver,
                    ttl,
                }
            }
            DnsRecord::TYPE_SOA => {
                let (mname, after_mname) = Self::parse_qname(buf, record_data_start)?;
                let (rname, after_rname) = Self::parse_qname(buf, after_mname)?;
                if after_rname + 20 > buf.len() {
                    bail!("Buffer too small for SOA record");
                }
                let read_u32 = |p: usize| {
                    u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]])
                };
                DnsRecord::SOA {
                    domain,
                    mname,
                    rname,
                    serial: read_u32(after_rname),
                    refresh: read_u32(after_rname + 4),
                    retry: read_u32(after_rname + 8),
                    expire: read_u32(after_rname + 12),
                    minimum: read_u32(after_rname + 16),
                    ttl,
                }
            }
            _ => bail!("Unsupported record type: {}", record_type),
        };

        new_offset += data_len;
        Ok((record, new_offset))
    }

    /// Parses TXT rdata, which is a sequence of length-prefixed character
    /// strings, into a single concatenated `String`.
    fn parse_character_strings(data: &[u8]) -> Result<String> {
        let mut text = String::new();
        let mut i = 0;
        while i < data.len() {
            let len = data[i] as usize;
            i += 1;
            if i + len > data.len() {
                bail!("Buffer overflow reading TXT character-string");
            }
            text.push_str(&String::from_utf8_lossy(&data[i..i + len]));
            i += len;
        }
        Ok(text)
    }

    /// The maximum number of compression-pointer jumps we will follow before
    /// giving up. A malicious packet can chain pointers into a cycle (e.g. a
    /// pointer that targets itself), which would otherwise loop forever and pin
    /// a worker at 100% CPU. RFC 1035 caps a name at 255 bytes, so any
    /// legitimate name needs far fewer jumps than this bound.
    const MAX_POINTER_JUMPS: usize = 64;

    /// Parses a domain name from the buffer, supporting name compression.
    fn parse_qname(buf: &[u8], offset: usize) -> Result<(String, usize)> {
        let mut qname = String::new();
        let mut current = offset;
        let mut jumped = false;
        let mut end_offset = 0;
        let mut jumps = 0;

        loop {
            if current >= buf.len() {
                bail!("Buffer overflow while parsing qname label length");
            }
            let len = buf[current] as usize;

            if (len & 0b1100_0000) != 0 {
                if current + 1 >= buf.len() {
                    bail!("Buffer overflow while parsing pointer");
                }
                jumps += 1;
                if jumps > Self::MAX_POINTER_JUMPS {
                    bail!("Too many compression pointers (possible pointer loop)");
                }
                if !jumped {
                    end_offset = current + 2;
                    jumped = true;
                }
                let pointer_offset =
                    u16::from_be_bytes([buf[current] & 0x3F, buf[current + 1]]) as usize;
                current = pointer_offset;
                continue;
            }

            if len == 0 {
                if !jumped {
                    end_offset = current + 1;
                }
                break;
            }
            current += 1;
            if current + len > buf.len() {
                bail!("Buffer overflow while parsing qname label");
            }
            qname.push_str(&String::from_utf8_lossy(&buf[current..current + len]));
            qname.push('.');
            current += len;
        }

        if qname.ends_with('.') {
            qname.pop();
        }

        Ok((qname, end_offset))
    }

    /// The maximum size of a DNS message sent over UDP without EDNS (RFC 1035).
    pub const MAX_UDP_SIZE: usize = 512;

    /// Converts the `DnsPacket` to a byte vector using the `DnsPacketEncoder`.
    pub fn to_bytes(&self) -> Vec<u8> {
        DnsPacketEncoder::to_bytes(self)
    }

    /// Encodes the packet for transmission over UDP, enforcing the 512-byte
    /// limit. If the full message would exceed the limit, the answer section is
    /// dropped and the TC (truncation) bit is set so the client knows to retry
    /// over TCP.
    pub fn to_udp_bytes(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        if bytes.len() <= Self::MAX_UDP_SIZE {
            return bytes;
        }

        let truncated = DnsPacket {
            header: DnsHeader {
                flags: self.header.flags | 0x0200, // TC bit
                answers: 0,
                authorities: 0,
                additionals: 0,
                ..self.header
            },
            questions: self.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        truncated.to_bytes()
    }

    /// The maximum number of CNAME records followed when resolving a query,
    /// guarding against accidental or malicious CNAME loops.
    const MAX_CNAME_CHAIN: usize = 16;

    /// Builds a response packet for the current query.
    ///
    /// Resolution honours the question type, supports `*` wildcard records, and
    /// follows CNAME chains within the zone (appending each CNAME and the final
    /// target's records). The AA bit is set when the server is authoritative for
    /// the name, and NXDOMAIN is returned when the original name does not exist.
    pub fn build_response(&self, zone: &Zone) -> DnsPacket {
        let mut answers = Vec::new();
        let mut authoritative = false;
        let mut rcode = 0u16; // NOERROR

        if let Some(question) = self.questions.first() {
            let qtype = question.qtype;
            // DNS names are case-insensitive, so match against a normalized key.
            let mut name = question.qname.to_lowercase();
            let mut seen = std::collections::HashSet::new();

            for _ in 0..Self::MAX_CNAME_CHAIN {
                if !seen.insert(name.clone()) {
                    break; // CNAME loop detected
                }

                let Some(records) = Self::lookup(zone, &name) else {
                    // Original name missing -> NXDOMAIN; a dangling CNAME target
                    // simply ends the chain with what we have so far.
                    if answers.is_empty() {
                        rcode = 3; // NXDOMAIN
                    }
                    break;
                };
                authoritative = true;

                // Direct records of the requested type answer the query.
                let direct: Vec<&DnsRecord> =
                    records.iter().filter(|r| r.record_type() == qtype).collect();
                if !direct.is_empty() {
                    for r in direct {
                        answers.push(r.with_domain(name.clone()));
                    }
                    break;
                }

                // Otherwise, follow a CNAME if present (unless CNAME was asked for).
                if let Some(cname) = records
                    .iter()
                    .find(|r| r.record_type() == DnsRecord::TYPE_CNAME)
                {
                    answers.push(cname.with_domain(name.clone()));
                    if let DnsRecord::CNAME { alias, .. } = cname {
                        name = alias.to_lowercase();
                        continue;
                    }
                }

                break; // name exists but no matching type and no CNAME -> NODATA
            }
        }

        // QR=1 (response). Preserve the client's RD bit; RA stays 0 because this
        // server does not perform recursion.
        let mut flags = 0x8000 | (self.header.flags & 0x0100) | rcode;
        if authoritative {
            flags |= 0x0400; // AA
        }

        DnsPacket {
            header: DnsHeader {
                id: self.header.id,
                flags,
                questions: self.questions.len() as u16,
                answers: answers.len() as u16,
                authorities: 0,
                additionals: 0,
            },
            questions: self.questions.clone(),
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Looks up a name in the zone, falling back to `*` wildcard records.
    ///
    /// An exact match wins; otherwise each parent suffix is tried as
    /// `*.<suffix>` from most to least specific (RFC 4592 style).
    fn lookup<'a>(zone: &'a Zone, name: &str) -> Option<&'a Vec<DnsRecord>> {
        if let Some(records) = zone.get(name) {
            return Some(records);
        }
        let mut remainder = name;
        while let Some(pos) = remainder.find('.') {
            remainder = &remainder[pos + 1..];
            if let Some(records) = zone.get(&format!("*.{remainder}")) {
                return Some(records);
            }
        }
        None
    }
}