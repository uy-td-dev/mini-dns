use crate::config::Zone;
use crate::dns::encoder::DnsPacketEncoder;
use crate::dns::header::DnsHeader;
use crate::dns::question::DnsQuestion;
use crate::dns::record::DnsRecord;
use anyhow::{bail, Result};
use std::net::Ipv4Addr;

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
            1 => { // A Record
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
            5 => { // CNAME Record
                let (alias, _) = Self::parse_qname(buf, record_data_start)?;
                DnsRecord::CNAME { domain, alias, ttl }
            }
            _ => bail!("Unsupported record type: {}", record_type),
        };

        new_offset += data_len;
        Ok((record, new_offset))
    }

    /// Parses a domain name from the buffer, supporting name compression.
    fn parse_qname(buf: &[u8], offset: usize) -> Result<(String, usize)> {
        let mut qname = String::new();
        let mut current = offset;
        let mut jumped = false;
        let mut end_offset = 0;

        loop {
            if current >= buf.len() {
                bail!("Buffer overflow while parsing qname label length");
            }
            let len = buf[current] as usize;

            if (len & 0b1100_0000) != 0 {
                if current + 1 >= buf.len() {
                    bail!("Buffer overflow while parsing pointer");
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

    /// Converts the `DnsPacket` to a byte vector using the `DnsPacketEncoder`.
    pub fn to_bytes(&self) -> Vec<u8> {
        DnsPacketEncoder::to_bytes(self)
    }

    /// Builds a response packet for the current query.
    pub fn build_response(&self, zone: &Zone) -> DnsPacket {
        let mut answers = Vec::new();
        if let Some(question) = self.questions.first() {
            if let Some(records) = zone.get(&question.qname) {
                answers.extend(records.clone());
            }
        }

        DnsPacket {
            header: DnsHeader {
                id: self.header.id,
                flags: 0x8180, // Response, recursion available, no error
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
}