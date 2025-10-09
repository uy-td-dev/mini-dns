//! `encoder` module provides functionality for encoding DNS packets into byte format.
use crate::dns::packet::DnsPacket;
use crate::dns::record::DnsRecord;
use std::vec::Vec;

/// `DnsPacketEncoder` is responsible for converting a `DnsPacket` into a byte vector.
pub struct DnsPacketEncoder;

impl DnsPacketEncoder {
    /// Encodes a `DnsPacket` into a byte vector.
    pub fn to_bytes(packet: &DnsPacket) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet.header.id.to_be_bytes());
        buf.extend_from_slice(&packet.header.flags.to_be_bytes());
        buf.extend_from_slice(&(packet.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(packet.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(packet.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(packet.additionals.len() as u16).to_be_bytes());

        for question in &packet.questions {
            Self::encode_qname(&mut buf, &question.qname);
            buf.extend_from_slice(&question.qtype.to_be_bytes());
            buf.extend_from_slice(&question.qclass.to_be_bytes());
        }

        for answer in &packet.answers {
            match answer {
                DnsRecord::A { domain, addr, ttl } => {
                    Self::encode_qname(&mut buf, domain);
                    buf.extend_from_slice(&1u16.to_be_bytes()); // Type A
                    buf.extend_from_slice(&1u16.to_be_bytes()); // Class IN
                    buf.extend_from_slice(&ttl.to_be_bytes());
                    buf.extend_from_slice(&4u16.to_be_bytes()); // Data length
                    buf.extend_from_slice(&addr.octets());
                }
                DnsRecord::CNAME { domain, alias, ttl } => {
                    Self::encode_qname(&mut buf, domain);
                    buf.extend_from_slice(&5u16.to_be_bytes()); // Type CNAME
                    buf.extend_from_slice(&1u16.to_be_bytes()); // Class IN
                    buf.extend_from_slice(&ttl.to_be_bytes());
                    let mut alias_buf = Vec::new();
                    Self::encode_qname(&mut alias_buf, alias);
                    buf.extend_from_slice(&(alias_buf.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&alias_buf);
                }
            }
        }
        buf
    }

    /// Encodes a domain name into the buffer in the label format.
    fn encode_qname(buf: &mut Vec<u8>, qname: &str) {
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }
}