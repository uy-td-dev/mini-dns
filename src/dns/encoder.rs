//! `encoder` module provides functionality for encoding DNS packets into byte format.
use crate::dns::packet::DnsPacket;
use crate::dns::record::DnsRecord;
use std::collections::HashMap;
use std::vec::Vec;

/// `DnsPacketEncoder` converts a `DnsPacket` into a byte vector.
///
/// It applies RFC 1035 name compression: the first time a (sub)domain is
/// written its offset is remembered, and later occurrences of the same suffix
/// are emitted as a 2-byte pointer instead of the full labels.
pub struct DnsPacketEncoder {
    buf: Vec<u8>,
    /// Maps a domain suffix (e.g. "www.example.com") to the offset where it was
    /// first written, so it can be referenced via a compression pointer.
    name_offsets: HashMap<String, u16>,
}

impl DnsPacketEncoder {
    /// Encodes a `DnsPacket` into a byte vector.
    pub fn to_bytes(packet: &DnsPacket) -> Vec<u8> {
        let mut encoder = DnsPacketEncoder {
            buf: Vec::new(),
            name_offsets: HashMap::new(),
        };
        encoder.encode(packet);
        encoder.buf
    }

    fn encode(&mut self, packet: &DnsPacket) {
        self.buf.extend_from_slice(&packet.header.id.to_be_bytes());
        self.buf.extend_from_slice(&packet.header.flags.to_be_bytes());
        self.buf
            .extend_from_slice(&(packet.questions.len() as u16).to_be_bytes());
        self.buf
            .extend_from_slice(&(packet.answers.len() as u16).to_be_bytes());
        self.buf
            .extend_from_slice(&(packet.authorities.len() as u16).to_be_bytes());
        self.buf
            .extend_from_slice(&(packet.additionals.len() as u16).to_be_bytes());

        for question in &packet.questions {
            self.encode_qname(&question.qname);
            self.buf.extend_from_slice(&question.qtype.to_be_bytes());
            self.buf.extend_from_slice(&question.qclass.to_be_bytes());
        }

        for answer in &packet.answers {
            self.encode_record(answer);
        }
        for record in &packet.authorities {
            self.encode_record(record);
        }
        for record in &packet.additionals {
            self.encode_record(record);
        }
    }

    /// Encodes a single resource record into the buffer.
    fn encode_record(&mut self, record: &DnsRecord) {
        match record {
            DnsRecord::A { domain, addr, ttl } => {
                self.encode_record_header(domain, DnsRecord::TYPE_A, *ttl);
                self.buf.extend_from_slice(&4u16.to_be_bytes()); // Data length
                self.buf.extend_from_slice(&addr.octets());
            }
            DnsRecord::AAAA { domain, addr, ttl } => {
                self.encode_record_header(domain, DnsRecord::TYPE_AAAA, *ttl);
                self.buf.extend_from_slice(&16u16.to_be_bytes()); // Data length
                self.buf.extend_from_slice(&addr.octets());
            }
            DnsRecord::CNAME { domain, alias, ttl } => {
                self.encode_record_header(domain, DnsRecord::TYPE_CNAME, *ttl);
                self.encode_rdata(|enc| enc.encode_qname(alias));
            }
            DnsRecord::MX {
                domain,
                preference,
                exchange,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_MX, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.extend_from_slice(&preference.to_be_bytes());
                    enc.encode_qname(exchange);
                });
            }
            DnsRecord::TXT { domain, text, ttl } => {
                self.encode_record_header(domain, DnsRecord::TYPE_TXT, *ttl);
                self.encode_rdata(|enc| enc.encode_character_strings(text));
            }
            DnsRecord::NS {
                domain,
                nameserver,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_NS, *ttl);
                self.encode_rdata(|enc| enc.encode_qname(nameserver));
            }
            DnsRecord::SOA {
                domain,
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_SOA, *ttl);
                self.encode_rdata(|enc| {
                    enc.encode_qname(mname);
                    enc.encode_qname(rname);
                    enc.buf.extend_from_slice(&serial.to_be_bytes());
                    enc.buf.extend_from_slice(&refresh.to_be_bytes());
                    enc.buf.extend_from_slice(&retry.to_be_bytes());
                    enc.buf.extend_from_slice(&expire.to_be_bytes());
                    enc.buf.extend_from_slice(&minimum.to_be_bytes());
                });
            }
            DnsRecord::SRV {
                domain,
                priority,
                weight,
                port,
                target,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_SRV, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.extend_from_slice(&priority.to_be_bytes());
                    enc.buf.extend_from_slice(&weight.to_be_bytes());
                    enc.buf.extend_from_slice(&port.to_be_bytes());
                    // RFC 2782: the SRV target must not be compressed.
                    enc.encode_name_uncompressed(target);
                });
            }
            DnsRecord::PTR {
                domain,
                ptrdname,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_PTR, *ttl);
                self.encode_rdata(|enc| enc.encode_qname(ptrdname));
            }
            DnsRecord::CAA {
                domain,
                flags,
                tag,
                value,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_CAA, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.push(*flags);
                    let tag_len = tag.len().min(255);
                    enc.buf.push(tag_len as u8);
                    enc.buf.extend_from_slice(&tag.as_bytes()[..tag_len]);
                    enc.buf.extend_from_slice(value.as_bytes());
                });
            }
            DnsRecord::OPT { udp_size } => {
                // OPT pseudo-record: root name, type OPT, UDP size in the class
                // field, extended-rcode/flags in the TTL field, empty rdata.
                self.buf.push(0); // root domain name
                self.buf.extend_from_slice(&DnsRecord::TYPE_OPT.to_be_bytes());
                self.buf.extend_from_slice(&udp_size.to_be_bytes());
                self.buf.extend_from_slice(&0u32.to_be_bytes());
                self.buf.extend_from_slice(&0u16.to_be_bytes());
            }
            DnsRecord::DNSKEY {
                domain,
                flags,
                protocol,
                algorithm,
                public_key,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_DNSKEY, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.extend_from_slice(&flags.to_be_bytes());
                    enc.buf.push(*protocol);
                    enc.buf.push(*algorithm);
                    enc.buf.extend_from_slice(public_key);
                });
            }
            DnsRecord::RRSIG {
                domain,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_RRSIG, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.extend_from_slice(&type_covered.to_be_bytes());
                    enc.buf.push(*algorithm);
                    enc.buf.push(*labels);
                    enc.buf.extend_from_slice(&original_ttl.to_be_bytes());
                    enc.buf.extend_from_slice(&signature_expiration.to_be_bytes());
                    enc.buf.extend_from_slice(&signature_inception.to_be_bytes());
                    enc.buf.extend_from_slice(&key_tag.to_be_bytes());
                    // RRSIG signer name is not compressed (RFC 4034 §3.2).
                    enc.encode_name_uncompressed(signer_name);
                    enc.buf.extend_from_slice(signature);
                });
            }
            DnsRecord::DS {
                domain,
                key_tag,
                algorithm,
                digest_type,
                digest,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_DS, *ttl);
                self.encode_rdata(|enc| {
                    enc.buf.extend_from_slice(&key_tag.to_be_bytes());
                    enc.buf.push(*algorithm);
                    enc.buf.push(*digest_type);
                    enc.buf.extend_from_slice(digest);
                });
            }
            DnsRecord::NSEC {
                domain,
                next_name,
                type_bitmap,
                ttl,
            } => {
                self.encode_record_header(domain, DnsRecord::TYPE_NSEC, *ttl);
                self.encode_rdata(|enc| {
                    // NSEC next name is not compressed (RFC 4034 §4.1.2).
                    enc.encode_name_uncompressed(next_name);
                    enc.buf.extend_from_slice(type_bitmap);
                });
            }
        }
    }

    /// Encodes a domain name in label format without using compression pointers.
    fn encode_name_uncompressed(&mut self, name: &str) {
        if name.is_empty() {
            self.buf.push(0);
            return;
        }
        for label in name.split('.') {
            let len = label.len().min(63);
            self.buf.push(len as u8);
            self.buf.extend_from_slice(&label.as_bytes()[..len]);
        }
        self.buf.push(0);
    }

    /// Writes the common record header (name, type, class IN, TTL).
    fn encode_record_header(&mut self, domain: &str, rtype: u16, ttl: u32) {
        self.encode_qname(domain);
        self.buf.extend_from_slice(&rtype.to_be_bytes());
        self.buf.extend_from_slice(&1u16.to_be_bytes()); // Class IN
        self.buf.extend_from_slice(&ttl.to_be_bytes());
    }

    /// Writes variable-length rdata produced by `write_body`, backfilling the
    /// 2-byte rdlength once the actual length is known (necessary because name
    /// compression makes the encoded size depend on prior content).
    fn encode_rdata(&mut self, write_body: impl FnOnce(&mut Self)) {
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_be_bytes());
        let rdata_start = self.buf.len();
        write_body(self);
        let rdlength = (self.buf.len() - rdata_start) as u16;
        self.buf[len_pos..len_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
    }

    /// Encodes text as one or more DNS character-strings (each a length byte
    /// followed by up to 255 bytes), splitting longer text across strings.
    fn encode_character_strings(&mut self, text: &str) {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            self.buf.push(0);
            return;
        }
        for chunk in bytes.chunks(255) {
            self.buf.push(chunk.len() as u8);
            self.buf.extend_from_slice(chunk);
        }
    }

    /// Encodes a domain name into the buffer in label format, using compression
    /// pointers for any suffix that has already been written.
    fn encode_qname(&mut self, qname: &str) {
        if qname.is_empty() {
            self.buf.push(0);
            return;
        }

        let labels: Vec<&str> = qname.split('.').collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            if let Some(&offset) = self.name_offsets.get(&suffix) {
                let pointer = 0xC000 | offset;
                self.buf.extend_from_slice(&pointer.to_be_bytes());
                return;
            }

            // Only positions addressable by a 14-bit pointer can be referenced.
            if self.buf.len() <= 0x3FFF {
                self.name_offsets.insert(suffix, self.buf.len() as u16);
            }

            let label = labels[i];
            // Labels are limited to 63 bytes; the two high bits are reserved for
            // pointers, so a longer label cannot be represented.
            let label_len = label.len().min(63);
            self.buf.push(label_len as u8);
            self.buf.extend_from_slice(&label.as_bytes()[..label_len]);
        }
        self.buf.push(0);
    }
}
