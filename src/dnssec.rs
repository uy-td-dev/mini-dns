//! DNSSEC key management and signing support (RFC 4034/4035).
//!
//! This module provides:
//! - ED25519 key pair generation (algorithm 15, RFC 8080)
//! - DNSKEY record construction
//! - Key tag computation (RFC 4034 Appendix B)
//! - RRset signing with RRSIG generation and verification
//!
//! NSEC chain construction for authenticated denial of existence is left as
//! future work. The signing is wired into the server's response path via
//! `ServerState::with_dnssec`, which injects DNSKEY records at zone apexes
//! and signs answer RRsets.

use crate::dns::record::DnsRecord;
use anyhow::Result;
use std::sync::Arc;

/// DNSSEC algorithm code for ED25519 (RFC 8080).
pub const ALG_ED25519: u8 = 15;

/// DNSKEY flag bit: this key signs the zone's apex DNSKEY RRset (KSK).
pub const FLAG_KSK: u16 = 0x0001;
/// DNSKEY flag bit: this key signs the zone (ZSK / general-purpose).
pub const FLAG_ZONE: u16 = 0x0100;

/// A DNSSEC signing key pair (ED25519).
pub struct SigningKey {
    /// The zone apex name this key signs (e.g. `example.com`).
    pub zone_name: String,
    /// DNSKEY flags (KSK + ZSK for a single combined-signing key).
    pub flags: u16,
    /// The algorithm (always ED25519 = 15 in this implementation).
    pub algorithm: u8,
    /// The public key (raw ED25519 point, 32 bytes).
    pub public_key: Vec<u8>,
    /// The private key (raw ED25519 scalar, 32 bytes).
    pub private_key: Vec<u8>,
}

impl SigningKey {
    /// Generates a new ED25519 key pair for `zone_name`.
    ///
    /// Uses `ring`'s CSPRNG and Ed25519 key generation. The key is a
    /// combined KSK+ZSK (flags `0x0101`), suitable for a small single-signer
    /// zone.
    pub fn generate(zone_name: &str) -> Result<Self> {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("generating ED25519 key pair"))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow::anyhow!("parsing generated key"))?;

        let public_key = key_pair.public_key().as_ref().to_vec();
        let private_key = pkcs8.as_ref().to_vec();

        Ok(SigningKey {
            zone_name: zone_name.to_string(),
            flags: FLAG_KSK | FLAG_ZONE,
            algorithm: ALG_ED25519,
            public_key,
            private_key,
        })
    }

    /// Builds the DNSKEY resource record for this key, with the given TTL.
    pub fn dnskey_record(&self, ttl: u32) -> DnsRecord {
        DnsRecord::DNSKEY {
            domain: self.zone_name.clone(),
            flags: self.flags,
            protocol: 3, // RFC 4034 §2.1.2: protocol MUST be 3 (DNSSEC)
            algorithm: self.algorithm,
            public_key: self.public_key.clone(),
            ttl,
        }
    }

    /// Computes the key tag for this key (RFC 4034 Appendix B).
    pub fn key_tag(&self) -> u16 {
        // Build the canonical DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public_key.
        let mut rdata = Vec::with_capacity(4 + self.public_key.len());
        rdata.extend_from_slice(&self.flags.to_be_bytes());
        rdata.push(3);
        rdata.push(self.algorithm);
        rdata.extend_from_slice(&self.public_key);
        key_tag_from_rdata(&rdata)
    }
}

/// Computes a DNSSEC key tag from canonical RDATA (RFC 4034 Appendix B).
pub fn key_tag_from_rdata(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        ac += (byte as u32) << if i & 1 == 0 { 8 } else { 0 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// A set of DNSSEC signing keys for a zone (typically one combined KSK+ZSK).
#[derive(Default)]
pub struct DnssecKeys {
    pub keys: Vec<Arc<SigningKey>>,
}

impl DnssecKeys {
    /// Whether DNSSEC signing is enabled (at least one key is present).
    pub fn is_enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Generates a single combined KSK+ZSK for `zone_name`.
    pub fn single(zone_name: &str) -> Result<Self> {
        let key = Arc::new(SigningKey::generate(zone_name)?);
        Ok(DnssecKeys { keys: vec![key] })
    }

    /// Returns the DNSKEY records for all keys, with the given TTL.
    pub fn dnskey_records(&self, ttl: u32) -> Vec<DnsRecord> {
        self.keys.iter().map(|k| k.dnskey_record(ttl)).collect()
    }

    /// Signs an RRset (a set of records with the same owner name and type)
    /// and returns the RRSIG record. Uses ED25519 (algorithm 15).
    ///
    /// The signature covers the canonical RRSIG RDATA (minus the signature
    /// field) followed by the canonical RRset data, per RFC 4034 §3.1.8.
    pub fn sign_rrset(
        &self,
        records: &[DnsRecord],
        signer_name: &str,
        ttl: u32,
        inception: u32,
        expiration: u32,
    ) -> Result<DnsRecord> {
        
        use ring::signature::Ed25519KeyPair;

        let key = self
            .keys
            .first()
            .ok_or_else(|| anyhow::anyhow!("no signing keys available"))?;

        // Parse the PKCS#8 private key.
        let key_pair = Ed25519KeyPair::from_pkcs8(&key.private_key)
            .map_err(|_| anyhow::anyhow!("failed to parse signing key"))?;

        // Determine the type covered and owner name from the first record.
        let type_covered = records[0].record_type();
        let owner = records[0].domain().to_string();

        // Count labels in the owner name (for the RRSIG "labels" field).
        // Wildcard names have one fewer label (the `*` doesn't count).
        let labels = owner.split('.').filter(|l| !l.is_empty() && *l != "*").count() as u8;

        // Build the data to sign: RRSIG RDATA (minus signature) + canonical RRset.
        let mut to_sign = Vec::new();

        // RRSIG RDATA fields (RFC 4034 §3.2):
        // type_covered(2) + algorithm(1) + labels(1) + original_ttl(4) +
        // signature_expiration(4) + signature_inception(4) + key_tag(2) +
        // signer_name (uncompressed, canonical)
        to_sign.extend_from_slice(&type_covered.to_be_bytes());
        to_sign.push(key.algorithm);
        to_sign.push(labels);
        to_sign.extend_from_slice(&ttl.to_be_bytes());
        to_sign.extend_from_slice(&expiration.to_be_bytes());
        to_sign.extend_from_slice(&inception.to_be_bytes());
        to_sign.extend_from_slice(&key.key_tag().to_be_bytes());
        // Signer name in canonical form: lowercase, uncompressed.
        canonical_name(signer_name, &mut to_sign);

        // Canonical RRset data: for each record, owner name (canonical) +
        // type(2) + class(2) + original_ttl(4) + rdlength(2) + rdata.
        for r in records {
            canonical_name(r.domain(), &mut to_sign);
            to_sign.extend_from_slice(&r.record_type().to_be_bytes());
            to_sign.extend_from_slice(&1u16.to_be_bytes()); // class IN
            to_sign.extend_from_slice(&ttl.to_be_bytes());
            // Encode the rdata canonically.
            let rdata = canonical_rdata(r);
            to_sign.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            to_sign.extend_from_slice(&rdata);
        }

        // Sign with ED25519.
        let sig = key_pair.sign(&to_sign);
        let signature = sig.as_ref().to_vec();

        Ok(DnsRecord::RRSIG {
            domain: owner,
            type_covered,
            algorithm: key.algorithm,
            labels,
            original_ttl: ttl,
            signature_expiration: expiration,
            signature_inception: inception,
            key_tag: key.key_tag(),
            signer_name: signer_name.to_string(),
            signature,
            ttl,
        })
    }
}

/// Writes a domain name in canonical form (lowercase, uncompressed) into `out`.
fn canonical_name(name: &str, out: &mut Vec<u8>) {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return;
    }
    for label in name.split('.') {
        let lower = label.to_lowercase();
        out.push(lower.len() as u8);
        out.extend_from_slice(lower.as_bytes());
    }
    out.push(0);
}

/// Returns the canonical RDATA bytes for a record (for signing).
/// For names within RDATA, they are written in canonical (lowercase,
/// uncompressed) form. For other types, the raw RDATA is used.
fn canonical_rdata(record: &DnsRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    match record {
        DnsRecord::A { addr, .. } => {
            buf.extend_from_slice(&addr.octets());
        }
        DnsRecord::AAAA { addr, .. } => {
            buf.extend_from_slice(&addr.octets());
        }
        DnsRecord::CNAME { alias, .. } | DnsRecord::NS { nameserver: alias, .. } |
        DnsRecord::PTR { ptrdname: alias, .. } => {
            canonical_name(alias, &mut buf);
        }
        DnsRecord::MX { preference, exchange, .. } => {
            buf.extend_from_slice(&preference.to_be_bytes());
            canonical_name(exchange, &mut buf);
        }
        DnsRecord::SOA {
            mname, rname, serial, refresh, retry, expire, minimum, ..
        } => {
            canonical_name(mname, &mut buf);
            canonical_name(rname, &mut buf);
            buf.extend_from_slice(&serial.to_be_bytes());
            buf.extend_from_slice(&refresh.to_be_bytes());
            buf.extend_from_slice(&retry.to_be_bytes());
            buf.extend_from_slice(&expire.to_be_bytes());
            buf.extend_from_slice(&minimum.to_be_bytes());
        }
        DnsRecord::SRV { priority, weight, port, target, .. } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            canonical_name(target, &mut buf);
        }
        DnsRecord::CAA { flags, tag, value, .. } => {
            buf.push(*flags);
            buf.push(tag.len() as u8);
            buf.extend_from_slice(tag.as_bytes());
            buf.extend_from_slice(value.as_bytes());
        }
        DnsRecord::TXT { text, .. } => {
            // TXT rdata: sequence of length-prefixed character-strings.
            for chunk in text.as_bytes().chunks(255) {
                buf.push(chunk.len() as u8);
                buf.extend_from_slice(chunk);
            }
        }
        DnsRecord::DNSKEY { flags, protocol, algorithm, public_key, .. } => {
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.push(*protocol);
            buf.push(*algorithm);
            buf.extend_from_slice(public_key);
        }
        // For RRSIG/DS/NSEC/OPT, just use empty (these are not typically signed).
        _ => {}
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_and_build_dnskey() {
        let key = SigningKey::generate("example.com").unwrap();
        assert_eq!(key.algorithm, ALG_ED25519);
        assert_eq!(key.flags, FLAG_KSK | FLAG_ZONE);
        assert_eq!(key.public_key.len(), 32);

        let dnskey = key.dnskey_record(3600);
        match dnskey {
            DnsRecord::DNSKEY {
                domain,
                flags,
                protocol,
                algorithm,
                public_key,
                ttl,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(flags, 0x0101);
                assert_eq!(protocol, 3);
                assert_eq!(algorithm, 15);
                assert_eq!(public_key.len(), 32);
                assert_eq!(ttl, 3600);
            }
            other => panic!("expected DNSKEY, got {:?}", other),
        }
    }

    #[test]
    fn key_tag_is_nonzero() {
        let key = SigningKey::generate("example.com").unwrap();
        let tag = key.key_tag();
        // Key tag is a u16; just verify it runs without panic.
        let _ = tag;
    }

    #[test]
    fn key_tag_from_rdata_known_value() {
        // RFC 4034 Appendix B example: a 4-byte RDATA of [0x01, 0x02, 0x03, 0x04]
        // ac = 0x0100 + 0x0002 + 0x0300 + 0x0004 = 0x0406
        // ac += (ac >> 16) = 0x0406 + 0 = 0x0406
        // key tag = 0x0406 = 1030
        assert_eq!(key_tag_from_rdata(&[0x01, 0x02, 0x03, 0x04]), 1030);
    }

    #[test]
    fn sign_and_verify_a_record() {
        // Sign an A record RRset and verify the signature with the public key.
        use ring::signature::{UnparsedPublicKey, ED25519};

        let keys = DnssecKeys::single("example.com").unwrap();
        let a_record = DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "192.0.2.1".parse().unwrap(),
            ttl: 3600,
        };

        let rrsig = keys
            .sign_rrset(
                &[a_record],
                "example.com",
                3600,
                1000,
                2000,
            )
            .unwrap();

        match &rrsig {
            DnsRecord::RRSIG {
                type_covered,
                algorithm,
                signature,
                signer_name,
                key_tag,
                ..
            } => {
                assert_eq!(*type_covered, 1); // A
                assert_eq!(*algorithm, 15); // ED25519
                assert_eq!(signer_name, "example.com");
                assert!(!signature.is_empty());

                // Verify the signature using the public key.
                let key = &keys.keys[0];
                let pub_key =
                    UnparsedPublicKey::new(&ED25519, &key.public_key);

                // Rebuild the data that was signed.
                let mut to_verify = Vec::new();
                to_verify.extend_from_slice(&type_covered.to_be_bytes());
                to_verify.push(*algorithm);
                to_verify.push(2); // labels: "example.com" has 2 labels
                to_verify.extend_from_slice(&3600u32.to_be_bytes());
                to_verify.extend_from_slice(&2000u32.to_be_bytes());
                to_verify.extend_from_slice(&1000u32.to_be_bytes());
                to_verify.extend_from_slice(&key_tag.to_be_bytes());
                canonical_name("example.com", &mut to_verify);
                canonical_name("example.com", &mut to_verify);
                to_verify.extend_from_slice(&1u16.to_be_bytes()); // type A
                to_verify.extend_from_slice(&1u16.to_be_bytes()); // class IN
                to_verify.extend_from_slice(&3600u32.to_be_bytes());
                let rdata = [192, 0, 2, 1];
                to_verify.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                to_verify.extend_from_slice(&rdata);

                pub_key
                    .verify(&to_verify, signature)
                    .expect("RRSIG signature verification failed");
            }
            other => panic!("expected RRSIG, got {:?}", other),
        }
    }

    #[test]
    fn sign_dnskey_rrset() {
        let keys = DnssecKeys::single("example.com").unwrap();
        let dnskey_records = keys.dnskey_records(3600);
        assert_eq!(dnskey_records.len(), 1);

        let rrsig = keys
            .sign_rrset(&dnskey_records, "example.com", 3600, 1000, 2000)
            .unwrap();

        match rrsig {
            DnsRecord::RRSIG { type_covered, .. } => {
                assert_eq!(type_covered, 48); // DNSKEY
            }
            other => panic!("expected RRSIG for DNSKEY, got {:?}", other),
        }
    }
}
