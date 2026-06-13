//! Zone resolution: turning a parsed query [`DnsPacket`] into a response.
//!
//! This is the authoritative-lookup *business logic* — wildcard matching, CNAME
//! chasing, AA/NXDOMAIN/NODATA determination and EDNS echo — kept separate from
//! the wire (de)serialisation concerns in [`super::packet`].

use crate::config::Zone;
use crate::dns::header::DnsHeader;
use crate::dns::packet::DnsPacket;
use crate::dns::record::DnsRecord;

/// The maximum number of CNAME records followed when resolving a query,
/// guarding against accidental or malicious CNAME loops.
const MAX_CNAME_CHAIN: usize = 16;

/// Builds a response packet for `request` against `zone`.
///
/// Resolution honours the question type, supports `*` wildcard records, and
/// follows CNAME chains within the zone (appending each CNAME and the final
/// target's records). The AA bit is set when the server is authoritative for
/// the name, and NXDOMAIN is returned when the original name does not exist.
pub fn build_response(request: &DnsPacket, zone: &Zone) -> DnsPacket {
    let mut answers = Vec::new();
    let mut authoritative = false;
    let mut rcode = 0u16; // NOERROR

    if let Some(question) = request.questions.first() {
        let qtype = question.qtype;
        // DNS names are case-insensitive, so match against a normalized key.
        let mut name = question.qname.to_lowercase();
        let mut seen = std::collections::HashSet::new();

        for _ in 0..MAX_CNAME_CHAIN {
            if !seen.insert(name.clone()) {
                break; // CNAME loop detected
            }

            let Some(records) = lookup(zone, &name) else {
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
    let mut flags = 0x8000 | (request.header.flags & 0x0100) | rcode;
    if authoritative {
        flags |= 0x0400; // AA
    }

    // EDNS(0): if the client sent an OPT record, echo one back advertising
    // the negotiated UDP payload size (also used as the truncation limit).
    let mut additionals = Vec::new();
    if let Some(client_size) = request.edns_udp_size() {
        let negotiated =
            client_size.clamp(DnsPacket::MAX_UDP_SIZE as u16, DnsPacket::MAX_EDNS_UDP as u16);
        additionals.push(DnsRecord::OPT {
            udp_size: negotiated,
        });
    }

    DnsPacket {
        header: DnsHeader {
            id: request.header.id,
            flags,
            questions: request.questions.len() as u16,
            answers: answers.len() as u16,
            authorities: 0,
            additionals: additionals.len() as u16,
        },
        questions: request.questions.clone(),
        answers,
        authorities: Vec::new(),
        additionals,
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
