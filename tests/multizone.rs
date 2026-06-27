use mini_dns::config::{ForwardRule, ForwardRules, Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use std::net::{Ipv4Addr, SocketAddr};

/// A query for `name` type A.
fn a_query(name: &str) -> DnsPacket {
    DnsPacket {
        header: DnsHeader {
            id: 1,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: name.to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

/// Two zones: `example.com` and `internal`, each with an A record at the apex
/// and a SOA (so the origin is tracked). Queries for each must resolve from
/// the correct zone, and NXDOMAIN within a zone must carry that zone's SOA.
#[test]
fn multi_zone_resolves_from_correct_zone() {
    let mut zone1 = Zone::new();
    zone1.insert(
        "example.com".to_string(),
        vec![
            DnsRecord::SOA {
                domain: "example.com".to_string(),
                mname: "ns1.example.com".to_string(),
                rname: "admin.example.com".to_string(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 60,
                ttl: 3600,
            },
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr: Ipv4Addr::new(192, 0, 2, 1),
                ttl: 3600,
            },
        ],
    );

    let mut zone2 = Zone::new();
    zone2.insert(
        "internal".to_string(),
        vec![
            DnsRecord::SOA {
                domain: "internal".to_string(),
                mname: "ns1.internal".to_string(),
                rname: "admin.internal".to_string(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 60,
                ttl: 3600,
            },
            DnsRecord::A {
                domain: "internal".to_string(),
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ttl: 3600,
            },
        ],
    );

    let zones = ZoneSet::new(vec![
        mini_dns::config::AuthZone {
            origin: "example.com".to_string(),
            records: zone1,
        },
        mini_dns::config::AuthZone {
            origin: "internal".to_string(),
            records: zone2,
        },
    ]);

    // Query example.com — resolves from zone 1.
    let r1 = a_query("example.com").build_response(&zones);
    assert_eq!(r1.answers.len(), 1);
    match &r1.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "192.0.2.1"),
        other => panic!("expected A from zone1, got {:?}", other),
    }

    // Query internal — resolves from zone 2.
    let r2 = a_query("internal").build_response(&zones);
    assert_eq!(r2.answers.len(), 1);
    match &r2.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "10.0.0.1"),
        other => panic!("expected A from zone2, got {:?}", other),
    }
}

/// NXDOMAIN within a specific zone must carry THAT zone's SOA, not the other
/// zone's SOA.
#[test]
fn multi_zone_nxdomain_carries_correct_soa() {
    let mut zone1 = Zone::new();
    zone1.insert(
        "example.com".to_string(),
        vec![DnsRecord::SOA {
            domain: "example.com".to_string(),
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 60,
            ttl: 3600,
        }],
    );

    let mut zone2 = Zone::new();
    zone2.insert(
        "internal".to_string(),
        vec![DnsRecord::SOA {
            domain: "internal".to_string(),
            mname: "ns1.internal".to_string(),
            rname: "admin.internal".to_string(),
            serial: 99,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 60,
            ttl: 3600,
        }],
    );

    let zones = ZoneSet::new(vec![
        mini_dns::config::AuthZone {
            origin: "example.com".to_string(),
            records: zone1,
        },
        mini_dns::config::AuthZone {
            origin: "internal".to_string(),
            records: zone2,
        },
    ]);

    // NXDOMAIN for missing.example.com — must carry example.com's SOA.
    let r = a_query("missing.example.com").build_response(&zones);
    assert_eq!(r.answers.len(), 0);
    assert_eq!(r.header.flags & 0x000F, 3); // NXDOMAIN
    assert_eq!(r.authorities.len(), 1);
    match &r.authorities[0] {
        DnsRecord::SOA { mname, .. } => assert_eq!(mname, "ns1.example.com"),
        other => panic!("expected example.com SOA, got {:?}", other),
    }

    // NXDOMAIN for missing.internal — must carry internal's SOA.
    let r2 = a_query("missing.internal").build_response(&zones);
    assert_eq!(r2.authorities.len(), 1);
    match &r2.authorities[0] {
        DnsRecord::SOA { mname, .. } => assert_eq!(mname, "ns1.internal"),
        other => panic!("expected internal SOA, got {:?}", other),
    }
}

/// A query for a name that doesn't fall within any zone must NOT be
/// authoritative and must NOT carry an SOA.
#[test]
fn multi_zone_name_outside_all_zones_no_aa() {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::SOA {
            domain: "example.com".to_string(),
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 60,
            ttl: 3600,
        }],
    );
    let zones = ZoneSet::from_single("example.com".to_string(), zone);

    let r = a_query("other.org").build_response(&zones);
    assert_eq!(r.answers.len(), 0);
    assert_eq!(r.header.flags & 0x000F, 3); // NXDOMAIN
    assert_eq!(r.header.flags & 0x0400, 0); // not authoritative
    assert_eq!(r.authorities.len(), 0); // no SOA
}

/// Conditional forwarding: longest-suffix match selects the upstream.
#[test]
fn conditional_forwarding_longest_suffix_wins() {
    let internal: SocketAddr = "10.0.0.1:53".parse().unwrap();
    let corp: SocketAddr = "10.0.0.2:53".parse().unwrap();
    let default: SocketAddr = "1.1.1.1:53".parse().unwrap();

    let rules = ForwardRules::new(
        Some(default),
        vec![
            ForwardRule {
                suffix: "corp.example.com".to_string(),
                upstream: corp,
            },
            ForwardRule {
                suffix: "example.com".to_string(),
                upstream: internal,
            },
        ],
    );

    // host.corp.example.com -> corp (longer suffix match)
    assert_eq!(
        rules.match_name("host.corp.example.com"),
        Some(corp)
    );
    // host.example.com -> internal
    assert_eq!(rules.match_name("host.example.com"), Some(internal));
    // example.com itself -> internal (exact match)
    assert_eq!(rules.match_name("example.com"), Some(internal));
    // other.org -> default
    assert_eq!(rules.match_name("other.org"), Some(default));
}

/// Conditional forwarding with no default: unmatched names get no upstream.
#[test]
fn conditional_forwarding_no_default_unmatched() {
    let corp: SocketAddr = "10.0.0.2:53".parse().unwrap();
    let rules = ForwardRules::new(
        None,
        vec![ForwardRule {
            suffix: "corp.example.com".to_string(),
            upstream: corp,
        }],
    );

    assert_eq!(rules.match_name("host.corp.example.com"), Some(corp));
    assert_eq!(rules.match_name("other.org"), None);
}
