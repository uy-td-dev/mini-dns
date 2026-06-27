use mini_dns::config::{Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::dnssec::DnssecKeys;
use mini_dns::cache::Cache;
use mini_dns::config::ForwardRules;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::state::{ServerState, Transport};
use std::net::{IpAddr, Ipv4Addr};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

fn dnssec_state() -> ServerState {
    let mut zone = Zone::new();
    zone.insert(
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
    let zones = ZoneSet::from_single("example.com".to_string(), zone);
    let keys = DnssecKeys::single("example.com").unwrap();
    ServerState::new(
        zones,
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    )
    .with_dnssec(keys)
}

fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
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
            qtype,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
    .to_bytes()
}

/// A DNSKEY query at the zone apex must return DNSKEY + RRSIG records.
#[tokio::test]
async fn dnskey_query_returns_dnskey_and_rrsig() {
    let state = dnssec_state();
    let resp = state
        .resolve(&query_bytes("example.com", 48), CLIENT, Transport::Udp) // DNSKEY
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    // Should have at least 2 answers: DNSKEY + RRSIG.
    assert!(packet.answers.len() >= 2);

    // First answer must be DNSKEY.
    assert!(matches!(packet.answers[0], DnsRecord::DNSKEY { .. }));
    // Second must be RRSIG covering DNSKEY.
    match &packet.answers[1] {
        DnsRecord::RRSIG { type_covered, .. } => {
            assert_eq!(*type_covered, 48); // DNSKEY
        }
        other => panic!("expected RRSIG, got {:?}", other),
    }
    // AA bit must be set.
    assert_ne!(packet.header.flags & 0x0400, 0);
}

/// A regular A query must return the A record plus an RRSIG covering it.
#[tokio::test]
async fn a_query_returns_rrsig() {
    let state = dnssec_state();
    let resp = state
        .resolve(&query_bytes("example.com", 1), CLIENT, Transport::Udp) // A
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    // Should have the A record plus an RRSIG.
    let has_a = packet.answers.iter().any(|r| matches!(r, DnsRecord::A { .. }));
    let has_rrsig = packet
        .answers
        .iter()
        .any(|r| matches!(r, DnsRecord::RRSIG { type_covered, .. } if *type_covered == 1));
    assert!(has_a, "expected A record in response");
    assert!(has_rrsig, "expected RRSIG covering A in response");
}

/// Without DNSSEC enabled, no RRSIG or DNSKEY records should appear.
#[tokio::test]
async fn no_dnssec_no_rrsig() {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );
    let state = ServerState::new(
        ZoneSet::from_single("example.com".to_string(), zone),
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    );

    let resp = state
        .resolve(&query_bytes("example.com", 1), CLIENT, Transport::Udp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    let has_rrsig = packet.answers.iter().any(|r| matches!(r, DnsRecord::RRSIG { .. }));
    assert!(!has_rrsig, "should not have RRSIG without DNSSEC enabled");
}
