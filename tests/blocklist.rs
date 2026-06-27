use mini_dns::blocklist::Blocklist;
use mini_dns::cache::Cache;
use mini_dns::config::{ForwardRules, Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::state::{ServerState, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Builds a ServerState with a single zone containing the given records.
fn state_with_zone(records: Vec<(String, Vec<DnsRecord>)>) -> ServerState {
    let mut zone = Zone::new();
    for (name, recs) in records {
        zone.insert(name, recs);
    }
    ServerState::new(
        ZoneSet::from_single("example.com".to_string(), zone),
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    )
}

/// Builds a DNS query packet.
fn query(name: &str, qtype: u16) -> Vec<u8> {
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

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// Blocked domains must get NXDOMAIN even when the name exists in the zone.
#[tokio::test]
async fn blocklist_returns_nxdomain() {
    let state = state_with_zone(vec![(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    )])
    .with_blocklist(Blocklist::from_domains(vec!["example.com".to_string()]));

    let resp = state
        .resolve(&query("example.com", 1), CLIENT, Transport::Udp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.header.flags & 0x000F, 3); // NXDOMAIN
    assert_eq!(state.metrics.blocked(), 1);
}

/// Wildcard blocklist entries block subdomains but not the apex.
#[tokio::test]
async fn blocklist_wildcard_blocks_subdomain() {
    let state = state_with_zone(vec![(
        "ads.example.com".to_string(),
        vec![DnsRecord::A {
            domain: "ads.example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    )])
    .with_blocklist(Blocklist::from_domains(vec!["*.example.com".to_string()]));

    // ads.example.com is blocked by *.example.com
    let resp = state
        .resolve(&query("ads.example.com", 1), CLIENT, Transport::Udp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.header.flags & 0x000F, 3); // NXDOMAIN

    // example.com itself is NOT blocked by the wildcard
    let state2 = state_with_zone(vec![(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    )])
    .with_blocklist(Blocklist::from_domains(vec!["*.example.com".to_string()]));
    let resp2 = state2
        .resolve(&query("example.com", 1), CLIENT, Transport::Udp)
        .await
        .unwrap();
    let packet2 = DnsPacket::from_bytes(&resp2).unwrap();
    assert_eq!(packet2.answers.len(), 1); // not blocked
}

/// DNS64: AAAA query for a name with only A records synthesizes AAAA.
#[tokio::test]
async fn dns64_synthesizes_aaaa_from_a() {
    let state = state_with_zone(vec![(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 300,
        }],
    )])
    .with_dns64(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0));

    let resp = state
        .resolve(&query("example.com", 28), CLIENT, Transport::Udp) // AAAA
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0] {
        DnsRecord::AAAA { addr, ttl, domain, .. } => {
            // 192.0.2.1 embedded in 64:ff9b::/96 -> 64:ff9b::192.0.2.1
            assert_eq!(addr.to_string(), "64:ff9b::c000:201");
            assert_eq!(*ttl, 300);
            // Owner name must be the queried name, not empty.
            assert_eq!(domain, "example.com");
        }
        other => panic!("expected synthesized AAAA, got {:?}", other),
    }
}

/// DNS64: when native AAAA records exist, they are returned as-is (no synthesis).
#[tokio::test]
async fn dns64_skips_when_native_aaaa_exists() {
    let state = state_with_zone(vec![(
        "example.com".to_string(),
        vec![
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr: Ipv4Addr::new(192, 0, 2, 1),
                ttl: 300,
            },
            DnsRecord::AAAA {
                domain: "example.com".to_string(),
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                ttl: 300,
            },
        ],
    )])
    .with_dns64(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0));

    let resp = state
        .resolve(&query("example.com", 28), CLIENT, Transport::Udp) // AAAA
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0] {
        DnsRecord::AAAA { addr, .. } => assert_eq!(addr.to_string(), "2001:db8::1"),
        other => panic!("expected native AAAA, got {:?}", other),
    }
}

/// DNS64: no A records -> no synthesis (NODATA preserved).
#[tokio::test]
async fn dns64_no_a_records_no_synthesis() {
    let state = state_with_zone(vec![(
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
    )])
    .with_dns64(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0));

    let resp = state
        .resolve(&query("example.com", 28), CLIENT, Transport::Udp) // AAAA
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 0); // NODATA, no synthesis
}
