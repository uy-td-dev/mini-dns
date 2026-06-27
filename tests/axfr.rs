use mini_dns::acl::Acl;
use mini_dns::config::{Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::cache::Cache;
use mini_dns::config::ForwardRules;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::state::{ServerState, Transport};
use std::net::{IpAddr, Ipv4Addr};

fn soa() -> DnsRecord {
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
    }
}

fn axfr_state(acl: Acl) -> ServerState {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![
            soa(),
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr: "192.0.2.1".parse().unwrap(),
                ttl: 3600,
            },
            DnsRecord::NS {
                domain: "example.com".to_string(),
                nameserver: "ns1.example.com".to_string(),
                ttl: 3600,
            },
        ],
    );
    zone.insert(
        "www.example.com".to_string(),
        vec![DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "192.0.2.2".parse().unwrap(),
            ttl: 3600,
        }],
    );
    ServerState::new(
        ZoneSet::from_single("example.com".to_string(), zone),
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    )
    .with_axfr_acl(acl)
}

fn axfr_query(zone_name: &str) -> Vec<u8> {
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
            qname: zone_name.to_string(),
            qtype: 252, // AXFR
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
    .to_bytes()
}

const CLIENT_OK: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const CLIENT_DENY: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

/// AXFR from an allowed client returns all zone records framed by SOA.
#[tokio::test]
async fn axfr_allowed_returns_all_records() {
    let acl = Acl::parse(&["10.0.0.0/8".to_string()]).unwrap();
    let state = axfr_state(acl);

    let resp = state
        .resolve(&axfr_query("example.com"), CLIENT_OK, Transport::Tcp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    // AXFR response: SOA, all records, SOA (last). We have 4 unique records
    // (SOA, A, NS, www A) plus the trailing SOA = 6 total.
    assert!(packet.answers.len() >= 5);
    // First and last must be SOA.
    assert!(matches!(packet.answers[0], DnsRecord::SOA { .. }));
    assert!(matches!(
        packet.answers[packet.answers.len() - 1],
        DnsRecord::SOA { .. }
    ));
    // AA bit set.
    assert_ne!(packet.header.flags & 0x0400, 0);
}

/// AXFR from a denied client gets REFUSED (rcode 5).
#[tokio::test]
async fn axfr_denied_returns_refused() {
    let acl = Acl::parse(&["10.0.0.0/8".to_string()]).unwrap();
    let state = axfr_state(acl);

    let resp = state
        .resolve(&axfr_query("example.com"), CLIENT_DENY, Transport::Tcp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.header.flags & 0x000F, 5); // REFUSED
    assert_eq!(packet.answers.len(), 0);
}

/// AXFR for a zone we're not authoritative for returns NXDOMAIN.
#[tokio::test]
async fn axfr_unknown_zone_returns_nxdomain() {
    let acl = Acl::parse(&["10.0.0.0/8".to_string()]).unwrap();
    let state = axfr_state(acl);

    let resp = state
        .resolve(&axfr_query("other.org"), CLIENT_OK, Transport::Tcp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.header.flags & 0x000F, 3); // NXDOMAIN
}

/// AXFR over UDP is not handled (returns the normal NXDOMAIN from resolve_local,
/// since try_axfr only runs for TCP).
#[tokio::test]
async fn axfr_over_udp_not_served() {
    let acl = Acl::parse(&["10.0.0.0/8".to_string()]).unwrap();
    let state = axfr_state(acl);

    let resp = state
        .resolve(&axfr_query("example.com"), CLIENT_OK, Transport::Udp)
        .await
        .unwrap();
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    // Over UDP, AXFR is not a normal query -> NXDOMAIN (no AXFR records in zone).
    assert_eq!(packet.answers.len(), 0);
}
