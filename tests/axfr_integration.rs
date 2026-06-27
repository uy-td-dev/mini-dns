//! Integration test for AXFR (zone transfer) over TCP.
//!
//! Starts a TCP server with an AXFR ACL allowing localhost, sends an AXFR
//! query over a TCP connection with 2-byte length framing, and verifies the
//! response contains all zone records framed by SOA.

use mini_dns::acl::Acl;
use mini_dns::cache::Cache;
use mini_dns::config::{ForwardRules, Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::server;
use mini_dns::state::ServerState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

fn axfr_zone() -> ZoneSet {
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
    ZoneSet::from_single("example.com".to_string(), zone)
}

fn axfr_query(zone_name: &str) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id: 42,
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

/// Sends a length-framed DNS message over a TCP stream and reads the response.
async fn tcp_dns_exchange(stream: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(msg.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(msg).await.unwrap();

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .unwrap()
        .unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

#[tokio::test]
async fn axfr_allowed_over_tcp() {
    let listener = server::bind_tcp("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);

    let state = ServerState::new(
        axfr_zone(),
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    )
    .with_axfr_acl(Acl::parse(&["127.0.0.0/8".to_string()]).unwrap());

    let handle = tokio::spawn(server::serve_tcp(
        std::sync::Arc::new(state),
        listener,
        rx,
    ));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let resp = tcp_dns_exchange(&mut stream, &axfr_query("example.com")).await;
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    // AXFR response: SOA, A, NS, www A, SOA = 5+ records.
    assert!(packet.answers.len() >= 5);
    // First and last must be SOA.
    assert!(matches!(packet.answers[0], DnsRecord::SOA { .. }));
    assert!(matches!(
        packet.answers[packet.answers.len() - 1],
        DnsRecord::SOA { .. }
    ));
    // AA bit set.
    assert_ne!(packet.header.flags & 0x0400, 0);

    handle.abort();
}

#[tokio::test]
async fn axfr_denied_over_tcp() {
    let listener = server::bind_tcp("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);

    let state = ServerState::new(
        axfr_zone(),
        None,
        ForwardRules::none(),
        None,
        Cache::new(16),
        RateLimiter::disabled(),
    )
    .with_axfr_acl(Acl::deny_all()); // deny all

    let handle = tokio::spawn(server::serve_tcp(
        std::sync::Arc::new(state),
        listener,
        rx,
    ));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let resp = tcp_dns_exchange(&mut stream, &axfr_query("example.com")).await;
    let packet = DnsPacket::from_bytes(&resp).unwrap();

    assert_eq!(packet.header.flags & 0x000F, 5); // REFUSED
    assert_eq!(packet.answers.len(), 0);

    handle.abort();
}
