use mini_dns::cache::Cache;
use mini_dns::config::Zone;
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::forwarder::Forwarder;
use mini_dns::ratelimit::RateLimiter;
use mini_dns::state::{ServerState, Transport};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Spawns a fake upstream resolver that answers every A query with 203.0.113.7.
async fn spawn_fake_upstream() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = DnsPacket::from_bytes(&buf[..len]).unwrap();
            let question = request.questions[0].clone();
            let answer = DnsRecord::A {
                domain: question.qname.clone(),
                addr: Ipv4Addr::new(203, 0, 113, 7),
                ttl: 300,
            };
            let response = DnsPacket {
                header: DnsHeader {
                    id: request.header.id,
                    flags: 0x8180, // response, RA, NOERROR
                    questions: 1,
                    answers: 1,
                    authorities: 0,
                    additionals: 0,
                },
                questions: vec![question],
                answers: vec![answer],
                authorities: vec![],
                additionals: vec![],
            };
            socket.send_to(&response.to_bytes(), peer).await.unwrap();
        }
    });
    addr
}

fn query_bytes(name: &str) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id: 0x1111,
            flags: 0x0100, // RD set (recursion desired)
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: name.to_string(),
            qtype: 1, // A
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
    .to_bytes()
}

#[tokio::test]
async fn forwards_unknown_names_and_caches() {
    let upstream = spawn_fake_upstream().await;
    let state = ServerState::new(
        Zone::new(), // empty zone -> everything is forwarded
        None,
        Some(Forwarder::new(upstream, Duration::from_secs(2))),
        Cache::new(16),
        RateLimiter::disabled(),
    );
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let query = query_bytes("notlocal.example");

    // First query: forwarded to upstream.
    let resp = state
        .resolve(&query, client, Transport::Udp)
        .await
        .expect("response");
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "203.0.113.7"),
        other => panic!("expected A, got {:?}", other),
    }
    assert_eq!(state.metrics.forwarded.load(Ordering::Relaxed), 1);
    assert_eq!(state.metrics.cache_hits.load(Ordering::Relaxed), 0);

    // Second identical query: served from cache, not forwarded again.
    let resp2 = state
        .resolve(&query, client, Transport::Udp)
        .await
        .expect("response");
    let packet2 = DnsPacket::from_bytes(&resp2).unwrap();
    assert_eq!(packet2.answers.len(), 1);
    assert_eq!(state.metrics.forwarded.load(Ordering::Relaxed), 1); // unchanged
    assert_eq!(state.metrics.cache_hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rate_limiter_drops_excess_queries() {
    let upstream = spawn_fake_upstream().await;
    let state = ServerState::new(
        Zone::new(),
        None,
        Some(Forwarder::new(upstream, Duration::from_secs(2))),
        Cache::new(16),
        RateLimiter::new(2, Duration::from_secs(60)),
    );
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let query = query_bytes("a.example");

    assert!(state.resolve(&query, client, Transport::Udp).await.is_some());
    assert!(state.resolve(&query, client, Transport::Udp).await.is_some());
    // Third within the window is dropped.
    assert!(state.resolve(&query, client, Transport::Udp).await.is_none());
    assert_eq!(state.metrics.rate_limited.load(Ordering::Relaxed), 1);
}
