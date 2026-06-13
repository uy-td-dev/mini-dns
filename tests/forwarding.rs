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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;

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
    query_bytes_id(name, 0x1111)
}

fn query_bytes_id(name: &str, id: u16) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id,
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
    assert_eq!(state.metrics.forwarded(), 1);
    assert_eq!(state.metrics.cache_hits(), 0);

    // Second identical query: served from cache, not forwarded again.
    let resp2 = state
        .resolve(&query, client, Transport::Udp)
        .await
        .expect("response");
    let packet2 = DnsPacket::from_bytes(&resp2).unwrap();
    assert_eq!(packet2.answers.len(), 1);
    assert_eq!(state.metrics.forwarded(), 1); // unchanged
    assert_eq!(state.metrics.cache_hits(), 1);
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
    assert_eq!(state.metrics.rate_limited(), 1);
}

/// Upstream that always returns NXDOMAIN with an SOA in the authority section,
/// counting requests. Returns its address and the request counter.
async fn spawn_nxdomain_upstream() -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&counter);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            c.fetch_add(1, Ordering::Relaxed);
            let request = DnsPacket::from_bytes(&buf[..len]).unwrap();
            let response = DnsPacket {
                header: DnsHeader {
                    id: request.header.id,
                    flags: 0x8183, // response, RA, NXDOMAIN(3)
                    questions: 1,
                    answers: 0,
                    authorities: 1,
                    additionals: 0,
                },
                questions: vec![request.questions[0].clone()],
                answers: vec![],
                authorities: vec![DnsRecord::SOA {
                    domain: "example".to_string(),
                    mname: "ns.example".to_string(),
                    rname: "admin.example".to_string(),
                    serial: 1,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1_209_600,
                    minimum: 60,
                    ttl: 60,
                }],
                additionals: vec![],
            };
            socket.send_to(&response.to_bytes(), peer).await.unwrap();
        }
    });
    (addr, counter)
}

#[tokio::test]
async fn negative_results_are_cached() {
    let (upstream, counter) = spawn_nxdomain_upstream().await;
    let state = ServerState::new(
        Zone::new(),
        None,
        Some(Forwarder::new(upstream, Duration::from_secs(2))),
        Cache::new(16),
        RateLimiter::disabled(),
    );
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let query = query_bytes("ghost.example");

    // First query forwards and gets NXDOMAIN.
    let resp = state
        .resolve(&query, client, Transport::Udp)
        .await
        .expect("response");
    let packet = DnsPacket::from_bytes(&resp).unwrap();
    assert_eq!(packet.header.flags & 0x000F, 3); // NXDOMAIN
    assert_eq!(state.metrics.forwarded(), 1);

    // Second identical query is served from the negative cache, not re-forwarded.
    let resp2 = state
        .resolve(&query, client, Transport::Udp)
        .await
        .expect("response");
    let packet2 = DnsPacket::from_bytes(&resp2).unwrap();
    assert_eq!(packet2.header.flags & 0x000F, 3); // still NXDOMAIN
    assert_eq!(counter.load(Ordering::Relaxed), 1); // upstream hit only once
    assert_eq!(state.metrics.cache_hits(), 1);
}

/// Upstream that counts requests and replies slowly, so concurrent queries pile
/// up. Returns its address and the request counter.
async fn spawn_counting_slow_upstream() -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&counter);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            c.fetch_add(1, Ordering::Relaxed);
            let request = DnsPacket::from_bytes(&buf[..len]).unwrap();
            sleep(Duration::from_millis(150)).await; // let followers coalesce
            let question = request.questions[0].clone();
            let response = DnsPacket {
                header: DnsHeader {
                    id: request.header.id,
                    flags: 0x8180,
                    questions: 1,
                    answers: 1,
                    authorities: 0,
                    additionals: 0,
                },
                questions: vec![question.clone()],
                answers: vec![DnsRecord::A {
                    domain: question.qname,
                    addr: Ipv4Addr::new(203, 0, 113, 7),
                    ttl: 300,
                }],
                authorities: vec![],
                additionals: vec![],
            };
            socket.send_to(&response.to_bytes(), peer).await.unwrap();
        }
    });
    (addr, counter)
}

#[tokio::test]
async fn single_flight_coalesces_concurrent_misses() {
    let (upstream, counter) = spawn_counting_slow_upstream().await;
    let state = Arc::new(ServerState::new(
        Zone::new(),
        None,
        Some(Forwarder::new(upstream, Duration::from_secs(2))),
        Cache::new(16),
        RateLimiter::disabled(),
    ));
    let client = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    // Fire many concurrent queries for the SAME name, each with a distinct ID.
    let n: u16 = 50;
    let mut handles = Vec::new();
    for i in 0..n {
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            let id = 0x1000 + i;
            let query = query_bytes_id("dup.example", id);
            let resp = state
                .resolve(&query, client, Transport::Udp)
                .await
                .expect("response");
            // Each caller must get a response carrying its OWN transaction ID.
            assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), id);
            let packet = DnsPacket::from_bytes(&resp).unwrap();
            assert_eq!(packet.answers.len(), 1);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // All but a handful should have been coalesced onto one upstream query.
    let upstream_hits = counter.load(Ordering::Relaxed);
    assert!(
        upstream_hits < n as u64,
        "expected coalescing, upstream got {upstream_hits} of {n}"
    );
    assert!(state.metrics.coalesced() >= 1);
}
