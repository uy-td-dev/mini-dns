use mini_dns::config::Zone;
use mini_dns::dns::record::DnsRecord;
use mini_dns::server;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_server_integration() {
    // Create a zone programmatically
    let mut zone = Zone::new();
    let domain = "example.com".to_string();
    let record = DnsRecord::A {
        domain: domain.clone(),
        addr: "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
        ttl: 3600,
    };
    zone.insert(domain, vec![record]);

    // Run the server in a background task
    let server_handle = tokio::spawn(async move {
        server::run(zone).await.unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a UDP socket and send a DNS query
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect("127.0.0.1:8888").await.unwrap();

    let query: &[u8] = &[
        // Header
        0xab, 0xcd, // ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authorities: 0
        0x00, 0x00, // Additionals: 0
        // Question
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // Null terminator
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];
    socket.send(query).await.unwrap();

    // Receive the response
    let mut response_buf = [0u8; 512];
    let len = timeout(Duration::from_secs(1), socket.recv(&mut response_buf))
        .await
        .expect("should receive a response within 1 second")
        .unwrap();

    // Parse the response
    let response_packet = mini_dns::dns::packet::DnsPacket::from_bytes(&response_buf[..len]).unwrap();

    // Assert that the response is correct
    assert_eq!(response_packet.header.id, 0xabcd);
    assert_eq!(response_packet.answers.len(), 1);
    if let DnsRecord::A { addr, .. } = &response_packet.answers[0] {
        assert_eq!(addr.to_string(), "192.0.2.1");
    } else {
        panic!("Expected an A record in the response");
    }

    // Abort the server task to allow the test to finish
    server_handle.abort();
}