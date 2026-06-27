use mini_dns::config::{Zone, ZoneSet};
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::record::DnsRecord;
use mini_dns::server;
use mini_dns::state::ServerState;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

/// A query packet for `example.com` A (shared by the integration tests).
const QUERY: &[u8] = &[
    0xab, 0xcd, // ID
    0x01, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answers: 0
    0x00, 0x00, // Authorities: 0
    0x00, 0x00, // Additionals: 0
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
    0x03, b'c', b'o', b'm', // "com"
    0x00, // Null terminator
    0x00, 0x01, // QTYPE: A
    0x00, 0x01, // QCLASS: IN
];

fn example_zone() -> ZoneSet {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
            ttl: 3600,
        }],
    );
    ZoneSet::from_single("example.com".to_string(), zone)
}

#[tokio::test]
async fn test_server_integration() {
    // Bind to an OS-chosen free port so the test never clashes on a fixed port.
    let server_socket = server::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // Shutdown signal that never fires (the test aborts the task instead).
    let (_tx, rx) = tokio::sync::watch::channel(false);

    // Run the server in a background task
    let server_handle = tokio::spawn(async move {
        server::serve(ServerState::authoritative(example_zone()), server_socket, rx)
            .await
            .unwrap();
    });

    // Create a UDP socket and send a DNS query
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server_addr).await.unwrap();
    socket.send(QUERY).await.unwrap();

    // Receive the response
    let mut response_buf = [0u8; 512];
    let len = timeout(Duration::from_secs(1), socket.recv(&mut response_buf))
        .await
        .expect("should receive a response within 1 second")
        .unwrap();

    // Parse the response
    let response_packet = DnsPacket::from_bytes(&response_buf[..len]).unwrap();

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

#[tokio::test]
async fn test_server_tcp() {
    // Bind a TCP listener on a free port and serve it.
    let listener = server::bind_tcp("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server::serve_tcp(ServerState::authoritative(example_zone()), listener, rx)
            .await
            .unwrap();
    });

    // DNS-over-TCP frames each message with a 2-byte big-endian length prefix.
    let mut stream = TcpStream::connect(server_addr).await.unwrap();
    stream
        .write_all(&(QUERY.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(QUERY).await.unwrap();

    // Read the 2-byte length, then the response message.
    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf))
        .await
        .expect("should receive a response within 1 second")
        .unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await.unwrap();

    let response_packet = DnsPacket::from_bytes(&msg).unwrap();
    assert_eq!(response_packet.header.id, 0xabcd);
    assert_eq!(response_packet.answers.len(), 1);
    match &response_packet.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "192.0.2.1"),
        other => panic!("Expected an A record, got {:?}", other),
    }

    server_handle.abort();
}