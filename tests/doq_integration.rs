//! Integration test for DNS-over-QUIC (DoQ, RFC 9250).
//!
//! Spins up a QUIC endpoint with a self-signed cert, connects a quinn client,
//! opens a bidirectional stream, sends a length-framed DNS query, and verifies
//! the response.

use mini_dns::config::{Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::doq;
use mini_dns::state::ServerState;
use mini_dns::tls;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use std::sync::Arc;

fn example_zone() -> ZoneSet {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "192.0.2.1".parse().unwrap(),
            ttl: 3600,
        }],
    );
    ZoneSet::from_single("example.com".to_string(), zone)
}

fn query_bytes(name: &str) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id: 0x1234,
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
    .to_bytes()
}

#[tokio::test]
async fn doq_resolves_query() {
    // Build a self-signed TLS config with the `doq` ALPN for the server.
    let assets = tls::build(None, None, vec![b"doq".to_vec()]).unwrap();
    let doq_config = doq::with_doq_alpn((*assets.config).clone());
    let endpoint = doq::build_endpoint(Arc::new(doq_config), "127.0.0.1:0").unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    let state = ServerState::authoritative(example_zone());
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(doq::serve(state, endpoint, rx));

    // Build a QUIC client that trusts the self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(assets.cert_der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"doq".to_vec()];

    let quic_client_cfg = QuicClientConfig::try_from(client_tls).unwrap();
    let client_config = ClientConfig::new(Arc::new(quic_client_cfg));
    let bind_addr = "127.0.0.1:0";
    let mut client_endpoint = Endpoint::client(bind_addr.parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    // Connect to the server.
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("QUIC connection failed");

    // Open a bidirectional stream and send the query.
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let query = query_bytes("example.com");
    send.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
    send.write_all(&query).await.unwrap();

    // Read the response: 2-byte length + DNS message.
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    recv.read_exact(&mut msg).await.unwrap();

    let packet = DnsPacket::from_bytes(&msg).unwrap();
    assert_eq!(packet.header.id, 0x1234);
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "192.0.2.1"),
        other => panic!("expected A record, got {:?}", other),
    }

    server_handle.abort();
}
