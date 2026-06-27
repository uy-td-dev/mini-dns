use base64::Engine;
use mini_dns::config::{Zone, ZoneSet};
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use mini_dns::doh;
use mini_dns::server;
use mini_dns::state::ServerState;
use mini_dns::tls;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

fn example_zone() -> ZoneSet {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );
    ZoneSet::from_single("example.com".to_string(), zone)
}

fn query_bytes(name: &str) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id: 0xbeef,
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
async fn doh_post_resolves() {
    let state = ServerState::authoritative(example_zone());
    let resp = doh::resolve_http(&state, "POST", "/dns-query", &query_bytes("example.com"), CLIENT)
        .await;
    assert_eq!(resp.status, 200);
    let packet = DnsPacket::from_bytes(&resp.body).unwrap();
    assert_eq!(packet.answers.len(), 1);
}

#[tokio::test]
async fn doh_get_resolves() {
    let state = ServerState::authoritative(example_zone());
    let encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query_bytes("example.com"));
    let target = format!("/dns-query?dns={encoded}");
    let resp = doh::resolve_http(&state, "GET", &target, &[], CLIENT).await;
    assert_eq!(resp.status, 200);
    let packet = DnsPacket::from_bytes(&resp.body).unwrap();
    assert_eq!(packet.answers.len(), 1);
}

#[tokio::test]
async fn doh_rejects_bad_requests() {
    let state = ServerState::authoritative(example_zone());
    // Wrong path.
    assert_eq!(
        doh::resolve_http(&state, "POST", "/wrong", &query_bytes("example.com"), CLIENT)
            .await
            .status,
        404
    );
    // Unsupported method.
    assert_eq!(
        doh::resolve_http(&state, "PUT", "/dns-query", &query_bytes("example.com"), CLIENT)
            .await
            .status,
        405
    );
    // GET without a dns parameter.
    assert_eq!(
        doh::resolve_http(&state, "GET", "/dns-query", &[], CLIENT)
            .await
            .status,
        400
    );
}

#[tokio::test]
async fn dot_integration() {
    // Self-signed cert for "localhost"; keep the cert DER to trust it client-side.
    let assets = tls::build(None, None, vec![b"dot".to_vec()]).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&assets.config));

    let listener = server::bind_tcp("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(server::serve_dot(
        ServerState::authoritative(example_zone()),
        listener,
        acceptor,
        rx,
    ));

    // Build a client that trusts the generated certificate.
    let mut roots = RootCertStore::empty();
    roots.add(assets.cert_der.clone()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Length-framed query (DNS-over-TLS uses the same framing as DNS-over-TCP).
    let query = query_bytes("example.com");
    tls.write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    tls.write_all(&query).await.unwrap();

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(2), tls.read_exact(&mut len_buf))
        .await
        .expect("response within 2s")
        .unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; len];
    tls.read_exact(&mut msg).await.unwrap();

    let packet = DnsPacket::from_bytes(&msg).unwrap();
    assert_eq!(packet.header.id, 0xbeef);
    assert_eq!(packet.answers.len(), 1);
    match &packet.answers[0] {
        DnsRecord::A { addr, .. } => assert_eq!(addr.to_string(), "192.0.2.1"),
        other => panic!("expected A record, got {:?}", other),
    }

    server_handle.abort();
}
