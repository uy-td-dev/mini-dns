use mini_dns::config::Zone;
use mini_dns::dns::header::DnsHeader;
use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;
use mini_dns::dns::record::DnsRecord;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_dns_packet_from_bytes() {
    let packet_bytes: &[u8] = &[
        // Header
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authorities: 0
        0x00, 0x00, // Additionals: 0
        // Question
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // Null terminator for the name
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];
    let packet = DnsPacket::from_bytes(packet_bytes).unwrap();

    assert_eq!(packet.header.id, 0x1234);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.questions[0].qname, "example.com");
}

#[test]
fn test_dns_packet_to_bytes() {
    let packet = DnsPacket {
        header: mini_dns::dns::header::DnsHeader {
            id: 0x5678,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: "test.com".to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let encoded = packet.to_bytes();
    let decoded = DnsPacket::from_bytes(&encoded).unwrap();

    assert_eq!(decoded.header.id, 0x5678);
    assert_eq!(decoded.questions[0].qname, "test.com");
}

/// AAAA, MX and TXT answer records must survive an encode/decode round-trip.
#[test]
fn test_record_types_round_trip() {
    let answers = vec![
        DnsRecord::AAAA {
            domain: "example.com".to_string(),
            addr: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            ttl: 3600,
        },
        DnsRecord::MX {
            domain: "example.com".to_string(),
            preference: 10,
            exchange: "mail.example.com".to_string(),
            ttl: 3600,
        },
        DnsRecord::TXT {
            domain: "example.com".to_string(),
            text: "v=spf1 -all".to_string(),
            ttl: 3600,
        },
    ];

    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x4242,
            flags: 0x8180,
            questions: 0,
            answers: answers.len() as u16,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };

    let decoded = DnsPacket::from_bytes(&packet.to_bytes()).unwrap();
    assert_eq!(decoded.answers.len(), 3);

    match &decoded.answers[0] {
        DnsRecord::AAAA { addr, .. } => assert_eq!(addr.to_string(), "2001:db8::1"),
        other => panic!("expected AAAA, got {:?}", other),
    }
    match &decoded.answers[1] {
        DnsRecord::MX {
            preference,
            exchange,
            ..
        } => {
            assert_eq!(*preference, 10);
            assert_eq!(exchange, "mail.example.com");
        }
        other => panic!("expected MX, got {:?}", other),
    }
    match &decoded.answers[2] {
        DnsRecord::TXT { text, .. } => assert_eq!(text, "v=spf1 -all"),
        other => panic!("expected TXT, got {:?}", other),
    }
}

/// NS and SOA answer records must survive an encode/decode round-trip.
#[test]
fn test_ns_soa_round_trip() {
    let answers = vec![
        DnsRecord::NS {
            domain: "example.com".to_string(),
            nameserver: "ns1.example.com".to_string(),
            ttl: 3600,
        },
        DnsRecord::SOA {
            domain: "example.com".to_string(),
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 2024_01_01,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600,
            ttl: 3600,
        },
    ];

    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x4243,
            flags: 0x8180,
            questions: 0,
            answers: answers.len() as u16,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };

    let decoded = DnsPacket::from_bytes(&packet.to_bytes()).unwrap();
    match &decoded.answers[0] {
        DnsRecord::NS { nameserver, .. } => assert_eq!(nameserver, "ns1.example.com"),
        other => panic!("expected NS, got {:?}", other),
    }
    match &decoded.answers[1] {
        DnsRecord::SOA {
            mname,
            rname,
            serial,
            minimum,
            ..
        } => {
            assert_eq!(mname, "ns1.example.com");
            assert_eq!(rname, "admin.example.com");
            assert_eq!(*serial, 2024_01_01);
            assert_eq!(*minimum, 3600);
        }
        other => panic!("expected SOA, got {:?}", other),
    }
}

/// SRV, PTR and CAA answer records must survive an encode/decode round-trip.
#[test]
fn test_srv_ptr_caa_round_trip() {
    let answers = vec![
        DnsRecord::SRV {
            domain: "_sip._tcp.example.com".to_string(),
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com".to_string(),
            ttl: 3600,
        },
        DnsRecord::PTR {
            domain: "1.2.0.192.in-addr.arpa".to_string(),
            ptrdname: "host.example.com".to_string(),
            ttl: 3600,
        },
        DnsRecord::CAA {
            domain: "example.com".to_string(),
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
            ttl: 3600,
        },
    ];
    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x4244,
            flags: 0x8180,
            questions: 0,
            answers: answers.len() as u16,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };

    let decoded = DnsPacket::from_bytes(&packet.to_bytes()).unwrap();
    assert_eq!(decoded.answers.len(), 3);
    match &decoded.answers[0] {
        DnsRecord::SRV {
            priority,
            weight,
            port,
            target,
            ..
        } => {
            assert_eq!((*priority, *weight, *port), (10, 60, 5060));
            assert_eq!(target, "sip.example.com");
        }
        other => panic!("expected SRV, got {:?}", other),
    }
    match &decoded.answers[1] {
        DnsRecord::PTR { ptrdname, .. } => assert_eq!(ptrdname, "host.example.com"),
        other => panic!("expected PTR, got {:?}", other),
    }
    match &decoded.answers[2] {
        DnsRecord::CAA { tag, value, .. } => {
            assert_eq!(tag, "issue");
            assert_eq!(value, "letsencrypt.org");
        }
        other => panic!("expected CAA, got {:?}", other),
    }
}

/// A query carrying an EDNS OPT record must get an OPT echoed in the response,
/// and the negotiated UDP size must be clamped to the server's maximum.
#[test]
fn test_edns_opt_echoed() {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );

    let query = DnsPacket {
        header: DnsHeader {
            id: 7,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 1,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![DnsRecord::OPT { udp_size: 4096 }],
    };
    assert_eq!(query.edns_udp_size(), Some(4096));

    let response = query.build_response(&zone);
    assert_eq!(response.answers.len(), 1);
    // 4096 is clamped to the server's max (1232).
    assert_eq!(response.edns_udp_size(), Some(1232));

    // The OPT must survive encoding (it appears in the additional section).
    let decoded = DnsPacket::from_bytes(&response.to_bytes()).unwrap();
    assert_eq!(decoded.edns_udp_size(), Some(1232));
}

/// Helper to build an A query for `name`.
fn a_query(name: &str) -> DnsPacket {
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
            qtype: 1, // A
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

/// A query for a CNAME's owner should return the CNAME plus the resolved target.
#[test]
fn test_cname_chaining() {
    let mut zone = Zone::new();
    zone.insert(
        "www.example.com".to_string(),
        vec![DnsRecord::CNAME {
            domain: "www.example.com".to_string(),
            alias: "example.com".to_string(),
            ttl: 3600,
        }],
    );
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );

    let response = a_query("www.example.com").build_response(&zone);
    assert_eq!(response.answers.len(), 2);
    assert!(matches!(response.answers[0], DnsRecord::CNAME { .. }));
    match &response.answers[1] {
        DnsRecord::A { addr, domain, .. } => {
            assert_eq!(addr.to_string(), "192.0.2.1");
            assert_eq!(domain, "example.com");
        }
        other => panic!("expected resolved A record, got {:?}", other),
    }
}

/// A wildcard record should match any subdomain, with the answer's owner name
/// rewritten to the queried name.
#[test]
fn test_wildcard_match() {
    let mut zone = Zone::new();
    zone.insert(
        "*.example.com".to_string(),
        vec![DnsRecord::A {
            domain: "*.example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 9),
            ttl: 3600,
        }],
    );

    let response = a_query("anything.example.com").build_response(&zone);
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0] {
        DnsRecord::A { addr, domain, .. } => {
            assert_eq!(addr.to_string(), "192.0.2.9");
            // Owner name is the queried name, not the stored wildcard.
            assert_eq!(domain, "anything.example.com");
        }
        other => panic!("expected A record, got {:?}", other),
    }
    assert_eq!(response.header.flags & 0x0400, 0x0400); // authoritative
}

/// A packet whose name contains a compression pointer that targets itself must
/// be rejected instead of looping forever (DoS regression test).
#[test]
fn test_self_referential_pointer_does_not_hang() {
    let packet_bytes: &[u8] = &[
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers
        0x00, 0x00, // Authorities
        0x00, 0x00, // Additionals
        // Question name: a pointer at offset 12 pointing back to offset 12.
        0xC0, 0x0C,
    ];

    let result = DnsPacket::from_bytes(packet_bytes);
    assert!(result.is_err(), "expected an error, got {:?}", result);
}

/// A query whose name differs only in case must still match the zone.
#[test]
fn test_lookup_is_case_insensitive() {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );

    let query = DnsPacket {
        header: mini_dns::dns::header::DnsHeader {
            id: 1,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: "EXAMPLE.COM".to_string(),
            qtype: 1, // A
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let response = query.build_response(&zone);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.header.flags & 0x0400, 0x0400); // AA bit set
}

/// A query for a type the zone has no records of returns NODATA (NOERROR, 0
/// answers), while a query for a type that exists returns only matching records.
#[test]
fn test_qtype_filtering() {
    let mut zone = Zone::new();
    zone.insert(
        "example.com".to_string(),
        vec![DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 3600,
        }],
    );

    let make_query = |qtype: u16| DnsPacket {
        header: mini_dns::dns::header::DnsHeader {
            id: 1,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    // A query (type 1) matches the A record.
    let a_resp = make_query(1).build_response(&zone);
    assert_eq!(a_resp.answers.len(), 1);

    // AAAA query (type 28): name exists but no matching type -> NODATA.
    let aaaa_resp = make_query(28).build_response(&zone);
    assert_eq!(aaaa_resp.answers.len(), 0);
    assert_eq!(aaaa_resp.header.flags & 0x000F, 0); // NOERROR
    assert_eq!(aaaa_resp.header.flags & 0x0400, 0x0400); // still authoritative
}

/// A query for a name not in the zone returns NXDOMAIN.
#[test]
fn test_nxdomain() {
    let zone = Zone::new();
    let query = DnsPacket {
        header: mini_dns::dns::header::DnsHeader {
            id: 1,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
        questions: vec![DnsQuestion {
            qname: "nope.example.com".to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let response = query.build_response(&zone);
    assert_eq!(response.answers.len(), 0);
    assert_eq!(response.header.flags & 0x000F, 3); // NXDOMAIN
    assert_eq!(response.header.flags & 0x0400, 0); // not authoritative
}