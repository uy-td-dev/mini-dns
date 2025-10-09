use mini_dns::dns::packet::DnsPacket;
use mini_dns::dns::question::DnsQuestion;

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