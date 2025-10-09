use mini_dns::config::load_zone_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_load_zone_file() {
    let mut zone_file = NamedTempFile::new().unwrap();
    writeln!(zone_file, "example.com. 3600 A 192.0.2.1").unwrap();
    writeln!(zone_file, "www.example.com. 3600 CNAME example.com.").unwrap();
    let path = zone_file.path().to_str().unwrap();

    let zone = load_zone_file(path).unwrap();

    assert_eq!(zone.len(), 2);
    assert!(zone.contains_key("example.com"));
    assert!(zone.contains_key("www.example.com"));

    let a_record = &zone["example.com"][0];
    if let mini_dns::dns::record::DnsRecord::A { domain, addr, ttl } = a_record {
        assert_eq!(domain, "example.com");
        assert_eq!(addr.to_string(), "192.0.2.1");
        assert_eq!(*ttl, 3600);
    } else {
        panic!("Expected A record");
    }

    let cname_record = &zone["www.example.com"][0];
    if let mini_dns::dns::record::DnsRecord::CNAME { domain, alias, ttl } = cname_record {
        assert_eq!(domain, "www.example.com");
        assert_eq!(alias, "example.com");
        assert_eq!(*ttl, 3600);
    } else {
        panic!("Expected CNAME record");
    }
}