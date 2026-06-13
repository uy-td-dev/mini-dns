//! Tiny closed-loop UDP load tester for mini-dns.
//!
//! Usage: `cargo run --release --example loadtest -- [addr] [seconds] [concurrency]`
//! Each task repeatedly sends an `example.com A` query and waits for the reply,
//! counting successful round-trips. Reported QPS is indicative (localhost,
//! closed-loop, client and server share the same machine).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8861".to_string());
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let concurrency: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);

    // A fixed "example.com A" query.
    let query: Vec<u8> = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];

    let count = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let started = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let addr = addr.clone();
        let query = query.clone();
        let count = Arc::clone(&count);
        handles.push(tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.connect(&addr).await.unwrap();
            let mut buf = [0u8; 512];
            while Instant::now() < deadline {
                if sock.send(&query).await.is_err() {
                    break;
                }
                if let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await
                {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed().as_secs_f64();
    let total = count.load(Ordering::Relaxed);
    println!(
        "queries={total} duration={elapsed:.1}s concurrency={concurrency} qps={:.0}",
        total as f64 / elapsed
    );
}
