use crate::config::Zone;
use crate::dns::packet::DnsPacket;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// `run` starts the DNS server and listens for incoming queries.
///
/// The server binds to a UDP socket and enters a loop to handle DNS requests concurrently.
/// Each request is processed in its own Tokio task to ensure the server remains responsive.
pub async fn run(zone: Zone) -> Result<()> {
    let zone = Arc::new(zone);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:8888").await?);
    println!("DNS server listening on 127.0.0.1:8888");

    let mut buf = [0u8; 512];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req_buf = buf[..len].to_vec();

        let zone = Arc::clone(&zone);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            match DnsPacket::from_bytes(&req_buf) {
                Ok(request) => {
                    println!("Received DNS query for: {:?}", request.questions);
                    let response = request.build_response(&zone);
                    let resp_buf = response.to_bytes();
                    if let Err(e) = socket.send_to(&resp_buf, addr).await {
                        eprintln!("Failed to send response: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse DNS packet: {}", e);
                }
            }
        });
    }
}