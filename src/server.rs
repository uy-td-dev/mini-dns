use crate::config::Zone;
use crate::dns::packet::DnsPacket;
use anyhow::Result;
use tokio::net::UdpSocket;

pub async fn run(zone: Zone) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8888").await?;
    println!("Received DNS query for: {:?}", "he;;p");
    let mut buf = [0u8; 512];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let req = DnsPacket::from_bytes(&buf[..len]);
        println!("Received DNS query for: {:?}", "he;;p");

        if let Ok(request) = req {
            println!("Received DNS query for: {:?}", request.questions);

            let response = request.build_response(&zone);
            let resp_buf = response.to_bytes();
            socket.send_to(&resp_buf, addr).await?;
        }
    }
}