//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

use anyhow::Result;
use mini_dns::config;
use mini_dns::server;

#[tokio::main]
async fn main() -> Result<()> {
    // Load the zone file into a `Zone` configuration.
    let config = config::load_zone_file("zones/example.zone")?;

    // Start the DNS server with the loaded configuration.
    server::run(config).await
}