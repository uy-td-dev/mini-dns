mod server;
mod config;
mod dns;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::load_zone_file("zones/example.zone")?;
    server::run(config).await
}