//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

pub mod cache;
pub mod config;
pub mod dns;
pub mod forwarder;
pub mod metrics;
pub mod ratelimit;
pub mod server;
pub mod state;
