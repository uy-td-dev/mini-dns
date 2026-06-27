//! # Mini DNS
//!
//! A lightweight DNS server implementation in Rust.

pub mod acl;
pub mod blocklist;
pub mod cache;
pub mod config;
pub mod dns;
pub mod dnssec;
pub mod doh;
pub mod doq;
pub mod forwarder;
pub mod metrics;
pub mod ratelimit;
pub mod recursive;
pub mod server;
pub mod state;
pub mod tls;
