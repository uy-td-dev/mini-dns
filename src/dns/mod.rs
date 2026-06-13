//! The `dns` module contains the core components for handling DNS packets,
//! including structures for the header, questions, and records.

pub mod encoder;
pub mod error;
pub mod header;
pub mod packet;
pub mod question;
pub mod record;
pub mod resolver;