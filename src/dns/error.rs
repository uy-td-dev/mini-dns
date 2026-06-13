//! Errors returned while parsing DNS messages from the wire.

use std::fmt;

/// An error encountered while parsing a DNS message off the wire.
///
/// Parsing runs on the hot path — one attempt per inbound datagram, including
/// malformed ones — so every variant is `Copy` and carries only static data.
/// Unlike a formatted `anyhow` error, constructing one allocates nothing, so a
/// flood of malformed packets can't turn into a flood of error-string
/// allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// A length/bounds check failed while reading the named field.
    Truncated {
        /// Which field was being read (a static label, for diagnostics).
        what: &'static str,
    },
    /// A resource record's rdata length was invalid for its type.
    InvalidRdata {
        /// The numeric record type whose rdata was malformed.
        rtype: u16,
    },
    /// Too many compression pointers were followed (a likely pointer loop).
    PointerLoop,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Truncated { what } => {
                write!(f, "message truncated while reading {what}")
            }
            DnsError::InvalidRdata { rtype } => {
                write!(f, "invalid rdata length for record type {rtype}")
            }
            DnsError::PointerLoop => {
                write!(f, "too many compression pointers (possible pointer loop)")
            }
        }
    }
}

impl std::error::Error for DnsError {}

/// Convenience alias for results produced by the DNS wire parser.
pub type Result<T> = std::result::Result<T, DnsError>;
