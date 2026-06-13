//! Minimal DNS-over-HTTPS (RFC 8484) support over HTTP/1.1.
//!
//! Implements the `/dns-query` endpoint:
//! - `POST` with an `application/dns-message` body (raw DNS query), or
//! - `GET /dns-query?dns=<base64url>` (RFC 4648 §5, no padding).
//!
//! The response carries the raw DNS message as `application/dns-message`. This
//! is an HTTP/1.1-only implementation intended for local use and demonstration;
//! clients that require HTTP/2 (e.g. browsers) are out of scope.

use crate::state::{ServerState, Transport};
use anyhow::Result;
use base64::Engine;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size of the request head (request line + headers) we will buffer.
const MAX_HEAD: usize = 16 * 1024;
/// Maximum DNS message size we will accept in a request body.
const MAX_BODY: usize = 64 * 1024;

/// The outcome of handling a DoH request: an HTTP status and a DNS message body.
pub struct DohResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl DohResponse {
    fn error(status: u16) -> Self {
        DohResponse {
            status,
            body: Vec::new(),
        }
    }
}

/// Resolves a DoH request given its method, request target, and body.
///
/// This is the transport-agnostic core, kept separate from socket/HTTP framing
/// so it can be unit-tested directly.
pub async fn resolve_http(
    state: &ServerState,
    method: &str,
    target: &str,
    body: &[u8],
    client: IpAddr,
) -> DohResponse {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    if path != "/dns-query" {
        return DohResponse::error(404);
    }

    let query_bytes = match method {
        "POST" => body.to_vec(),
        "GET" => match query.and_then(extract_dns_param) {
            Some(decoded) => decoded,
            None => return DohResponse::error(400),
        },
        _ => return DohResponse::error(405),
    };

    if query_bytes.is_empty() || query_bytes.len() > MAX_BODY {
        return DohResponse::error(400);
    }

    // DoH runs over HTTP, so there is no 512-byte UDP limit.
    match state.resolve(&query_bytes, client, Transport::Tcp).await {
        Some(dns_response) => DohResponse {
            status: 200,
            body: dns_response,
        },
        None => DohResponse::error(400),
    }
}

/// Extracts and base64url-decodes the `dns` parameter from a query string.
fn extract_dns_param(query: &str) -> Option<Vec<u8>> {
    let value = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
}

/// Reads one HTTP/1.1 request from `stream`, resolves it, and writes the
/// response. The connection is closed afterwards (no keep-alive).
pub async fn handle_connection<S>(state: &ServerState, mut stream: S, client: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    // Read until the end of the request head.
    let head_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // connection closed before a full request
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD {
            return write_response(&mut stream, &DohResponse::error(431)).await;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    if content_length > MAX_BODY {
        return write_response(&mut stream, &DohResponse::error(413)).await;
    }

    // Collect the body (some bytes may already be buffered after the head).
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    let response = resolve_http(state, &method, &target, &body, client).await;
    write_response(&mut stream, &response).await
}

/// Writes an HTTP/1.1 response carrying an `application/dns-message` body.
async fn write_response<S>(stream: &mut S, response: &DohResponse) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    if !response.body.is_empty() {
        stream.write_all(&response.body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Returns the index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
