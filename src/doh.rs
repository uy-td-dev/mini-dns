//! DNS-over-HTTPS (RFC 8484) support, served via `hyper` (HTTP/1.1 and HTTP/2).
//!
//! Implements the `/dns-query` endpoint:
//! - `POST` with an `application/dns-message` body (raw DNS query), or
//! - `GET /dns-query?dns=<base64url>` (RFC 4648 §5, no padding).
//!
//! The response carries the raw DNS message as `application/dns-message`. HTTP/2
//! lets a client multiplex many queries over a single kept-alive connection.

use crate::state::{ServerState, Transport};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{header, Request, Response, StatusCode};
use std::convert::Infallible;
use std::net::IpAddr;

/// Maximum DNS message size accepted in a request body.
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

/// Hyper service entry point: extracts the request, resolves it, and builds the
/// HTTP response. Always returns `Ok` (errors are mapped to HTTP statuses).
pub async fn handle_http(
    state: &ServerState,
    req: Request<Incoming>,
    client: IpAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_default();

    // Bound the body size to avoid unbounded buffering.
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(build_response(DohResponse::error(413))),
    };

    let result = resolve_http(state, &method, &target, &body, client).await;
    Ok(build_response(result))
}

/// Resolves a DoH request given its method, request target, and body.
///
/// Transport-agnostic core, kept separate from HTTP framing for unit testing.
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

/// Builds an HTTP response carrying an `application/dns-message` body.
fn build_response(result: DohResponse) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .body(Full::new(Bytes::from(result.body)))
        .expect("valid response")
}
