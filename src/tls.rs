//! TLS setup for DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH).
//!
//! A certificate and key are loaded from PEM files when both paths are given;
//! otherwise a self-signed certificate for `localhost` is generated at startup
//! (handy for local testing).

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::fs;
use std::sync::Arc;

/// A ready-to-use TLS configuration plus the leaf certificate (DER), which lets
/// tests build a client that trusts the (possibly self-signed) certificate.
pub struct TlsAssets {
    pub config: Arc<ServerConfig>,
    pub cert_der: CertificateDer<'static>,
}

/// Builds a TLS server configuration advertising the given ALPN protocols.
///
/// If both `cert_path` and `key_path` are provided, the certificate chain and
/// key are loaded from those PEM files; otherwise a self-signed certificate is
/// generated for `localhost`.
pub fn build(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    alpn: Vec<Vec<u8>>,
) -> Result<TlsAssets> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_pem(c, k)?,
        _ => generate_self_signed()?,
    };
    let cert_der = certs
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no certificate found"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to set TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid certificate/key pair")?;
    config.alpn_protocols = alpn;

    Ok(TlsAssets {
        config: Arc::new(config),
        cert_der,
    })
}

/// Loads a certificate chain and private key from PEM files.
fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = fs::read(cert_path).with_context(|| format!("reading {cert_path}"))?;
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in {cert_path}"));
    }

    let key_pem = fs::read(key_path).with_context(|| format!("reading {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .context("parsing private key PEM")?
        .ok_or_else(|| anyhow!("no private key in {key_path}"))?;

    Ok((certs, key))
}

/// Generates a self-signed certificate and key for `localhost`.
fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generating self-signed certificate")?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));
    Ok((vec![cert_der], key_der))
}
