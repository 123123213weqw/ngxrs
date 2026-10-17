//! TLS termination with SNI-based certificate selection.
//!
//! Mirrors nginx's behaviour: each `server` block on an `ssl` listen socket may
//! carry its own `ssl_certificate`; the certificate is chosen by SNI name, with
//! the default server's certificate as the fallback.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use crate::config::{Http, Server};

/// Selects a certificate by SNI name, falling back to the default server.
#[derive(Debug)]
pub struct SniResolver {
    /// Exact name -> key.
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `*.example.com` style wildcards, keyed without the leading `*.`.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

/// nginx's lookup order: exact name, then single-label wildcard, then default.
fn select<'a, T>(
    exact: &'a HashMap<String, T>,
    wildcard: &'a HashMap<String, T>,
    default: &'a Option<T>,
    name: Option<&str>,
) -> Option<&'a T> {
    if let Some(name) = name {
        let lower = name.to_ascii_lowercase();
        if let Some(k) = exact.get(&lower) {
            return Some(k);
        }
        if let Some((_, rest)) = lower.split_once('.') {
            if let Some(k) = wildcard.get(rest) {
                return Some(k);
            }
        }
    }
    default.as_ref()
}

impl SniResolver {
    fn pick(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        select(&self.exact, &self.wildcard, &self.default, name).cloned()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.pick(hello.server_name())
    }
}

fn load_cert(key_path: &Path, cert_path: &Path) -> io::Result<Arc<CertifiedKey>> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read ssl_certificate {}: {e}", cert_path.display()),
        )
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read ssl_certificate_key {}: {e}", key_path.display()),
        )
    })?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad certificate: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no PEM certificate in {}", cert_path.display()),
        ));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad private key: {e}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no private key in {}", key_path.display()),
            )
        })?;

    let signing = ring::sign::any_supported_type(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// Build the TLS configuration for one listen socket.
pub fn build_config(http: &Http, server_idxs: &[usize]) -> io::Result<Arc<ServerConfig>> {
    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for &idx in server_idxs {
        let server: &Server = http.server(idx);
        let (cert, key) = match (&server.ssl_certificate, &server.ssl_certificate_key) {
            (Some(c), Some(k)) => (c, k),
            _ => continue,
        };
        let key_id = load_cert(key, cert)?;
        for name in &server.names {
            let lower = name.to_ascii_lowercase();
            if lower.is_empty() || lower == "_" || lower.starts_with('~') {
                continue;
            }
            if let Some(rest) = lower.strip_prefix("*.") {
                wildcard.insert(rest.to_string(), key_id.clone());
            } else if let Some(rest) = lower.strip_prefix('.') {
                // nginx treats `.example.com` as both exact and wildcard
                exact.insert(lower.clone(), key_id.clone());
                wildcard.insert(rest.to_string(), key_id.clone());
            } else {
                exact.insert(lower, key_id.clone());
            }
        }
        if default.is_none() {
            default = Some(key_id);
        }
    }

    let resolver = Arc::new(SniResolver {
        exact,
        wildcard,
        default,
    });

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // nginx advertises h2 only when `listen ... http2` is set.
    let http2 = server_idxs.iter().any(|&i| http.server(i).http2);
    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(cfg))
}

/// Install the default crypto provider once per process.
pub fn init_crypto() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_selection_order() {
        let exact = HashMap::from([("a.example.com".to_string(), 1u8)]);
        let wildcard = HashMap::from([("example.com".to_string(), 2u8)]);
        let default = Some(3u8);

        assert_eq!(select(&exact, &wildcard, &default, Some("A.Example.COM")), Some(&1));
        assert_eq!(select(&exact, &wildcard, &default, Some("b.example.com")), Some(&2));
        // a wildcard covers exactly one label
        assert_eq!(select(&exact, &wildcard, &default, Some("x.b.example.com")), Some(&3));
        assert_eq!(select(&exact, &wildcard, &default, None), Some(&3));
    }

    #[test]
    fn missing_default_returns_none() {
        let exact: HashMap<String, u8> = HashMap::new();
        let wildcard: HashMap<String, u8> = HashMap::new();
        let default = None;
        assert_eq!(select(&exact, &wildcard, &default, Some("nope")), None);
    }
}
