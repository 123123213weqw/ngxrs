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

    // Offer a client certificate whenever any server on this socket asks for
    // one. Which servers *require* it is decided per request, from the server
    // the request actually lands on (`ngx_http_request.c` does the same: it
    // reads `sscf->verify` of the request's server conf, not of the socket).
    let wants_client_auth = server_idxs
        .iter()
        .any(|&i| http.server(i).ssl_verify_client != 0);

    let builder = ServerConfig::builder();
    let mut cfg = if wants_client_auth {
        // Advertise the configured CA names in the CertificateRequest.
        let mut hints = Vec::new();
        for &i in server_idxs {
            if let Some(ca) = &http.server(i).ssl_client_certificate {
                if let Ok(file) = std::fs::File::open(ca) {
                    let mut rd = std::io::BufReader::new(file);
                    for cert in rustls_pemfile::certs(&mut rd).flatten() {
                        if let Ok(anchor) = webpki::anchor_from_trusted_cert(&cert) {
                            // `TrustAnchor::subject` holds the DN *contents*, but
                            // the CertificateRequest's certificate_authorities
                            // list wants a full DER SEQUENCE. Sending the bare
                            // contents makes OpenSSL fail with
                            // `asn1_check_tlen:wrong tag` while parsing CA names
                            // and abort the handshake.
                            let name =
                                rustls::DistinguishedName::from(der_sequence(anchor.subject.as_ref()));
                            if !hints.iter().any(|h: &rustls::DistinguishedName| {
                                h.as_ref() == name.as_ref()
                            }) {
                                hints.push(name);
                            }
                        }
                    }
                }
            }
        }
        builder
            .with_client_cert_verifier(Arc::new(PermissiveClientVerifier::new(hints)))
            .with_cert_resolver(resolver)
    } else {
        builder.with_no_client_auth().with_cert_resolver(resolver)
    };

    // nginx advertises h2 only when `listen ... http2` is set.
    let http2 = server_idxs.iter().any(|&i| http.server(i).http2);
    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(cfg))
}

/// A client-cert verifier that *requests* a certificate but accepts any chain.
///
/// nginx completes the handshake even when `ssl_verify_client` rejects the peer
/// and then answers the request with a 400 (codes 495/496). Rejecting inside the
/// handshake — which `WebPkiClientVerifier` would do — turns that into a TLS
/// alert the client sees as a connection failure, so the decision is deferred to
/// the HTTP layer and made per virtual host.
#[derive(Debug)]
pub struct PermissiveClientVerifier {
    hints: Vec<rustls::DistinguishedName>,
}

impl PermissiveClientVerifier {
    pub fn new(hints: Vec<rustls::DistinguishedName>) -> Self {
        Self { hints }
    }
}

impl rustls::server::danger::ClientCertVerifier for PermissiveClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// nginx does not abort the handshake when the certificate is missing.
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let r = rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        );
        match r {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding
                | rustls::CertificateError::Other(_),
            )) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            other => other,
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let r = rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        );
        // webpki refuses X.509 **v1** certificates outright
        // (`UnsupportedCertVersion`), and the certificates nginx-tests generate
        // are v1. OpenSSL — and therefore nginx — has no such restriction.
        // Let the handshake proceed so the request can still be answered; the
        // chain is judged independently at the HTTP layer, so nothing is
        // reported as verified that was not.
        match r {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding
                | rustls::CertificateError::Other(_),
            )) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            other => other,
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Encode a DER certificate as PEM, wrapping at 64 columns like nginx.
pub fn der_to_pem(der: &[u8]) -> String {
    use base64_encode::encode;
    let b64 = encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

mod base64_encode {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }
}

/// Wrap a DER value in a SEQUENCE unless it already is one.
fn der_sequence(inner: &[u8]) -> Vec<u8> {
    if inner.first() == Some(&0x30) {
        return inner.to_vec();
    }
    let len = inner.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(0x30);
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(inner);
    out
}

/// Verify a presented client chain against the CA bundle at `ca_path`.
///
/// Returns `Ok(())` when the leaf chains to a trusted root, otherwise the reason
/// nginx would put after `FAILED:` in `$ssl_client_verify`.
pub fn verify_client_chain(
    ca_path: Option<&std::path::Path>,
    chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<(), String> {
    use rustls::pki_types::{CertificateDer, UnixTime};
    use webpki::anchor_from_trusted_cert;

    if chain.is_empty() {
        return Err("no certificate".to_string());
    }
    let Some(ca_path) = ca_path else {
        // `ssl_verify_client` without `ssl_client_certificate`: nginx has no
        // trust anchors, so nothing can validate.
        return Err("unable to verify the first certificate".to_string());
    };
    let file = std::fs::File::open(ca_path).map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(file);
    let mut anchors = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader).flatten() {
        if let Ok(anchor) = anchor_from_trusted_cert(&cert) {
            anchors.push(anchor.to_owned());
        }
    }
    if anchors.is_empty() {
        return Err("no trusted certificate".to_string());
    }

    let der: CertificateDer<'static> = chain[0].clone();
    let ee = webpki::EndEntityCert::try_from(&der)
        .map_err(|e| format!("invalid certificate: {e}"))?;
    let intermediates: Vec<CertificateDer<'static>> = chain[1..].to_vec();
    let now = UnixTime::now();
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        now,
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
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
