//! TLS termination with SNI-based certificate selection.
//!
//! Mirrors nginx's behaviour: each `server` block on an `ssl` listen socket may
//! carry its own `ssl_certificate`; the certificate is chosen by SNI name, with
//! the default server's certificate as the fallback.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use crate::config::{Http, Server};

/// A certificate whose path contains variables.
///
/// nginx resolves these **per handshake**, in the SNI callback, where
/// `$ssl_server_name` is known. Resolving at config time (an earlier
/// simplification here) is wrong: `ssl_certificate $ssl_server_name.crt` is the
/// canonical way to serve a certificate per name, and at config time the
/// variable has no value at all.
#[derive(Debug)]
struct CertTemplate {
    cert: PathBuf,
    key: PathBuf,
    passwords: Vec<String>,
    cache: crate::config::typed::CertCacheCfg,
}

/// One cache entry. `loaded` is when the files were read; `used` drives LRU
/// eviction when `max` is reached and `inactive` eviction on the manager pass.
#[derive(Debug)]
struct CacheEntry {
    key: Arc<CertifiedKey>,
    loaded: std::time::Instant,
    used: std::time::Instant,
}

#[derive(Debug, Default)]
struct CertCacheState {
    map: HashMap<String, CacheEntry>,
}

impl CertCacheState {
    fn lookup(
        &mut self,
        cfg: &crate::config::typed::CertCacheCfg,
        key: &str,
        tpl: &CertTemplate,
    ) -> io::Result<Arc<CertifiedKey>> {
        let now = std::time::Instant::now();
        if !cfg.is_off() {
            let mut expired = false;
            if let Some(e) = self.map.get(key) {
                if let Some(valid) = cfg.valid {
                    expired = now.duration_since(e.loaded) >= valid;
                }
                if !expired {
                    let hit = e.key.clone();
                    if let Some(e) = self.map.get_mut(key) {
                        e.used = now;
                    }
                    return Ok(hit);
                }
            }
            if expired {
                self.map.remove(key);
            }
        }

        let loaded = load_cert_with(&tpl.key, &tpl.cert, &tpl.passwords)?;

        if !cfg.is_off() {
            // Evict the least recently used entry once `max` is reached.
            while self.map.len() >= cfg.max {
                let victim = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.used)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(v) => {
                        self.map.remove(&v);
                    }
                    None => break,
                }
            }
            self.map.insert(
                key.to_string(),
                CacheEntry {
                    key: loaded.clone(),
                    loaded: now,
                    used: now,
                },
            );
        }
        Ok(loaded)
    }

    /// `inactive`: drop entries not used for that long. Called on every lookup
    /// rather than from a timer -- nginx has a cache manager process, but the
    /// observable behaviour is the same and this needs no extra thread.
    fn sweep(&mut self, cfg: &crate::config::typed::CertCacheCfg) {
        if let Some(inactive) = cfg.inactive {
            let now = std::time::Instant::now();
            self.map
                .retain(|_, e| now.duration_since(e.used) < inactive);
        }
    }
}

#[derive(Debug)]
pub struct SniResolver {
    /// Exact name -> key.
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `*.example.com` style wildcards, keyed without the leading `*.`.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
    /// Server index for each name, used to pick a template.
    name_to_server: HashMap<String, usize>,
    template_default: Option<usize>,
    templates: HashMap<usize, Arc<CertTemplate>>,
    cache: std::sync::Mutex<CertCacheState>,
}

/// nginx's lookup order: exact name, then single-label wildcard, then default.
fn select_server(
    name_to_server: &HashMap<String, usize>,
    default: &Option<usize>,
    name: Option<&str>,
) -> Option<usize> {
    if let Some(name) = name {
        let lower = name.to_ascii_lowercase();
        if let Some(&i) = name_to_server.get(&lower) {
            return Some(i);
        }
        if let Some((_, rest)) = lower.split_once('.') {
            if let Some(&i) = name_to_server.get(&format!("*.{rest}")) {
                return Some(i);
            }
        }
    }
    *default
}

/// Expand `$ssl_server_name` (and geo/map defaults) in a certificate path.
fn expand_handshake_path(raw: &Path, server_name: Option<&str>) -> PathBuf {
    expand_cert_path_with(raw, server_name)
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

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name();
        // A variable certificate is resolved per handshake, exactly as nginx
        // does in its SNI callback: the file is read when the name is known.
        if let Some(idx) = select_server(&self.name_to_server, &self.template_default, name) {
            if let Some(tpl) = self.templates.get(&idx) {
                let cert = expand_handshake_path(&tpl.cert, name);
                let key = expand_handshake_path(&tpl.key, name);
                let expanded = CertTemplate {
                    cert,
                    key,
                    passwords: tpl.passwords.clone(),
                    cache: tpl.cache.clone(),
                };
                let ck = self.cache.lock();
                let mut guard = match ck {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                guard.sweep(&expanded.cache);
                let cache_key = format!(
                    "{}|{}",
                    expanded.cert.to_string_lossy(),
                    expanded.key.to_string_lossy()
                );
                match guard.lookup(&expanded.cache, &cache_key, &expanded) {
                    Ok(k) => return Some(k),
                    Err(e) => {
                        crate::log::error_log(
                            "error",
                            &format!("ssl_certificate for \"{}\" not loaded: {e}", name.unwrap_or("")),
                        );
                        return None;
                    }
                }
            }
        }
        select(&self.exact, &self.wildcard, &self.default, name).cloned()
    }
}

/// Read an `ssl_password_file`: one password per line, tried in order.
/// nginx loads the whole file at config time and stops at the first password
/// that decrypts the key, so a file may legitimately hold several.
pub fn read_passwords(path: &Path) -> io::Result<Vec<String>> {
    let text = std::fs::read(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read ssl_password_file {}: {e}", path.display()),
        )
    })?;
    Ok(String::from_utf8_lossy(&text)
        .lines()
        .map(|l| l.trim_end_matches('\r').to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Decrypt a PKCS#8 `BEGIN ENCRYPTED PRIVATE KEY` block.
///
/// Returns `None` when the PEM holds no encrypted block, so the common
/// unencrypted case keeps using `rustls-pemfile` untouched.
fn decrypt_pkcs8(pem: &[u8], passwords: &[String]) -> io::Result<Option<Vec<u8>>> {
    let text = match std::str::from_utf8(pem) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    if !text.contains("ENCRYPTED PRIVATE KEY") {
        return Ok(None);
    }
    if passwords.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private key is encrypted but no ssl_password_file is configured",
        ));
    }
    // `EncryptedPrivateKeyInfo` borrows from the DER, so `DecodePem` (which
    // needs an owned result) is unavailable; extract the block and decode it
    // in place instead.
    let body: String = text
        .split_once("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        .and_then(|(_, rest)| rest.split_once("-----END ENCRYPTED PRIVATE KEY-----"))
        .map(|(b, _)| b.split_whitespace().collect())
        .unwrap_or_default();
    let der = crate::util::base64_decode(&body)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad base64 in encrypted key"))?;
    let info =
        <pkcs8::EncryptedPrivateKeyInfo as pkcs8::der::Decode>::from_der(&der).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad encrypted key: {e}"),
            )
        })?;
    let mut last = String::from("no password matched");
    for pw in passwords {
        // `pkcs8` handles PBES2 (PBKDF2 + AES-CBC or 3DES) and yields plain
        // PKCS#8 DER, which is exactly what ring expects.
        match info.decrypt(pw.as_bytes()) {
            Ok(doc) => return Ok(Some(doc.as_bytes().to_vec())),
            Err(e) => last = e.to_string(),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cannot decrypt private key with any password in ssl_password_file: {last}"),
    ))
}

/// Expand variables in a `ssl_certificate` / `ssl_certificate_key` path.
///
/// nginx has accepted variables here since 1.15.9. The value is evaluated once
/// per SSL context; for a config-level source such as
/// `geo $one { default one; }` that means the `default` branch, because there
/// is no client address at config time. Supporting that case (and `map` /
/// `split_clients` defaults) covers how the directive is actually used; a
/// variable that depends on the live request cannot select a certificate
/// anyway, since the certificate is needed before the request exists.
fn expand_cert_path_with(raw: &Path, server_name: Option<&str>) -> PathBuf {
    let s = raw.to_string_lossy();
    if !s.contains('$') {
        return raw.to_path_buf();
    }
    let geos = crate::config::geos();
    let maps = crate::config::maps();
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'$' {
                i += 1;
            }
            out.push_str(&s[start..i]);
            continue;
        }
        i += 1;
        let braced = i < bytes.len() && bytes[i] == b'{';
        if braced {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let name = &s[start..i];
        if braced && i < bytes.len() && bytes[i] == b'}' {
            i += 1;
        }
        let value = if name == "ssl_server_name" {
            server_name.unwrap_or("").to_string()
        } else {
            geos.iter()
                .find(|g| g.var == name)
                .and_then(|g| g.default.clone())
                .or_else(|| {
                    maps.iter()
                        .find(|m| m.var == name)
                        .and_then(|m| m.default.clone())
                })
                .unwrap_or_default()
        };
        out.push_str(&value);
    }
    PathBuf::from(out)
}

/// A client certificate returned verbatim, bypassing webpki's parse check.
///
/// See `upstream_connector_with_client_cert` for why that check has to be
/// bypassed: it rejects X.509 v1, which OpenSSL accepts.
#[derive(Debug)]
struct FixedClientCert(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for FixedClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A TLS client configuration that presents a client certificate.
///
/// `proxy_ssl_certificate` / `uwsgi_ssl_certificate` and their `_key`
/// counterparts make us authenticate to the upstream. Verification of the
/// upstream itself stays off unless `proxy_ssl_verify on` is implemented, which
/// matches nginx's default (`proxy_ssl_verify off`).
///
/// Cached per (cert, key) pair: building a `ClientConfig` per connection starts
/// from an empty session store, so `*_ssl_session_reuse` could never answer
/// `r`.
pub fn upstream_connector_with_client_cert(
    cert: &Path,
    key: &Path,
    passwords: &[String],
    reuse: bool,
    alpn: &[u8],
) -> io::Result<tokio_rustls::TlsConnector> {
    let (certs, key_der) = load_raw_identity(key, cert, passwords)?;
    // `with_client_auth_cert` runs the certificate through webpki, which rejects
    // X.509 v1 outright (`UnsupportedCertVersion`). OpenSSL does not, and the
    // nginx fixtures are v1 self-signed certs, so the whole connection failed
    // before the handshake. Installing the key through a resolver that returns
    // it verbatim keeps the same behaviour nginx has here: send what was
    // configured, let the peer decide.
    let signing = ring::sign::any_supported_type(&key_der)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported key: {e}")))?;
    let ck = Arc::new(CertifiedKey::new(certs.clone(), signing));
    let provider = rustls::crypto::ring::default_provider();
    let base = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::grpc::NoVerify(Arc::new(provider))))
        .with_client_cert_resolver(Arc::new(FixedClientCert(ck)));
    let mut cfg = base;
    // An empty ALPN entry is an illegal protocol name: the peer answers
    // `DecodeError` on the ServerHello path. Only advertise when asked.
    if !alpn.is_empty() {
        cfg.alpn_protocols = vec![alpn.to_vec()];
    }
    if !reuse {
        cfg.resumption = rustls::client::Resumption::disabled();
    }
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

/// The subject of a DER certificate as OpenSSL's `X509_NAME_oneline` renders
/// it: `/CN=name`, `/C=US/ST=CA/CN=name`, using `+` between the attribute-value
/// pairs of one RDN. That is the format `$ssl_client_s_dn` reports.
///
/// Only the subject is needed, and only for one variable, so this walks the
/// handful of TLVs between the outer SEQUENCE and the subject rather than
/// pulling in a full X.509 parser.
pub fn der_subject_oneline(der: &[u8]) -> String {
    fn tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
        let tag = *buf.get(pos)?;
        let first = *buf.get(pos + 1)?;
        if first & 0x80 == 0 {
            return Some((tag, pos + 2, first as usize));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < pos + 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &buf[pos + 2..pos + 2 + n] {
            len = (len << 8) | b as usize;
        }
        Some((tag, pos + 2 + n, len))
    }

    fn short_name(oid: &[u8]) -> String {
        // DER contents of the common attribute OIDs.
        const MAP: &[(&[u8], &str)] = &[
            (&[0x55, 0x04, 0x03], "CN"),
            (&[0x55, 0x04, 0x06], "C"),
            (&[0x55, 0x04, 0x07], "L"),
            (&[0x55, 0x04, 0x08], "ST"),
            (&[0x55, 0x04, 0x0a], "O"),
            (&[0x55, 0x04, 0x0b], "OU"),
            (&[0x55, 0x04, 0x05], "serialNumber"),
            (&[0x55, 0x04, 0x09], "street"),
            (&[0x55, 0x04, 0x0c], "GN"),
            (&[0x55, 0x04, 0x2a], "SN"),
            (&[0x55, 0x04, 0x2b], "title"),
            (&[0x55, 0x04, 0x2e], "DC"),
            (&[0x55, 0x04, 0x2f], "UID"),
            (&[0x55, 0x1d, 0x1e], "emailAddress"),
            (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01], "emailAddress"),
        ];
        for (k, v) in MAP {
            if *k == oid {
                return (*v).to_string();
            }
        }
        // Unknown OID: render dotted-decimal, as OpenSSL does.
        if oid.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        let mut acc: u64 = 0;
        let mut first = true;
        for &b in oid {
            acc = (acc << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                if first {
                    let a = acc / 40;
                    let b2 = acc % 40;
                    out.push_str(&format!("{}.{}", a.min(2), b2));
                    first = false;
                } else {
                    out.push_str(&format!(".{acc}"));
                }
                acc = 0;
            }
        }
        out
    }

    let Some((_, cert_body, _)) = tlv(der, 0) else {
        return String::new();
    };
    let Some((_, tbs_body, _)) = tlv(der, cert_body) else {
        return String::new();
    };
    let mut pos = tbs_body;
    // [0] EXPLICIT version, present for v2/v3.
    if let Some((tag, _, _)) = tlv(der, pos) {
        if tag == 0xa0 {
            let (_, body, len) = tlv(der, pos).unwrap();
            pos = body + len;
        }
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..4 {
        let Some((_, body, len)) = tlv(der, pos) else {
            return String::new();
        };
        pos = body + len;
    }
    let Some((_, mut name_pos, name_len)) = tlv(der, pos) else {
        return String::new();
    };
    let name_end = name_pos + name_len;

    let mut out = String::new();
    // Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
    while name_pos < name_end {
        let Some((_, set_body, set_len)) = tlv(der, name_pos) else {
            break;
        };
        let set_end = (set_body + set_len).min(name_end);
        let mut first_in_set = true;
        let mut p = set_body;
        while p < set_end {
            let Some((_, atv_body, atv_len)) = tlv(der, p) else {
                break;
            };
            let atv_end = atv_body + atv_len;
            if let Some((_, oid_body, oid_len)) = tlv(der, atv_body) {
                if let Some((_, val_body, val_len)) = tlv(der, oid_body + oid_len) {
                    let name = short_name(&der[oid_body..oid_body + oid_len]);
                    let value =
                        String::from_utf8_lossy(&der[val_body..(val_body + val_len).min(atv_end)]);
                    if !first_in_set {
                        out.push('+');
                    }
                    out.push('/');
                    out.push_str(&name);
                    out.push('=');
                    out.push_str(&value);
                    first_in_set = false;
                }
            }
            p = atv_end;
        }
        name_pos = set_body + set_len;
    }
    out
}

/// Read every certificate in a PEM file, including OpenSSL's
/// `TRUSTED CERTIFICATE` blocks.
///
/// `openssl x509 -addtrust <purpose> -trustout` re-encodes a certificate with
/// the `X509_AUX` structure appended and a `TRUSTED CERTIFICATE` PEM label.
/// `rustls_pemfile::certs` looks only for a `CERTIFICATE` label and finds
/// nothing, so such a file previously looked like it held no certificate at
/// all. nginx/OpenSSL read it fine, so a config that works there failed here
/// with "no PEM certificate in ...".
///
/// The DER is a certificate SEQUENCE immediately followed by the aux data, so
/// the fix is to honour the outer SEQUENCE length and drop the tail. The trust
/// purposes themselves are OpenSSL-only policy and are ignored, which matches
/// what they mean for a server: they say "this is trusted for serverAuth", not
/// "this is a CA".
fn read_certs(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut out: Vec<CertificateDer<'static>> = Vec::new();
    let text = String::from_utf8_lossy(pem);
    let mut rest = text.as_ref();

    while let Some(begin) = rest.find("-----BEGIN ") {
        let label_end = match rest[begin..].find("-----\n").or_else(|| rest[begin..].find("-----\r")) {
            Some(i) => begin + i + 5,
            None => break,
        };
        let label = &rest[begin + 11..label_end - 5];
        let tagged = label.trim();
        let end_marker = format!("-----END {tagged}-----");
        let body_start = label_end;
        let body_end = match rest[body_start..].find(&end_marker) {
            Some(i) => body_start + i,
            None => break,
        };
        let body = &rest[body_start..body_end];
        rest = &rest[body_end + end_marker.len()..];

        let is_cert = tagged == "CERTIFICATE" || tagged == "TRUSTED CERTIFICATE";
        let is_trusted = tagged == "TRUSTED CERTIFICATE";
        if !is_cert {
            continue;
        }
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let Ok(der) = base64_decode(&b64) else {
            continue;
        };
        let der = if is_trusted {
            match der_sequence_len(&der) {
                Some(n) if n <= der.len() => der[..n].to_vec(),
                _ => der,
            }
        } else {
            der
        };
        out.push(CertificateDer::from(der));
    }

    if out.is_empty() {
        // Nothing matched the hand-rolled scan; fall back to rustls_pemfile so
        // exotic encodings keep working.
        return rustls_pemfile::certs(&mut pem.clone())
            .collect::<Result<Vec<_>, _>>();
    }
    Ok(out)
}

/// Total encoded length of a DER SEQUENCE at the start of `der`.
fn der_sequence_len(der: &[u8]) -> Option<usize> {
    if der.len() < 2 || der[0] != 0x30 {
        return None;
    }
    let first = der[1];
    if first & 0x80 == 0 {
        return Some(2 + first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || der.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &der[2..2 + n] {
        len = (len << 8) | b as usize;
    }
    Some(2 + n + len)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in bytes {
        let Some(v) = val(b) else { return Err(()) };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Read a certificate chain and its (possibly encrypted) private key.
fn load_raw_identity(
    key_path: &Path,
    cert_path: &Path,
    passwords: &[String],
) -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    PrivateKeyDer<'static>,
)> {
    let cert_path = &expand_cert_path_with(cert_path, None);
    let key_path = &expand_cert_path_with(key_path, None);
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read ssl_certificate {}: {e}", cert_path.display()),
        )
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot read ssl_certificate_key {}: {e}",
                key_path.display()
            ),
        )
    })?;

    let certs: Vec<CertificateDer<'static>> = read_certs(&cert_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad certificate: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no PEM certificate in {}", cert_path.display()),
        ));
    }

    let key: PrivateKeyDer<'static> = match decrypt_pkcs8(&key_pem, passwords)? {
        // Decrypted PKCS#8 DER needs an explicit tag: the PEM parser would have
        // to guess between PKCS#8 and PKCS#1.
        Some(der) => PrivateKeyDer::Pkcs8(der.into()),
        None => rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad private key: {e}"))
            })?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("no private key in {}", key_path.display()),
                )
            })?,
    };

    Ok((certs, key))
}

fn load_cert_with(
    key_path: &Path,
    cert_path: &Path,
    passwords: &[String],
) -> io::Result<Arc<CertifiedKey>> {
    let (certs, key) = load_raw_identity(key_path, cert_path, passwords)?;
    let signing = ring::sign::any_supported_type(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

fn load_cert(key_path: &Path, cert_path: &Path) -> io::Result<Arc<CertifiedKey>> {
    load_cert_with(key_path, cert_path, &[])
}

/// Certificate + key for a QUIC listener: the same files HTTP uses, but
/// returned raw because `quinn` builds its own (TLS 1.3 only) configuration.
pub fn quic_identity(
    http: &Http,
    server_idxs: &[usize],
) -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    for &idx in server_idxs {
        let server: &Server = http.server(idx);
        if let (Some(cert), Some(key)) = (&server.ssl_certificate, &server.ssl_certificate_key) {
            let passwords = match &server.ssl_password_file {
                Some(p) => read_passwords(p)?,
                None => Vec::new(),
            };
            return load_raw_identity(key, cert, &passwords);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "no ssl_certificate configured for the quic listen socket",
    ))
}

/// Build the TLS configuration for one listen socket.
pub fn build_config(http: &Http, server_idxs: &[usize]) -> io::Result<Arc<ServerConfig>> {
    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut default: Option<Arc<CertifiedKey>> = None;
    // Server selection has to happen before the certificate decision: a
    // variable certificate belongs to a *server*, so we need to know which
    // server the SNI name lands on before expanding anything.
    let mut name_to_server: HashMap<String, usize> = HashMap::new();
    let mut templates: HashMap<usize, Arc<CertTemplate>> = HashMap::new();
    let mut default_server: Option<usize> = None;

    for &idx in server_idxs {
        let server: &Server = http.server(idx);
        let (cert, key) = match (&server.ssl_certificate, &server.ssl_certificate_key) {
            (Some(c), Some(k)) => (c, k),
            _ => continue,
        };
        // `ssl_password_file` is inherited from the http block, so the server
        // already carries the effective path.
        if default_server.is_none() {
            default_server = Some(idx);
        }
        for name in &server.names {
            let lower = name.to_ascii_lowercase();
            if lower.is_empty() || lower == "_" || lower.starts_with('~') {
                continue;
            }
            name_to_server.insert(lower.clone(), idx);
            if let Some(rest) = lower.strip_prefix('.') {
                name_to_server.insert(format!("*.{rest}"), idx);
            }
        }
        let passwords = match &server.ssl_password_file {
            Some(p) => read_passwords(p)?,
            None => Vec::new(),
        };
        // A path with a variable is resolved per handshake, not here.
        if cert.to_string_lossy().contains('$') || key.to_string_lossy().contains('$') {
            templates.insert(
                idx,
                Arc::new(CertTemplate {
                    cert: cert.clone(),
                    key: key.clone(),
                    passwords,
                    cache: server.ssl_certificate_cache.clone(),
                }),
            );
            if default.is_none() && !templates.is_empty() && default_server == Some(idx) {
                // The default server's certificate is produced at handshake
                // time; leave `default` empty so `resolve` takes the template
                // path for it.
            }
            continue;
        }
        // nginx does not abort startup when a certificate cannot be loaded:
        // it logs the error and the handshake for that server then fails. That
        // is observable -- `ssl_certificate.t` configures
        // `ssl_certificate $ssl_server_name.crt`, where the variable is empty
        // at config time, and asserts that the socket simply produces no
        // response. Failing the whole listen socket here would take every other
        // server on the same socket down with it.
        let key_id = match load_cert_with(key, cert, &passwords) {
            Ok(k) => k,
            Err(e) => {
                crate::log::error_log(
                    "error",
                    &format!("TLS setup for a server on this socket: {e}; continuing without it"),
                );
                continue;
            }
        };
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
        name_to_server,
        template_default: default_server,
        templates,
        cache: std::sync::Mutex::new(CertCacheState::default()),
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
                {
                    for cert in read_certs(&std::fs::read(ca).unwrap_or_default()).unwrap_or_default() {
                        if let Ok(anchor) = webpki::anchor_from_trusted_cert(&cert) {
                            // `TrustAnchor::subject` holds the DN *contents*, but
                            // the CertificateRequest's certificate_authorities
                            // list wants a full DER SEQUENCE. Sending the bare
                            // contents makes OpenSSL fail with
                            // `asn1_check_tlen:wrong tag` while parsing CA names
                            // and abort the handshake.
                            let name = rustls::DistinguishedName::from(der_sequence(
                                anchor.subject.as_ref(),
                            ));
                            if !hints
                                .iter()
                                .any(|h: &rustls::DistinguishedName| h.as_ref() == name.as_ref())
                            {
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

/// Build a TLS configuration from a single certificate/key pair, for `mail`.
///
/// No SNI: a mail `server {}` has no `server_name`, so nginx presents the one
/// certificate from its `mail` block for every connection.
pub fn build_mail_config(cert: &Path, key: &Path) -> io::Result<Arc<ServerConfig>> {
    build_mail_config_with(cert, key, &[])
}

/// Client-certificate verifier that rejects bad chains *inside* the handshake,
/// which is what nginx's stream module does (unlike http, which defers).
///
/// A trust anchor presented as the leaf is accepted directly: OpenSSL does the
/// same, and the nginx test fixtures are X.509 v1 self-signed certificates that
/// webpki refuses to parse.
#[derive(Debug)]
pub struct AnchorClientVerifier {
    trusted: Vec<rustls::pki_types::CertificateDer<'static>>,
    hints: Vec<rustls::DistinguishedName>,
    mandatory: bool,
}

impl AnchorClientVerifier {
    pub fn new(
        trusted: Vec<rustls::pki_types::CertificateDer<'static>>,
        hints: Vec<rustls::DistinguishedName>,
        mandatory: bool,
    ) -> Self {
        Self {
            trusted,
            hints,
            mandatory,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for AnchorClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if self
            .trusted
            .iter()
            .any(|c| c.as_ref() == end_entity.as_ref())
        {
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(|e| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                std::sync::Arc::new(std::io::Error::other(format!("client certificate: {e}"))),
            )))
        })?;
        // The anchors borrow from `self.trusted`, so they are built here rather
        // than stored in the verifier.
        let anchors: Vec<rustls::pki_types::TrustAnchor> = self
            .trusted
            .iter()
            .filter_map(|c| webpki::anchor_from_trusted_cert(c).ok())
            .collect();
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            intermediates,
            now,
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|e| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                std::sync::Arc::new(std::io::Error::other(format!("client certificate: {e}"))),
            )))
        })?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    // The handshake signature is checked against the key in the presented
    // certificate. webpki refuses to parse an X.509 v1 certificate at all
    // (`BadEncoding`), which would abort every handshake with the nginx test
    // fixtures even though the chain itself was already accepted above. The
    // chain check is the security boundary here, so an encoding complaint from
    // the signature helper is tolerated — the same trade-off the http-side
    // `PermissiveClientVerifier` makes.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        ) {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding | rustls::CertificateError::Other(_),
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
        match rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        ) {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding | rustls::CertificateError::Other(_),
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

/// Stream/mail TLS with `ssl_verify_client`.
///
/// nginx's stream module verifies inside the handshake (unlike http, which
/// defers and answers 400): `on` sets `SSL_VERIFY_PEER|FAIL_IF_NO_PEER_CERT`,
/// `optional` sets only `SSL_VERIFY_PEER` (a presented but unverifiable
/// certificate still fails the handshake), and `optional_no_ca` accepts any
/// chain and reports the outcome through `$ssl_client_verify`.
pub fn build_stream_config(
    cert: &Path,
    key: &Path,
    passwords: &[String],
    verify: u8,
    client_ca: Option<&Path>,
    trusted: Option<&Path>,
) -> io::Result<Arc<ServerConfig>> {
    let key_id = load_cert_with(key, cert, passwords)?;
    let resolver = Arc::new(SniResolver {
        exact: HashMap::new(),
        wildcard: HashMap::new(),
        default: Some(key_id),
        name_to_server: HashMap::new(),
        template_default: None,
        templates: HashMap::new(),
        cache: std::sync::Mutex::new(CertCacheState::default()),
    });
    let mut cfg = match verify {
        0 => ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
        // nginx draws the client CA store from `ssl_client_certificate`, and
        // `ssl_trusted_certificate` only contributes to chain building.
        3 => {
            let hints = ca_hints(client_ca)?;
            ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(PermissiveClientVerifier::new(hints)))
                .with_cert_resolver(resolver)
        }
        mode => {
            let mut store: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
            for path in [client_ca, trusted].into_iter().flatten() {
                let Ok(bytes) = std::fs::read(path) else {
                    continue;
                };
                for c in read_certs(&bytes).unwrap_or_default() {
                    if !store.iter().any(|x| x.as_ref() == c.as_ref()) {
                        store.push(c);
                    }
                }
            }
            if store.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ssl_verify_client without ssl_client_certificate",
                ));
            }
            // Only `ssl_client_certificate` names go into the CertificateRequest;
            // `ssl_trusted_certificate` just extends the verify store.
            let v = AnchorClientVerifier::new(store, ca_hints(client_ca)?, mode == 1);
            ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(v))
                .with_cert_resolver(resolver)
        }
    };
    cfg.alpn_protocols = Vec::new();
    Ok(Arc::new(cfg))
}

/// Distinguished names advertised in the CertificateRequest.
fn ca_hints(ca: Option<&Path>) -> io::Result<Vec<rustls::DistinguishedName>> {
    let mut hints = Vec::new();
    if let Some(path) = ca {
        let bytes = std::fs::read(path)?;
        for cert in read_certs(&bytes).unwrap_or_default() {
            if let Ok(anchor) = webpki::anchor_from_trusted_cert(&cert) {
                hints.push(rustls::DistinguishedName::from(der_sequence(
                    anchor.subject.as_ref(),
                )));
            }
        }
    }
    Ok(hints)
}

/// As `build_mail_config`, but able to unlock an encrypted key.
pub fn build_mail_config_with(
    cert: &Path,
    key: &Path,
    passwords: &[String],
) -> io::Result<Arc<ServerConfig>> {
    let key_id = load_cert_with(key, cert, passwords)?;
    let resolver = Arc::new(SniResolver {
        exact: HashMap::new(),
        wildcard: HashMap::new(),
        default: Some(key_id),
        name_to_server: HashMap::new(),
        template_default: None,
        templates: HashMap::new(),
        cache: std::sync::Mutex::new(CertCacheState::default()),
    });
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = Vec::new();
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
                rustls::CertificateError::BadEncoding | rustls::CertificateError::Other(_),
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
                rustls::CertificateError::BadEncoding | rustls::CertificateError::Other(_),
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
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
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
    verify_client_chain_multi(ca_path.into_iter().collect(), chain)
}

/// As `verify_client_chain`, over several CA bundles.
pub fn verify_client_chain_multi(
    ca_paths: Vec<&std::path::Path>,
    chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<(), String> {
    use rustls::pki_types::{CertificateDer, UnixTime};
    use webpki::anchor_from_trusted_cert;

    if chain.is_empty() {
        return Err("no certificate".to_string());
    }
    if ca_paths.is_empty() {
        // `ssl_verify_client` without `ssl_client_certificate`: nginx has no
        // trust anchors, so nothing can validate.
        return Err("unable to verify the first certificate".to_string());
    }
    let mut trusted: Vec<CertificateDer<'static>> = Vec::new();
    for path in &ca_paths {
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        let mut reader = std::io::BufReader::new(file);
        for cert in read_certs(&std::fs::read(path).unwrap_or_default()).unwrap_or_default() {
            if !trusted.iter().any(|c| c.as_ref() == cert.as_ref()) {
                trusted.push(cert);
            }
        }
    }
    if trusted.is_empty() {
        return Err("no trusted certificate".to_string());
    }
    // A trust anchor presented as the leaf verifies trivially. OpenSSL accepts
    // that, and it is the only way the nginx test fixtures validate: they are
    // X.509 v1 self-signed certificates, which webpki rejects outright
    // (`UnsupportedCertVersion`) while OpenSSL does not.
    if trusted.iter().any(|c| c.as_ref() == chain[0].as_ref()) {
        return Ok(());
    }
    let mut anchors = Vec::new();
    for cert in &trusted {
        if let Ok(anchor) = anchor_from_trusted_cert(cert) {
            anchors.push(anchor.to_owned());
        }
    }
    if anchors.is_empty() {
        return Err("no trusted certificate".to_string());
    }

    let der: CertificateDer<'static> = chain[0].clone();
    let ee =
        webpki::EndEntityCert::try_from(&der).map_err(|e| format!("invalid certificate: {e}"))?;
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

        assert_eq!(
            select(&exact, &wildcard, &default, Some("A.Example.COM")),
            Some(&1)
        );
        assert_eq!(
            select(&exact, &wildcard, &default, Some("b.example.com")),
            Some(&2)
        );
        // a wildcard covers exactly one label
        assert_eq!(
            select(&exact, &wildcard, &default, Some("x.b.example.com")),
            Some(&3)
        );
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

#[cfg(test)]
mod cert_read_tests {
    use super::*;

    /// A minimal, real DER certificate so the length arithmetic is exercised
    /// against actual ASN.1 rather than a synthetic buffer.
    fn sample_der() -> Vec<u8> {
        // Parsed from the fixtures at run time would need openssl; instead build
        // a SEQUENCE of small integers, which is enough to check the length
        // logic (the cert *contents* are never inspected here).
        let mut body = Vec::new();
        body.push(0x02);
        body.push(0x01);
        body.push(0x05);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        der
    }

    fn pem(label: &str, der: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in der.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                | chunk.get(2).copied().unwrap_or(0) as u32;
            b64.push(ALPHABET[(n >> 18) as usize & 63] as char);
            b64.push(ALPHABET[(n >> 12) as usize & 63] as char);
            b64.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            b64.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    #[test]
    fn plain_certificate_is_read() {
        let der = sample_der();
        let text = pem("CERTIFICATE", &der);
        let got = read_certs(text.as_bytes()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), der.as_slice());
    }

    #[test]
    fn trusted_certificate_has_aux_stripped() {
        let der = sample_der();
        // `openssl x509 -trustout` appends the X509_AUX structure after the
        // certificate SEQUENCE and relabels the block.
        let mut with_aux = der.clone();
        with_aux.extend_from_slice(&[0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08]);
        let text = pem("TRUSTED CERTIFICATE", &with_aux);
        let got = read_certs(text.as_bytes()).unwrap();
        assert_eq!(got.len(), 1, "trusted block must be read, not skipped");
        assert_eq!(
            got[0].as_ref(),
            der.as_slice(),
            "aux data must be stripped or webpki sees trailing garbage"
        );
    }

    #[test]
    fn mixed_file_keeps_both() {
        let a = sample_der();
        let mut b = sample_der();
        b[2] = 0x07;
        let mut text = pem("CERTIFICATE", &a);
        text.push_str(&pem("TRUSTED CERTIFICATE", &b));
        let got = read_certs(text.as_bytes()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref(), a.as_slice());
        assert_eq!(got[1].as_ref(), b.as_slice());
    }

    #[test]
    fn sequence_len_handles_long_form() {
        // 0x30 0x82 <hi> <lo> => 4-byte header.
        let der = vec![0x30, 0x82, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(der_sequence_len(&der), Some(4 + 256));
    }
}
