//! `grpc_pass` — proxy a request to an upstream over HTTP/2.
//!
//! nginx always speaks HTTP/2 to a gRPC backend (h2c for `grpc://`, TLS+ALPN
//! for `grpcs://`), regardless of how the client reached us.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Request as H2Request, StatusCode};

use crate::config::typed::{Http, LocCfg};
use crate::http::request::Request;
use crate::http::Response;

/// Accept any server certificate and require no SNI match.
///
/// nginx's defaults are `grpc_ssl_verify off` and `proxy_ssl_verify off`, i.e.
/// the upstream certificate is not validated, so this mirrors that exactly.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // webpki refuses X.509 v1 certificates, which nginx-tests generate;
        // with `grpc_ssl_verify off` we are not deciding trust here anyway, so
        // let the handshake proceed instead of failing the connection.
        tolerant_signature(rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        tolerant_signature(rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Accept the failures webpki raises for X.509 **v1** certificates (it refuses
/// them outright), which OpenSSL — and therefore nginx — accepts. With
/// `grpc_ssl_verify off` trust is not being decided here anyway.
fn tolerant_signature(
    r: Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    match r {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding | rustls::CertificateError::Other(_),
        )) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
        other => other,
    }
}

/// TLS client used for `grpcs://` upstreams (and `proxy_pass https://`).
pub fn grpcs_connector() -> Option<tokio_rustls::TlsConnector> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(Arc::new(provider))))
        .with_no_client_auth();
    // gRPC backends always speak HTTP/2.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Some(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

/// A resolved `grpc_pass` destination.
#[derive(Debug, Clone)]
pub struct Target {
    pub addr: SocketAddr,
    pub host: String,
    pub ssl: bool,
}

/// Strip `grpc://` / `grpcs://`, exactly as `ngx_http_grpc_pass` does before
/// handing the remainder to the upstream lookup.
pub fn split_scheme(spec: &str) -> (&str, bool) {
    // `ngx_strncasecmp(url->data, "grpcs://", 8)` / `"grpc://", 7`: a plain
    // case-insensitive prefix compare, so the scheme may be upper case.
    if spec.len() > 8 && spec[..8].eq_ignore_ascii_case("grpcs://") {
        (&spec[8..], true)
    } else if spec.len() > 7 && spec[..7].eq_ignore_ascii_case("grpc://") {
        (&spec[7..], false)
    } else {
        (spec, false)
    }
}

/// Split `host[:port]` with nginx's defaults: 80 for grpc, 443 for grpcs.
pub fn split_host_port(s: &str, ssl: bool) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            if ssl {
                443
            } else {
                80
            }
        } else {
            after.strip_prefix(':')?.parse().ok()?
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            Some((h.to_string(), p.parse().ok()?))
        }
        _ => Some((s.to_string(), if ssl { 443 } else { 80 })),
    }
}

/// Resolve a `grpc_pass` destination statically (no variables in the value).
pub fn resolve_static(spec: &str, http: &Http) -> Option<Target> {
    let (rest, ssl) = split_scheme(spec);
    // nginx looks the *scheme-stripped* string up in the upstream table first.
    if let Some(idx) = http
        .upstreams
        .iter()
        .position(|u| u.name == rest.trim_end_matches('/'))
    {
        let up = &http.upstreams[idx];
        let s = up.servers.iter().find(|s| !s.down && !s.backup)?;
        return Some(Target {
            addr: s.addr,
            host: rest.trim_end_matches('/').to_string(),
            ssl,
        });
    }
    let (host, port) = split_host_port(rest, ssl)?;
    let ip = host.parse().ok()?;
    Some(Target {
        addr: SocketAddr::new(ip, port),
        host: rest.to_string(),
        ssl,
    })
}

/// Resolve a target that may contain variables.
///
/// nginx evaluates the value per request, strips the scheme, then looks the
/// remainder up in the upstream table before falling back to `resolver`.
pub async fn resolve_any(
    spec: &str,
    http: &Http,
    vars: Option<&crate::http::ServerVars<'_>>,
) -> Option<Target> {
    let expanded = match (spec.contains('$'), vars) {
        (true, Some(v)) => v.expand(spec),
        (true, None) => return None,
        (false, _) => spec.to_string(),
    };
    if let Some(t) = resolve_static(&expanded, http) {
        return Some(t);
    }
    // Bare host name: needs the configured resolver.
    let (rest, ssl) = split_scheme(&expanded);
    let (host, port) = split_host_port(rest, ssl)?;
    let r = http.resolver.as_ref()?;
    let ip = crate::resolver::resolve(r, &host).await?;
    Some(Target {
        addr: SocketAddr::new(ip, port),
        host: rest.to_string(),
        ssl,
    })
}

/// Send one request to the gRPC backend and translate the reply back.
pub async fn fetch(
    http: &Http,
    loc: &LocCfg,
    req: &Request,
    path: &str,
    query: &str,
    peer_ip: &str,
    vars: Option<&crate::http::ServerVars<'_>>,
) -> Option<Response> {
    let spec = loc.grpc_pass.as_ref()?;
    let target = resolve_any(spec, http, vars).await?;

    let mut uri = path.to_string();
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(query);
    }

    // The `h2` crate derives `:scheme` and `:authority` from the URI, so it must
    // be absolute; an origin-form target leaves the request malformed.
    let scheme = if target.ssl { "https" } else { "http" };
    let absolute = format!("{scheme}://{}{uri}", target.host);
    let mut b = H2Request::builder()
        .method(req.method.as_str())
        .uri(absolute);
    for (name, value) in req.headers.iter() {
        let n = name.to_ascii_lowercase();
        // HTTP/2 forbids these; the transport supplies them.
        if matches!(
            n.as_str(),
            "host"
                | "connection"
                | "transfer-encoding"
                | "keep-alive"
                | "upgrade"
                | "proxy-connection"
        ) {
            continue;
        }
        if let Ok(v) = HeaderValue::from_str(value) {
            if let Some(h) = b.headers_mut() {
                h.append(http::header::HeaderName::from_bytes(n.as_bytes()).ok()?, v);
            }
        }
    }
    let _ = peer_ip;
    let request = b.body(()).ok()?;

    let tcp = tokio::net::TcpStream::connect(target.addr).await.ok()?;
    tcp.set_nodelay(true).ok();
    let (status, headers, body) = if target.ssl {
        let connector = grpcs_connector()?;
        // SNI takes a bare host name, not `host:port`.
        let sni = split_host_port(&target.host, true)
            .map(|(h, _)| h)
            .unwrap_or_else(|| target.host.clone());
        let name = rustls::pki_types::ServerName::try_from(sni).ok()?;
        let tls = connector.connect(name, tcp).await.ok()?;
        h2_roundtrip(tls, request).await?
    } else {
        h2_roundtrip(tcp, request).await?
    };

    let mut resp = Response::empty(status.as_u16());
    // `Response::raw` holds pre-rendered *header lines*, not a whole message:
    // status line and framing are added by the writer.
    for (name, value) in &headers {
        // `Server` and `Date` are added by the writer (as nginx does), so the
        // upstream copies must not be forwarded or they appear twice.
        if name == http::header::CONTENT_LENGTH
            || name == http::header::TRANSFER_ENCODING
            || name == http::header::CONNECTION
            || name == http::header::SERVER
            || name == http::header::DATE
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            resp.headers
                .push((name.as_str().to_string(), v.to_string()));
        }
    }
    resp.body = crate::http::Body::Bytes(body);
    Some(resp)
}

async fn h2_roundtrip<S>(
    io: S,
    request: H2Request<()>,
) -> Option<(StatusCode, http::HeaderMap, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, conn) = h2::client::handshake(io).await.ok()?;
    let mut conn = Box::pin(conn);
    // Drive the connection while awaiting the response.
    // `end_of_stream = true` already closes our half of the stream; sending an
    // extra DATA frame would be rejected (the stream is no longer writable).
    let (resp, send) = client.send_request(request, true).ok()?;
    let response = tokio::select! {
        r = resp => r.ok()?,
        _ = &mut conn => return None,
    };
    drop(send);
    let (parts, mut body) = response.into_parts();
    let mut out = Vec::new();
    loop {
        let chunk = tokio::select! {
            c = body.data() => c,
            _ = &mut conn => None,
        };
        match chunk {
            Some(Ok(d)) => {
                out.extend_from_slice(&d);
                let _ = body.flow_control().release_capacity(d.len());
            }
            _ => break,
        }
    }
    Some((parts.status, parts.headers, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_schemes() {
        assert_eq!(split_scheme("grpc://h:1"), ("h:1", false));
        assert_eq!(split_scheme("grpcs://h:1"), ("h:1", true));
        assert_eq!(split_scheme("h:1"), ("h:1", false));
        assert_eq!(split_scheme("GRPCS://h"), ("h", true));
    }

    #[test]
    fn default_ports() {
        assert_eq!(split_host_port("h", false).unwrap(), ("h".into(), 80));
        assert_eq!(split_host_port("h", true).unwrap(), ("h".into(), 443));
        assert_eq!(split_host_port("h:9", false).unwrap(), ("h".into(), 9));
        assert_eq!(
            split_host_port("[::1]:7", false).unwrap(),
            ("::1".into(), 7)
        );
        assert_eq!(split_host_port("[::1]", true).unwrap(), ("::1".into(), 443));
    }
}
