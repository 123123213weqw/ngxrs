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
pub struct NoVerify(pub Arc<rustls::crypto::CryptoProvider>);

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
    let ip = crate::resolver::resolve(r, &host).await?.into_iter().next()?;
    Some(Target {
        addr: SocketAddr::new(ip, port),
        host: rest.to_string(),
        ssl,
    })
}

/// Why a single gRPC attempt failed, in the vocabulary of
/// `grpc_next_upstream`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FailKind {
    /// The connection (or the h2 handshake) never came up: `error`.
    Connect,
    /// Connected, but the peer produced no usable HTTP/2 response. nginx folds
    /// "closed without a reply" into `invalid_header`, which is why
    /// `return 444` on a gRPC backend is retried under `invalid_header` only.
    InvalidHeader,
}

/// Build the outbound HTTP/2 request for one peer.
fn build_request(req: &Request, path: &str, query: &str, target: &Target) -> Option<H2Request<()>> {
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
    b.body(()).ok()
}

/// Turn an h2 reply into the response this server renders.
fn translate(status: StatusCode, headers: http::HeaderMap, body: Vec<u8>) -> Response {
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
    resp
}

/// One attempt against one peer.
async fn fetch_one(
    req: &Request,
    path: &str,
    query: &str,
    target: &Target,
    body: &[u8],
) -> Result<Response, FailKind> {
    // Build first: a value HTTP/2 cannot carry is `invalid_header`, not a
    // connection problem.
    let request = match build_request(req, path, query, target) {
        Some(r) => r,
        None => return Err(FailKind::InvalidHeader),
    };
    let tcp = match tokio::net::TcpStream::connect(target.addr).await {
        Ok(t) => t,
        Err(_) => return Err(FailKind::Connect),
    };
    tcp.set_nodelay(true).ok();
    let got = if target.ssl {
        let connector = match grpcs_connector() {
            Some(c) => c,
            None => return Err(FailKind::Connect),
        };
        // SNI takes a bare host name, not `host:port`.
        let sni = split_host_port(&target.host, true)
            .map(|(h, _)| h)
            .unwrap_or_else(|| target.host.clone());
        let name = match rustls::pki_types::ServerName::try_from(sni) {
            Ok(n) => n,
            Err(_) => return Err(FailKind::Connect),
        };
        match connector.connect(name, tcp).await {
            Ok(tls) => h2_roundtrip(tls, request, body).await,
            Err(_) => return Err(FailKind::Connect),
        }
    } else {
        h2_roundtrip(tcp, request, body).await
    };
    match got {
        Some((status, headers, body)) => Ok(translate(status, headers, body)),
        None => Err(FailKind::InvalidHeader),
    }
}

/// One candidate peer, remembering where it came from so a failed attempt can
/// be charged against `max_fails`.
struct Cand {
    target: Target,
    peer: Option<(usize, usize)>,
    /// `$upstream_addr` for this attempt (`127.0.0.1:8081`).
    label: String,
}

/// The peers to try, in order.
async fn candidates(
    http: &Http,
    spec: &str,
    peer_ip: &str,
    vars: Option<&crate::http::ServerVars<'_>>,
) -> Option<Vec<Cand>> {
    let expanded = match (spec.contains('$'), vars) {
        (true, Some(v)) => v.expand(spec),
        (true, None) => return None,
        (false, _) => spec.to_string(),
    };
    let (rest, ssl) = split_scheme(&expanded);
    let name = rest.trim_end_matches('/');

    // An `upstream {}` block: walk its peers in the same order the HTTP proxy
    // would, including `max_fails`/`fail_timeout` and the `rr`/`hash`/`random`
    // rotation, so a backend taken out of service here is out for both modules.
    if let Some(idx) = http.upstreams.iter().position(|u| u.name == name) {
        let client_ip: std::net::IpAddr = peer_ip
            .parse()
            .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
        let order = crate::proxy::select_order(&http.upstreams[idx], idx, &client_ip, None)?;
        let up = &http.upstreams[idx];
        let out: Vec<Cand> = order
            .iter()
            .map(|&i| {
                let srv = &up.servers[i];
                Cand {
                    target: Target {
                        addr: srv.addr,
                        host: name.to_string(),
                        ssl,
                    },
                    peer: Some((idx, i)),
                    label: srv.addr.to_string(),
                }
            })
            .collect();
        return if out.is_empty() { None } else { Some(out) };
    }

    // A literal or variable-resolved target: exactly one attempt.
    let t = resolve_any(spec, http, vars).await?;
    let label = t.addr.to_string();
    Some(vec![Cand {
        target: t,
        peer: None,
        label,
    }])
}

/// Does this upstream status trip a `next_upstream http_XXX` flag?
fn retry_on_status(status: u16, flags: u32) -> bool {
    use crate::config::next_upstream as nu;
    match status {
        500 => flags & nu::HTTP_500 != 0,
        502 => flags & nu::HTTP_502 != 0,
        503 => flags & nu::HTTP_503 != 0,
        504 => flags & nu::HTTP_504 != 0,
        403 => flags & nu::HTTP_403 != 0,
        404 => flags & nu::HTTP_404 != 0,
        429 => flags & nu::HTTP_429 != 0,
        _ => false,
    }
}

/// Which statuses count against `max_fails`. Probed against nginx: 5xx and 429
/// do, 403 and 404 do not.
fn counts_as_failure(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504 | 429)
}

/// Where the next attempt should go.
enum Source {
    /// An `upstream {}` block: peers are picked one at a time, because nginx
    /// advances the round-robin counter on every *peer get*, not once per
    /// request. Picking the whole order up front makes a retry reuse a stale
    /// rotation and stops `max_fails` from ever reaching its limit.
    Upstream {
        idx: usize,
        name: String,
        ssl: bool,
        client_ip: std::net::IpAddr,
    },
    /// A literal or variable-resolved target: exactly one attempt.
    Single(Cand),
}

async fn source(http: &Http, spec: &str, peer_ip: &str, vars: Option<&crate::http::ServerVars<'_>>) -> Option<Source> {
    let expanded = match (spec.contains('$'), vars) {
        (true, Some(v)) => v.expand(spec),
        (true, None) => return None,
        (false, _) => spec.to_string(),
    };
    let (rest, ssl) = split_scheme(&expanded);
    let name = rest.trim_end_matches('/');
    if let Some(idx) = http.upstreams.iter().position(|u| u.name == name) {
        let client_ip: std::net::IpAddr = peer_ip
            .parse()
            .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
        return Some(Source::Upstream {
            idx,
            name: name.to_string(),
            ssl,
            client_ip,
        });
    }
    let t = resolve_any(spec, http, vars).await?;
    let label = t.addr.to_string();
    Some(Source::Single(Cand {
        target: t,
        peer: None,
        label,
    }))
}

/// One peer get, skipping the ones already tried in this request.
fn pick_next(
    http: &Http,
    idx: usize,
    name: &str,
    ssl: bool,
    client_ip: &std::net::IpAddr,
    tried: &[usize],
) -> Option<Cand> {
    let up = &http.upstreams[idx];
    let order = crate::proxy::select_order(up, idx, client_ip, None)?;
    let pick = order.iter().copied().find(|i| !tried.contains(i))?;
    let srv = &up.servers[pick];
    Some(Cand {
        target: Target {
            addr: srv.addr,
            host: name.to_string(),
            ssl,
        },
        peer: Some((idx, pick)),
        label: srv.addr.to_string(),
    })
}

/// Send the request to a gRPC backend, following `grpc_next_upstream` across
/// the peers of an `upstream {}` block.
pub async fn fetch(
    http: &Http,
    loc: &LocCfg,
    req: &Request,
    path: &str,
    query: &str,
    peer_ip: &str,
    vars: Option<&crate::http::ServerVars<'_>>,
    body: &[u8],
) -> Option<Response> {
    use crate::config::next_upstream as nu;
    let spec = loc.grpc_pass.as_deref()?;
    let src = source(http, spec, peer_ip, vars).await?;

    let flags = loc.grpc_next_upstream;
    let retry_enabled = flags & nu::OFF == 0;
    let mut tries = if loc.grpc_next_upstream_tries == 0 {
        u32::MAX
    } else {
        loc.grpc_next_upstream_tries
    };
    let deadline = if loc.grpc_next_upstream_timeout.is_zero() {
        None
    } else {
        Some(std::time::Instant::now() + loc.grpc_next_upstream_timeout)
    };
    let mut tried: Vec<usize> = Vec::new();
    let mut last: Option<Response> = None;

    loop {
        if tries == 0 {
            break;
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                break;
            }
        }
        let cand = match &src {
            Source::Single(c) => {
                if !tried.is_empty() {
                    break;
                }
                tried.push(0);
                Cand {
                    target: c.target.clone(),
                    peer: c.peer,
                    label: c.label.clone(),
                }
            }
            Source::Upstream {
                idx,
                name,
                ssl,
                client_ip,
            } => match pick_next(http, *idx, name, *ssl, client_ip, &tried) {
                Some(c) => {
                    if let Some((_, i)) = c.peer {
                        tried.push(i);
                    }
                    c
                }
                None => break,
            },
        };
        tries -= 1;

        let slot = crate::timing::begin();
        crate::timing::set_addr(slot, &cand.label);
        // Another attempt is possible only when the directive allows retrying
        // and a peer may be left; `pick_next` answers the latter.
        let more = retry_enabled;

        match fetch_one(req, path, query, &cand.target, body).await {
            Ok(resp) => {
                crate::timing::set_status(slot, resp.status);
                if let Some((u, i)) = cand.peer {
                    crate::proxy::peer_mark(u, i, counts_as_failure(resp.status));
                }
                if more && retry_on_status(resp.status, flags) {
                    last = Some(resp);
                    continue;
                }
                return Some(resp);
            }
            Err(kind) => {
                if let Some((u, i)) = cand.peer {
                    crate::proxy::peer_mark(u, i, true);
                }
                let retry = more
                    && match kind {
                        FailKind::Connect => flags & nu::ERROR != 0,
                        FailKind::InvalidHeader => flags & nu::INVALID_HEADER != 0,
                    };
                // Nothing has reached the client, so a failed final attempt is
                // a 502 rather than the previous peer's response.
                if !retry {
                    return None;
                }
            }
        }
    }
    last
}

async fn h2_roundtrip<S>(
    io: S,
    request: H2Request<()>,
    body: &[u8],
) -> Option<(StatusCode, http::HeaderMap, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, conn) = h2::client::handshake(io).await.ok()?;
    let mut conn = Box::pin(conn);
    // Drive the connection while awaiting the response.
    //
    // The request body goes out as one DATA frame. `send_request`'s
    // `end_of_stream` argument must therefore be false whenever a body follows:
    // with it true the stream is already half-closed and the DATA is rejected,
    // which is how every gRPC request body used to be dropped
    // ("request - DATA" in `grpc_ssl.t`).
    let (resp, mut send) = client.send_request(request, body.is_empty()).ok()?;
    if !body.is_empty() {
        send.send_data(Bytes::copy_from_slice(body), true).ok()?;
    }
    let response = tokio::select! {
        r = resp => r.ok()?,
        _ = &mut conn => return None,
    };
    // The `SendStream` is released only after the response arrived; both
    // dropping it early and keeping it forever were tried here and neither
    // matters -- what mattered was `end_of_stream`.
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

/// TLS client for `proxy_pass https://`. ALPN advertises `http/1.1`: the HTTP
/// proxy speaks HTTP/1 to its upstream, unlike `grpcs://` which speaks HTTP/2.
///
/// Verification is off by default, matching `proxy_ssl_verify off` -- nginx's
/// default for the HTTP proxy module (the *stream* module defaults to on).
pub fn proxy_tls_connector() -> Option<tokio_rustls::TlsConnector> {
    proxy_tls_connector_with_reuse(true)
}

/// Same, but `proxy_ssl_session_reuse off` disables the session store, which is
/// how nginx makes the upstream report `$ssl_session_reused` as `.` again.
pub fn proxy_tls_connector_with_reuse(reuse: bool) -> Option<tokio_rustls::TlsConnector> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(Arc::new(provider))))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    if !reuse {
        cfg.resumption = rustls::client::Resumption::disabled();
    }
    Some(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}
