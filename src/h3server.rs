//! HTTP/3 (QUIC) request handling.
//!
//! Mirrors `h2server`: the pseudo-headers are turned into a synthetic HTTP/1
//! `Request` so the whole routing/rewrite/content pipeline is shared, which is
//! what keeps `location`, `error_page`, `gzip` and the proxy modules behaving
//! the same on all three protocols.

use std::sync::Arc;

use bytes::Bytes;
use h3::server::Connection as H3Connection;
use h3_quinn::Connection as QuicConnection;
use http::{Method as H3Method, StatusCode};

use crate::config::typed::{Config, Http, Server};
use crate::http::request::{normalize_host, Headers, Method, Request};
use crate::http::Body;
use crate::http::Ctx;
use crate::instr::InStr;

type H3Request = http::Request<()>;
type H3Response = http::Response<()>;

/// Accept QUIC connections until shutdown, one task per connection.
pub async fn serve(
    endpoint: quinn::Endpoint,
    ctx: Arc<Ctx>,
    server_idxs: Vec<usize>,
    default_server: usize,
    server_port: u16,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                endpoint.close(0u32.into(), b"shutdown");
                return;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return };
                // Snapshot once per connection, like the HTTP/1 and HTTP/2
                // paths: an existing connection keeps serving the config it
                // started with across a SIGHUP.
                let cfg = ctx.cfg();
                let idxs = server_idxs.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let _ = handle_conn(conn, cfg, idxs, default_server, server_port).await;
                });
            }
        }
    }
}

async fn handle_conn(
    conn: quinn::Connection,
    cfg: Arc<Config>,
    server_idxs: Vec<usize>,
    default_server: usize,
    server_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // `send_grease` defaults to true in the h3 crate, which injects reserved
    // frame/stream types. The nginx reference client (`Test::Nginx::HTTP3`)
    // decodes a fixed frame table and aborts on anything else, and nginx
    // itself sends no grease, so it is disabled here.
    let mut h3 = h3::server::builder()
        .send_grease(false)
        .build::<QuicConnection, Bytes>(QuicConnection::new(conn))
        .await?;
    // Requests on one connection are answered in arrival order: the h3
    // accept/resolve API borrows the connection, so the stream cannot outlive
    // the resolver. Functionally equivalent, but it means a slow upstream
    // serialises the other streams on that connection (see COMPAT.md).
    while let Some(resolver) = h3.accept().await? {
        let (req, mut stream) = resolver.resolve_request().await?;
        let _ = answer(
            req,
            &mut stream,
            &cfg.http,
            &server_idxs,
            default_server,
            server_port,
        )
        .await;
    }
    Ok(())
}

async fn answer(
    req: H3Request,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    http: &Http,
    server_idxs: &[usize],
    default_server: usize,
    server_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        });
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    let server: &Server =
        crate::http::select_server(http, server_idxs, default_server, authority.as_deref());

    let h1 = synthesize(&req, authority.as_deref(), &path, &query);
    let head_only = h1.method == Method::Head;
    let loc = server.locate(&path);

    let resp = crate::http::resolve_response(
        &h1,
        &path,
        &query,
        server,
        loc,
        http,
        "127.0.0.1",
        server_port,
    )
    .await;

    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = H3Response::builder().status(status);
    if let Some(headers) = builder.headers_mut() {
        for line in split_header_lines(&resp.raw) {
            if let Some((k, v)) = line.split_once(':') {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(k.trim().as_bytes()),
                    http::header::HeaderValue::from_str(v.trim()),
                ) {
                    headers.append(name, value);
                }
            }
        }
        for (k, v) in &resp.headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(k.as_bytes()),
                http::header::HeaderValue::from_str(v),
            ) {
                headers.append(name, value);
            }
        }
        // HTTP/3 carries the protocol in the ALPN, so these hop-by-hop fields
        // must not be echoed (nginx does the same).
        for name in [http::header::CONNECTION, http::header::TRANSFER_ENCODING] {
            headers.remove(name);
        }
    }

    let body = crate::http::body_bytes(resp.body).await.unwrap_or_default();
    let len = body.len();
    if let Some(headers) = builder.headers_mut() {
        if !headers.contains_key(http::header::CONTENT_LENGTH)
            && resp.status != 204
            && resp.status != 304
        {
            if let Ok(v) = http::header::HeaderValue::from_str(&len.to_string()) {
                headers.insert(http::header::CONTENT_LENGTH, v);
            }
        }
    }

    let response = builder.body(())?;
    stream.send_response(response).await?;
    if !head_only && len > 0 {
        stream.send_data(Bytes::from(body)).await?;
    }
    stream.finish().await?;
    Ok(())
}

fn synthesize(req: &H3Request, authority: Option<&str>, path: &str, query: &str) -> Request {
    let mut headers = Headers::default();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.push(InStr::new(name.as_str()), InStr::new(v));
        }
    }
    let method = match req.method() {
        &H3Method::GET => Method::Get,
        &H3Method::HEAD => Method::Head,
        &H3Method::POST => Method::Post,
        &H3Method::PUT => Method::Put,
        &H3Method::DELETE => Method::Delete,
        &H3Method::OPTIONS => Method::Options,
        &H3Method::PATCH => Method::Patch,
        other => Method::Other(InStr::new(other.as_str())),
    };
    let mut target = path.to_string();
    if !query.is_empty() {
        target.push('?');
        target.push_str(query);
    }
    Request {
        method,
        raw_target: target,
        version_minor: 1,
        headers,
        body_len: 0,
        chunked: false,
        keepalive: true,
        host: authority.map(|a| InStr::new(&normalize_host(a))),
        expect_continue: false,
        tls: None,
        started: std::time::Instant::now(),
    }
}

fn split_header_lines(raw: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

#[allow(dead_code)]
fn _body_is_used(_: Body) {}

/// Build the QUIC server config: TLS 1.3 only (QUIC forbids anything older)
/// with the `h3` ALPN, reusing whatever certificate the listen group resolved.
pub fn quic_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> std::io::Result<quinn::ServerConfig> {
    // `with_single_cert` runs the certificate through webpki, which rejects
    // X.509 v1 — and the nginx-tests fixtures are v1. A server never validates
    // its own certificate, so install the chain through a resolver instead,
    // which is exactly what rustls does internally once the check passes.
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let certified = std::sync::Arc::new(rustls::sign::CertifiedKey::new(certs, signing));

    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(FixedCert(certified)));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let transport = Arc::get_mut(&mut cfg.transport).expect("fresh transport config");
    // nginx's default QUIC idle timeout is 30s.
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("30s fits"),
    ));
    Ok(cfg)
}

/// Always offers the one configured certificate (no SNI on the QUIC path yet).
#[derive(Debug)]
struct FixedCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
