//! HTTP/2 (RFC 9113) over TLS, via the `h2` crate.
//!
//! Covers what nginx's `http_v2` module does for the content we serve:
//! multiplexed requests, `:authority`-based virtual hosts, header normalization
//! and flow control (delegated to `h2`). Requests reuse the HTTP/1 routing
//! table, so location matching, error_page, gzip and static files behave the
//! same on both protocols.

use std::io;

use bytes::Bytes;
use h2::server;
use http::{Method as H2Method, Request as H2Request, Response as H2Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{Http, Server};
use crate::http::request::{Headers, Method, Request};
use crate::instr::InStr;

/// Serve one HTTP/2 connection (ALPN already negotiated `h2`).
pub async fn serve<S>(socket: S, server_idxs: &[usize], default_server: usize, http: &Http, tokens: bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = match server::handshake(socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ngxrs: [error] http2 handshake failed: {e}");
            return;
        }
    };

    while let Some(accepted) = conn.accept().await {
        let (request, mut respond) = match accepted {
            Ok(v) => v,
            Err(_) => break,
        };

        let authority = request
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            });

        let server: &Server =
            crate::http::select_server(http, server_idxs, default_server, authority.as_deref());

        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or("").to_string();
        let loc = server.locate(&path);
        let h1 = synthesize_request(&request, authority.as_deref(), &path, &query);
        let head_only = h1.method == Method::Head;

        let resp = crate::http::resolve_response(&h1, &path, &query, server, loc, http).await;

        let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut builder = H2Response::builder().status(status);
        {
            let headers = builder.headers_mut().expect("fresh builder");
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
            if !headers.contains_key(http::header::SERVER) {
                headers.insert(
                    http::header::SERVER,
                    http::header::HeaderValue::from_static(if tokens {
                        "nginx/1.28.0"
                    } else {
                        "nginx"
                    }),
                );
            }
        }

        let body = match crate::http::body_bytes(resp.body).await {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
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

        let response = match builder.body(()) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut send = match respond.send_response(response, head_only || len == 0) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !head_only && len > 0 {
            let _ = send.send_data(Bytes::from(body), true);
        }
    }
}

fn split_header_lines(raw: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

fn synthesize_request(
    req: &H2Request<h2::RecvStream>,
    authority: Option<&str>,
    path: &str,
    query: &str,
) -> Request {
    let mut headers = Headers::default();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.push(InStr::new(name.as_str()), InStr::new(v));
        }
    }
    let method = match req.method() {
        &H2Method::GET => Method::Get,
        &H2Method::HEAD => Method::Head,
        &H2Method::POST => Method::Post,
        &H2Method::PUT => Method::Put,
        &H2Method::DELETE => Method::Delete,
        &H2Method::OPTIONS => Method::Options,
        &H2Method::PATCH => Method::Patch,
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
        host: authority.map(InStr::new),
        expect_continue: false,
    }
}

#[allow(dead_code)]
fn _unused(_: io::Result<()>) {}
