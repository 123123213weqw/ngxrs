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
    // nginx's SETTINGS frame, byte for byte (`ngx_http_v2_send_settings`):
    //   MAX_CONCURRENT_STREAMS = concurrent_streams (default 128)
    //   INITIAL_WINDOW_SIZE    = preread_size        (default 65536)
    //   MAX_FRAME_SIZE         = (1 << 24) - 1
    // and then a connection-level WINDOW_UPDATE of
    //   NGX_HTTP_V2_MAX_WINDOW - NGX_HTTP_V2_DEFAULT_WINDOW = 0x7fff0000
    // (`ngx_http_v2_send_window_update(h2c, 0, ...)` right after the handshake).
    //
    // The `h2` crate sends an empty SETTINGS and no WINDOW_UPDATE by default,
    // which is RFC-legal but differs from nginx frame-for-frame — enough to fail
    // the very first assertions of the official `h2.t`.
    const NGX_MAX_FRAME_SIZE: u32 = (1 << 24) - 1;
    const NGX_MAX_WINDOW: u32 = (1 << 31) - 1;
    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(128)
        .initial_window_size(65536)
        .max_frame_size(NGX_MAX_FRAME_SIZE)
        // Enlarging the connection window makes `h2` emit the same
        // connection-level WINDOW_UPDATE nginx sends.
        .initial_connection_window_size(NGX_MAX_WINDOW);

    let mut conn = match builder.handshake(socket).await {
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

        // The effective host is `:authority` when present, otherwise the
        // `Host` header — nginx's `$host` accepts either over HTTP/2.
        let mut host_headers = request.headers().get_all("host").iter();
        let first_host = host_headers
            .next()
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let duplicate_host = host_headers.next().is_some();

        let authority = request
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| first_host.clone());

        // Empty, duplicated or structurally invalid authority is a 400, exactly
        // as on HTTP/1. The check runs on the *raw* value: normalizing first
        // would strip the port and trailing dots that make `a.b..:98` invalid,
        // so a normalized-only check accepts hosts nginx rejects.
        //
        // `:authority` follows the stricter absolute-form rules (port must be
        // digits), while a `Host` header is truncated at the first ':' like
        // `ngx_http_validate_host`.
        let authority_from_header = request.uri().authority().is_none();
        let bad_host = duplicate_host
            || match authority.as_deref() {
                None => false,
                Some(a) => {
                    if authority_from_header {
                        crate::http::request::validate_host_header(a).is_err()
                    } else {
                        crate::http::request::validate_authority(a).is_err()
                    }
                }
            };
        if bad_host {
            let mut b = H2Response::builder().status(StatusCode::BAD_REQUEST);
            if let Some(h) = b.headers_mut() {
                if let Ok(v) = http::header::HeaderValue::from_str(if tokens {
                    "nginx/1.28.0"
                } else {
                    "nginx"
                }) {
                    h.insert(http::header::SERVER, v);
                }
            }
            if let Ok(r) = b.body(()) {
                if let Ok(mut send) = respond.send_response(r, true) {
                    let _ = send.send_data(Bytes::new(), true);
                }
            }
            continue;
        }

        let server: &Server =
            crate::http::select_server(http, server_idxs, default_server, authority.as_deref());

        // `large_client_header_buffers` bounds header fields on HTTP/2 too:
        // nginx checks each decoded string against `buffers.size` and the whole
        // block against `size * num`. Exceeding either is a connection error
        // there (GOAWAY ENHANCE_YOUR_CALM); the `h2` crate owns framing, so we
        // can only refuse the stream — see OPEN-ISSUES in COMPAT.md.
        {
            // nginx charges pseudo-headers against the same budget as ordinary
            // fields (they are part of the HPACK block), so they must be counted
            // here or a request that only overflows thanks to `:path` slips by.
            let mut block = 7 + request.method().as_str().len() // ":method"
                + 5 + request.uri().path().len() // ":path"
                + 10 + authority.as_deref().map(str::len).unwrap_or(0) // ":authority"
                + 7 + request.uri().scheme_str().map(str::len).unwrap_or(0); // ":scheme"
            let mut too_large = false;
            for (name, value) in request.headers() {
                // nginx charges `name.len + value.len` against a running budget
                // (`ngx_http_v2_state_header_complete`); the HPACK +32 per-entry
                // overhead is *not* counted.
                block += name.as_str().len() + value.len();
                if name.as_str().len() > server.header_field_limit
                    || value.len() > server.header_field_limit
                {
                    too_large = true;
                }
            }
            if too_large || block > server.header_block_limit {
                let mut b = H2Response::builder().status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
                if let Some(h) = b.headers_mut() {
                    if let Ok(v) = http::header::HeaderValue::from_str(if tokens {
                        "nginx/1.28.0"
                    } else {
                        "nginx"
                    }) {
                        h.insert(http::header::SERVER, v);
                    }
                }
                if let Ok(r) = b.body(()) {
                    if let Ok(mut send) = respond.send_response(r, true) {
                        let _ = send.send_data(Bytes::new(), true);
                    }
                }
                continue;
            }
        }

        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or("").to_string();
        let loc = server.locate(&path);
        let h1 = synthesize_request(&request, authority.as_deref(), &path, &query);
        let head_only = h1.method == Method::Head;

        let resp = crate::http::resolve_response(
            &h1,
            &path,
            &query,
            server,
            loc,
            http,
            "127.0.0.1",
            443,
        )
        .await;

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
        // nginx's `$host` is normalized: lowercase, port and stray colon
        // dropped, trailing dots removed — same as the HTTP/1 parser.
        host: authority
            .map(|a| InStr::new(&crate::http::request::normalize_host(a))),
        expect_continue: false,
        tls: None,
    }
}

#[allow(dead_code)]
fn _unused(_: io::Result<()>) {}
