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
pub async fn serve<S>(
    socket: S,
    server_idxs: &[usize],
    default_server: usize,
    http: &Http,
    tokens: bool,
    // The port this listener accepted on. `Location` absolutisation needs it:
    // nginx reports the port the client connected to, and hard-coding 443 made
    // `absolute_redirect` emit `http://on:443/` for a cleartext listener on 8080
    // (`h2_absolute_redirect.t`).
    listen_port: u16,
) where
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

    // Streams are handled concurrently, not one at a time.
    //
    // This is not a style choice: the `h2::server::Connection` is the only thing
    // that reads the socket, and it makes progress only while it is being
    // polled. Awaiting a request body inside the accept loop therefore stalled
    // the connection whenever the body had not fully arrived -- the next DATA
    // frame was never read, and a body larger than the stream window never even
    // got its WINDOW_UPDATE. `h2_request_body.t`'s multi-frame, big-body and
    // "discarded body" cases all hung on exactly that.
    //
    // So `accept()` keeps being polled here and each stream runs as a local
    // future. `futures` is not a dependency, hence the small poll set below.
    let mut pending: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>> =
        Vec::new();
    loop {
        let accepted = tokio::select! {
            a = conn.accept() => a,
            _ = poll_all(&mut pending), if !pending.is_empty() => continue,
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (request, respond) = match accepted {
            Ok(v) => v,
            Err(_) => break,
        };
        pending.push(Box::pin(handle_stream(
            request,
            respond,
            server_idxs,
            default_server,
            http,
            tokens,
            listen_port,
        )));
    }
    // Drain whatever is still in flight before the connection goes away.
    while !pending.is_empty() {
        poll_all(&mut pending).await;
    }
}

/// Poll every future in `pending` once, dropping the ones that finished.
///
/// Returns as soon as at least one completed, so the caller's `select!` can make
/// progress without needing a separate wakeup protocol.
async fn poll_all<'a>(
    pending: &mut Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>>,
) {
    std::future::poll_fn(|cx| {
        use std::task::Poll;
        let mut finished = false;
        let mut i = 0;
        while i < pending.len() {
            if pending[i].as_mut().poll(cx).is_ready() {
                pending.swap_remove(i);
                finished = true;
            } else {
                i += 1;
            }
        }
        if finished {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    request: H2Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    server_idxs: &[usize],
    default_server: usize,
    http: &Http,
    tokens: bool,
    listen_port: u16,
) {
    {
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
        // Selected before the host check: a bad host still needs a server for
        // `error_page` to resolve against.
        let server: &Server =
            crate::http::select_server(http, server_idxs, default_server, authority.as_deref());

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
            // nginx's HTTP/2 path produces the 400 inside the request
            // machinery, so `error_page 400 ...` applies to it. Answering here
            // skipped that.
            let synthetic = synthesize_request(&request, authority.as_deref(), "/", "");
            let resp = crate::http::error_page_response(
                &synthetic,
                400,
                server,
                http,
                "127.0.0.1",
                0,
                listen_port,
                "127.0.0.1",
            )
            .await;
            if !send_http2_response(&mut respond, resp, tokens, false).await {
                return;
            }
            return;
        }
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
                let mut b =
                    H2Response::builder().status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
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
                return;
            }
        }

        // The request target must be resolved the same way as on HTTP/1:
        // percent-decoded and path-normalised. `uri().path()` keeps `%20`
        // escaped, so `/dir%20sp` did not match the `dir sp` on disk and the
        // trailing-slash redirect -- the one `h2_absolute_redirect.t` measures
        // with escaped names -- never fired.
        let query = request.uri().query().unwrap_or("").to_string();
        let (path, _) = match crate::util::parse_target(request.uri().path()) {
            Ok(v) => v,
            Err(_) => {
                let synthetic = synthesize_request(&request, authority.as_deref(), "/", "");
                let resp = crate::http::error_page_response(
                    &synthetic,
                    400,
                    server,
                    http,
                    "127.0.0.1",
                    0,
                    listen_port,
                    "127.0.0.1",
                )
                .await;
                if !send_http2_response(&mut respond, resp, tokens, false).await {
                return;
            }
                return;
            }
        };
        let loc = server.locate(&path);
        let mut h1 = synthesize_request(&request, authority.as_deref(), &path, &query);
        let head_only = h1.method == Method::Head;

        // ---- request body ----
        //
        // The DATA frames live on the stream, not on a socket the dispatcher
        // can read, so collect them here and hand routing an in-memory body.
        // `flow_control().release_capacity` is mandatory: the initial window is
        // 65536 bytes and without it a larger body never arrives, which shows up
        // as "small bodies work, large ones hang".
        // nginx stops reading as soon as `content-length` bytes have arrived: it
        // does not wait for the END_STREAM flag. A client that declares a length
        // and then keeps the stream open therefore gets an answer from nginx and
        // hung against us -- which is exactly what `h2_request_body_extra.t`'s
        // "body multi" cases do (they send the body one byte per DATA frame and
        // never set END_STREAM).
        let declared_len: Option<u64> = request
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let max_body = loc.client_max_body_size;
        let mut recv = request.into_body();
        let mut body: Vec<u8> = Vec::new();
        let mut too_large = false;
        // Flow control is released in blocks, not per DATA frame.
        //
        // nginx credits the window in large steps, and `h2_request_body.t`
        // asserts a single WINDOW_UPDATE with `wdelta >= 65536` for an 80 KB
        // body. Releasing every 16 KB frame produced a 16 KB delta.
        const WINDOW_STEP: usize = 65536;
        let mut unreleased: usize = 0;
        // Whether anything is going to look at the body. A request nothing needs
        // the body for is answered without waiting for END_STREAM, and the
        // stream is then reset -- which is what nginx does, and what
        // "request body discarded - zero RST_STREAM" measures.
        let wants_body = loc.proxy_pass.is_some()
            || loc.fastcgi_pass.is_some()
            || loc.uwsgi_pass.is_some()
            || loc.scgi_pass.is_some()
            || (loc.dav_methods != 0)
            || crate::http::references_body_var(&loc.headers)
            || loc
                .ret
                .as_ref()
                .map(|(_, t)| t.contains("$request_body"))
                .unwrap_or(false)
            // Deliberately *not* `!loc.error_pages.is_empty()`: an error page
            // existing somewhere in the config does not mean this request's body
            // is needed, and treating it as such made every stream wait for an
            // END_STREAM that "request body discarded" never sends.
            ;
        let mut ended = false;
        // A request whose stream already ended has no body to discard, and
        // resetting it after the response is a protocol error the client sees as
        // a failed stream (`h2_request_body.t`, "request body with padding -
        // next"). Only an *unfinished* stream gets the reset.
        let ended_on_headers = recv.is_end_stream();
        let mut discarded = false;
        let mut saw_data = false;
        if wants_body {
            loop {
                match recv.data().await {
                    Some(Ok(chunk)) => {
                        saw_data = true;
                        let n = chunk.len();
                        if max_body != u64::MAX && (body.len() + n) as u64 > max_body {
                            too_large = true;
                            let _ = recv.flow_control().release_capacity(n);
                            break;
                        }
                        body.extend_from_slice(&chunk);
                        unreleased += n;
                        if unreleased >= WINDOW_STEP
                            && recv.flow_control().release_capacity(unreleased).is_err()
                        {
                            break;
                        } else if unreleased >= WINDOW_STEP {
                            unreleased = 0;
                        }
                        if declared_len.is_some_and(|l| body.len() as u64 >= l) {
                            ended = true;
                            break;
                        }
                        // The peer may have set END_STREAM on the DATA frame while
                        // declaring a longer `content-length` (a malformed request
                        // nginx answers 400). `data()` will not report the end in
                        // that case -- the length and the flag disagree -- so check
                        // the flag itself instead of waiting forever.
                        if recv.is_end_stream() {
                            ended = true;
                            break;
                        }
                    }
                    Some(Err(_)) => {
                        ended = true;
                        break;
                    }
                    None => {
                        ended = true;
                        break;
                    }
                }
            }
            if unreleased > 0 {
                let _ = recv.flow_control().release_capacity(unreleased);
            }
            // nginx compares what arrived against the declared length and
            // answers 400 on any mismatch ("request body less/more than
            // content-length").
            if !too_large {
                if let Some(l) = declared_len {
                    if body.len() as u64 != l {
                        let mut resp = crate::http::error_page_response(
                            &h1,
                            400,
                            server,
                            http,
                            "127.0.0.1",
                            0,
                            listen_port,
                            "127.0.0.1",
                        )
                        .await;
                        crate::http::absolutize_location_field(
                            &mut resp,
                            &h1,
                            loc,
                            listen_port,
                            "127.0.0.1",
                        );
                        if !send_http2_response(&mut respond, resp, tokens, false).await {
                return;
            }
                        return;
                    }
                }
            }
            let _ = ended;
        } else {
            discarded = !ended_on_headers;
        }

        if too_large {
            // nginx answers 413 without draining the rest of the body, and
            // resets the stream so the client stops sending.
            let mut b = H2Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE);
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
                    send.send_data(Bytes::new(), true).ok();
                }
            }
            return;
        }
        // `client_body_in_file_only`, or a body larger than
        // `client_body_buffer_size`, spills to a temp file: `$request_body`
        // then renders empty and `$request_body_file` names the file.
        // `client_body_in_file_only on` writes a file even for an empty body
        // (`h2_request_body.t`: "request body - empty body file"), while an
        // empty body never spills on the buffer-size rule.
        if crate::http::body_needs_file(loc, body.len()) {
            h1.request_body_file = crate::http::write_body_file(http, &body);
        }
        // Only present when the request actually carries one: `buffered_body`
        // being `Some` makes the upstream head emit `Content-Length: 0`, and
        // nginx sends no such header for a request without a body
        // (`h2_request_body.t`, "request without body - content length").
        if saw_data || !body.is_empty() || declared_len.is_some() {
            h1.buffered_body = Some(body);
        }

        let resp = crate::http::resolve_response(
            &h1,
            &path,
            &query,
            server,
            loc,
            http,
            "127.0.0.1",
            listen_port,
        )
        .await;

        if !send_http2_response(&mut respond, resp, tokens, head_only).await {
            return;
        }
        if discarded {
            // Nothing consumed the body, so tell the client to stop sending it.
            // nginx resets with NO_ERROR (code 0) *after* the response, which is
            // what "request body discarded - zero RST_STREAM" checks.
            respond.send_reset(h2::Reason::NO_ERROR);
        }
    }
}

/// Render a `Response` as HTTP/2 HEADERS (+ DATA) frames.
async fn send_http2_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    resp: crate::http::Response,
    tokens: bool,
    head_only: bool,
) -> bool {
    // nginx's `return 444` closes the connection without sending anything, on
    // every protocol -- the h1 path does that by propagating `ConnectionAborted`
    // from the writer. Emitting a 444 HEADERS frame instead (which this did)
    // leaks a status nginx never sends and, more importantly, makes a gRPC
    // client treat the peer as answering rather than as having dropped.
    if resp.status == 444 {
        let _ = respond.send_reset(h2::Reason::INTERNAL_ERROR);
        return false;
    }
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // A location-level `server_tokens` overrides the server's for this stream.
    let tokens = resp.server_tokens.unwrap_or(tokens);
    let mut builder = H2Response::builder().status(status);
    {
        let headers = builder.headers_mut().expect("fresh builder");
        for line in split_header_lines(&resp.raw) {
            if let Some((k, v)) = line.split_once(':') {
                // `Transfer-Encoding` and the rest of the hop-by-hop set are
                // forbidden in HTTP/2, and the h1 path adds
                // `Transfer-Encoding: chunked` whenever `add_trailer` applies.
                if is_connection_specific(k.trim()) {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(k.trim().as_bytes()),
                    http::header::HeaderValue::from_str(v.trim()),
                ) {
                    headers.append(name, value);
                }
            }
        }
        for (k, v) in &resp.headers {
            if is_connection_specific(k) {
                continue;
            }
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

    // `add_trailer` reaches HTTP/2 as a second HEADERS frame after the DATA, so
    // the response must not end the stream up front (`h2_trailers.t` counts the
    // frames: HEADERS, DATA without END_STREAM, then the trailer HEADERS).
    let has_trailers = !resp.trailers.is_empty();
    let Ok(response) = builder.body(()) else {
        return true;
    };
    let Ok(mut send) = respond.send_response(response, !has_trailers && (head_only || len == 0))
    else {
        return true;
    };
    if head_only {
        return true;
    }
    if len > 0 && !has_trailers {
        let _ = send.send_data(Bytes::from(body), true);
        return true;
    }
    if len > 0 {
        let _ = send.send_data(Bytes::from(body), false);
    }
    if has_trailers {
        let mut trailers = http::HeaderMap::new();
        for (k, v) in &resp.trailers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(k.as_bytes()),
                http::header::HeaderValue::from_str(v),
            ) {
                trailers.append(name, value);
            }
        }
        let _ = send.send_trailers(trailers);
    }
    true
}

/// Headers HTTP/2 forbids (`RFC 9113` 8.2.2): HTTP/2 has its own framing, so the
/// hop-by-hop set must not be forwarded.
fn is_connection_specific(name: &str) -> bool {
    name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("upgrade")
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
        proxy_protocol: None,
        request_id: crate::util::new_request_id(),
        method,
        raw_target: target,
        version_minor: 1,
        headers,
        body_len: 0,
        buffered_body: None,
        streamed_body: std::sync::Arc::new(std::sync::Mutex::new(None)),
        request_body_file: None,
        chunked: false,
        keepalive: true,
        // nginx's `$host` is normalized: lowercase, port and stray colon
        // dropped, trailing dots removed — same as the HTTP/1 parser.
        host: authority.map(|a| InStr::new(&crate::http::request::normalize_host(a))),
        expect_continue: false,
        tls: None,
        started: std::time::Instant::now(),
    }
}

#[allow(dead_code)]
fn _unused(_: io::Result<()>) {}
