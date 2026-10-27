//! uwsgi and SCGI upstream protocols.
//!
//! Both are "CGI over a socket" like FastCGI but with much simpler framing:
//! * uwsgi: a 4-byte little-endian header (modifier1, modifier2, datasize,
//!   then key/value pairs as 2-byte LE length + bytes).
//! * SCGI: `netstring` length prefix `len:`, then NUL-terminated key/value
//!   pairs, then a comma, then the request body.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::conn::Conn;
use crate::http::request::Request;
use crate::http::{error_body, Body, Outcome, Response};

/// Variables available to uwsgi_param / scgi_param.
struct Vars<'a> {
    req: &'a Request,
    peer_ip: &'a str,
    uri: &'a str,
    args: &'a str,
    document_root: &'a str,
}

fn expand(spec: &str, v: &Vars<'_>) -> String {
    let mut out = String::with_capacity(spec.len() + 16);
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            // Copy the literal run as a slice. Pushing `b as char` maps each
            // byte to a Latin-1 code point, so any non-ASCII text in a
            // directive came out as mojibake (`\u{6a21}\u{6a23}` -> the same
            // bytes re-encoded). `$` is ASCII, so both ends of the slice are
            // char boundaries.
            let end = memchr::memchr(b'$', &b[i..])
                .map(|p| i + p)
                .unwrap_or(b.len());
            out.push_str(&spec[i..end]);
            i = end;
            continue;
        }
        let rest = &spec[i + 1..];
        let n = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if n == 0 {
            out.push('$');
            i += 1;
            continue;
        }
        let name = &rest[..n];
        let value = match name {
            "request_uri" => Some(v.req.raw_target.clone()),
            "uri" | "document_uri" => Some(v.uri.to_string()),
            "args" | "query_string" => Some(v.args.to_string()),
            "request_method" => Some(v.req.method.as_str().to_string()),
            "remote_addr" => Some(v.peer_ip.to_string()),
            "document_root" => Some(v.document_root.to_string()),
            "content_length" => v.req.headers.get("content-length").map(|s| s.to_string()),
            "content_type" => v.req.headers.get("content-type").map(|s| s.to_string()),
            "server_protocol" => Some(if v.req.version_minor == 1 {
                "HTTP/1.1".to_string()
            } else {
                "HTTP/1.0".to_string()
            }),
            "scheme" => Some("http".to_string()),
            "host" | "http_host" => v.req.host.as_ref().map(|h| h.as_str().to_string()),
            _ => {
                if let Some(h) = name.strip_prefix("http_") {
                    let key = h.replace('_', "-");
                    v.req.headers.get(&key).map(|s| s.to_string())
                } else {
                    None
                }
            }
        };
        match value {
            Some(val) => {
                out.push_str(&val);
                i += 1 + n;
            }
            None => {
                out.push('$');
                i += 1;
            }
        }
    }
    out
}

/// uwsgi packet: modifier1=0 (WSGI), modifier2=0.
fn uwsgi_packet(params: &[(String, String)]) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    for (k, v) in params {
        data.extend_from_slice(&(k.len() as u16).to_le_bytes());
        data.extend_from_slice(k.as_bytes());
        data.extend_from_slice(&(v.len() as u16).to_le_bytes());
        data.extend_from_slice(v.as_bytes());
    }
    // nginx builds this byte by byte: modifier1, size low, size high,
    // modifier2 (see ngx_http_uwsgi_module.c, ngx_http_uwsgi_create_request).
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(0); // modifier1: WSGI request
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.push(0); // modifier2
    out.extend_from_slice(&data);
    out
}

/// SCGI request: `len:key\0value\0...` then `,` then the body.
fn scgi_request(params: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut net = Vec::with_capacity(256);
    for (k, v) in params {
        net.extend_from_slice(k.as_bytes());
        net.push(0);
        net.extend_from_slice(v.as_bytes());
        net.push(0);
    }
    let mut out = Vec::with_capacity(net.len() + body.len() + 12);
    out.extend_from_slice(net.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(&net);
    out.push(b',');
    out.extend_from_slice(body);
    out
}

/// Split a CGI-style header block (same rules as the FastCGI module).
fn parse_cgi(buf: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, bool) {
    let split = memchr::memmem::find(buf, b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&buf[..i], buf[i + 4..].to_vec()),
        None => (&buf[..0], buf.to_vec()),
    };
    let mut status = 200u16;
    let mut headers = Vec::new();
    let mut had_length = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = memchr::memchr(b':', line) else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
        if name.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            had_length = true;
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("server")
            || name.eq_ignore_ascii_case("date")
        {
            continue;
        }
        headers.push((name, value));
    }
    (status, headers, body, had_length)
}

fn frame_response(
    status: u16,
    headers: &[(String, String)],
    payload: &[u8],
    had_length: bool,
) -> (Vec<u8>, Vec<u8>) {
    let mut raw = Vec::with_capacity(256);
    for (k, v) in headers {
        raw.extend_from_slice(k.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(v.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    let body = if had_length {
        raw.extend_from_slice(b"Content-Length: ");
        raw.extend_from_slice(payload.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n");
        payload.to_vec()
    } else {
        raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        let mut chunked = Vec::with_capacity(payload.len() + 32);
        if !payload.is_empty() {
            chunked.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            chunked.extend_from_slice(payload);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        chunked
    };
    let _ = status;
    (raw, body)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    query: &str,
    loc: &crate::config::LocCfg,
    addr: SocketAddr,
    kind: &str,
    params: &[crate::config::FastcgiParam],
    connect_timeout: Duration,
    read_timeout: Duration,
    tokens: bool,
    tls: Option<&(std::path::PathBuf, std::path::PathBuf, Vec<String>)>,
) -> io::Result<Option<Outcome>> {
    // RFC 7231: never send 100 Continue to an HTTP/1.0 client.
    if req.expect_continue && req.version_minor == 1 {
        conn.send_100_continue().await?;
    }

    let body = crate::proxy::take_request_body(conn, req, 32 * 1024 * 1024).await?;

    let document_root = loc
        .alias
        .as_ref()
        .map(|a| a.to_string_lossy().to_string())
        .unwrap_or_else(|| loc.root.to_string_lossy().to_string());
    let peer_ip = conn.peer.ip().to_string();
    let vars = Vars {
        req,
        peer_ip: &peer_ip,
        uri: path,
        args: query,
        document_root: &document_root,
    };

    // Protocol mandates a few variables; user config adds the rest.
    let mut all: Vec<(String, String)> = Vec::with_capacity(params.len() + 6);
    if kind == "uwsgi" {
        all.push(("REQUEST_METHOD".into(), req.method.as_str().to_string()));
        all.push(("REQUEST_URI".into(), req.raw_target.clone()));
        all.push(("PATH_INFO".into(), path.to_string()));
        all.push(("QUERY_STRING".into(), query.to_string()));
        all.push(("SERVER_PROTOCOL".into(), "HTTP/1.1".into()));
        all.push(("CONTENT_LENGTH".into(), body.len().to_string()));
    } else {
        all.push(("CONTENT_LENGTH".into(), body.len().to_string()));
    }
    for p in params {
        all.push((p.name.clone(), expand(&p.value, &vars)));
    }
    if kind == "scgi" && !all.iter().any(|(k, _)| k == "SCGI") {
        all.push(("SCGI".into(), "1".into()));
    }

    let packet = if kind == "uwsgi" {
        uwsgi_packet(&all)
    } else {
        scgi_request(&all, &body)
    };

    let tcp = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("ngxrs: [error] {kind} connect {addr} failed: {e}");
            return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
        }
        Err(_) => {
            eprintln!("ngxrs: [error] {kind} connect {addr} timed out");
            return Ok(Some(error_out(conn, 504, tokens, req.keepalive).await?));
        }
    };
    let _ = tcp.set_nodelay(true);
    // `suwsgi://` wraps the connection in TLS, presenting the client
    // certificate from `uwsgi_ssl_certificate` when configured.
    let mut stream = match tls {
        Some((cert, key, pw)) => {
            let connector = match crate::tls::upstream_connector_with_client_cert(
                cert,
                key,
                pw,
                true,
                b"",
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("ngxrs: [error] {kind} client certificate: {e}");
                    return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
                }
            };
            let name = rustls::pki_types::ServerName::try_from(addr.ip().to_string())
                .map_err(|_| io::Error::other("bad upstream name"))?;
            match tokio::time::timeout(connect_timeout, connector.connect(name, tcp)).await {
                Ok(Ok(s)) => crate::proxy::UpStream::Tls(Box::new(s)),
                Ok(Err(e)) => {
                    eprintln!("ngxrs: [error] {kind} TLS handshake {addr} failed: {e}");
                    return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
                }
                Err(_) => {
                    eprintln!("ngxrs: [error] {kind} TLS handshake {addr} timed out");
                    return Ok(Some(error_out(conn, 504, tokens, req.keepalive).await?));
                }
            }
        }
        None => crate::proxy::UpStream::Tcp(tcp),
    };
    if let Err(e) = stream.write_all(&packet).await {
        eprintln!("ngxrs: [error] {kind} write failed: {e}");
        return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
    }
    // Over TLS the packet only lands in rustls' internal buffer until a flush,
    // so `suwsgi://` would wait forever for a reply to a request never sent.
    // A no-op for plain TCP.
    if let Err(e) = stream.flush().await {
        eprintln!("ngxrs: [error] {kind} flush failed: {e}");
        return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
    }

    // uwsgi/SCGI responses are length-delimited or terminated by EOF.
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = match tokio::time::timeout(read_timeout, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("ngxrs: [error] {kind} read failed: {e}");
                return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?));
            }
            Err(_) => {
                eprintln!("ngxrs: [error] {kind} read timed out");
                return Ok(Some(error_out(conn, 504, tokens, req.keepalive).await?));
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        // Stop as soon as the head plus a declared Content-Length is complete.
        if let Some(sep) = memchr::memmem::find(&buf, b"\r\n\r\n") {
            let head = &buf[..sep];
            if let Some(len) = content_length_of(head) {
                let have = buf.len() - (sep + 4);
                if have as u64 >= len {
                    break;
                }
            }
        }
    }

    let (status, headers, payload, had_length) = parse_cgi(&buf);
    let (raw, framed) = frame_response(status, &headers, &payload, had_length);
    let resp = Response {
        status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,

        headers_finalized: false,
        body: Body::Bytes(framed),
    };
    let bytes = crate::http::write_response(
        conn,
        resp,
        req.keepalive,
        tokens,
        req.method == crate::http::request::Method::Head,
    )
    .await?;
    Ok(Some(Outcome {
        status,
        bytes,
        close: false,
        sent: Vec::new(),
    }))
}

fn content_length_of(head: &[u8]) -> Option<u64> {
    for line in String::from_utf8_lossy(head).split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

async fn error_out(
    conn: &mut Conn,
    status: u16,
    tokens: bool,
    keepalive: bool,
) -> io::Result<Outcome> {
    let body = error_body(status, tokens);
    let mut raw = Vec::with_capacity(96);
    raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
    raw.extend_from_slice(body.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n");
    let resp = Response {
        status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,

        headers_finalized: false,
        body: Body::Bytes(body),
    };
    let bytes = crate::http::write_response(conn, resp, keepalive, tokens, false).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
        sent: Vec::new(),
    })
}

pub async fn handle_uwsgi(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    query: &str,
    loc: &crate::config::LocCfg,
    tokens: bool,
    vars: &crate::http::ServerVars<'_>,
) -> io::Result<Option<Outcome>> {
    let Some(pass) = &loc.uwsgi_pass else {
        return Ok(None);
    };
    // `suwsgi://` needs a client certificate; without one the handshake cannot
    // succeed, so report 502 like any other upstream setup failure.
    let cert_pair: Option<(std::path::PathBuf, std::path::PathBuf, Vec<String>)> = if pass.tls {
        match (&loc.uwsgi_ssl_certificate, &loc.uwsgi_ssl_certificate_key) {
            (Some(c), Some(k)) => Some((
                std::path::PathBuf::from(vars.expand(&c.to_string_lossy())),
                std::path::PathBuf::from(vars.expand(&k.to_string_lossy())),
                loc.uwsgi_ssl_password_file
                    .as_ref()
                    .and_then(|p| crate::tls::read_passwords(p).ok())
                    .unwrap_or_default(),
            )),
            _ => return Ok(Some(error_out(conn, 502, tokens, req.keepalive).await?)),
        }
    } else {
        None
    };
    run(
        conn,
        req,
        path,
        query,
        loc,
        pass.addr,
        "uwsgi",
        &loc.uwsgi_params,
        pass.connect_timeout,
        pass.read_timeout,
        tokens,
        cert_pair.as_ref(),
    )
    .await
}

pub async fn handle_scgi(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    query: &str,
    loc: &crate::config::LocCfg,
    tokens: bool,
) -> io::Result<Option<Outcome>> {
    let Some(pass) = &loc.scgi_pass else {
        return Ok(None);
    };
    run(
        conn,
        req,
        path,
        query,
        loc,
        pass.addr,
        "scgi",
        &loc.scgi_params,
        pass.connect_timeout,
        pass.read_timeout,
        tokens,
        None,
    )
    .await
}
