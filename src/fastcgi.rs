//! FastCGI client (nginx's `fastcgi_pass` / `fastcgi_param` family).
//!
//! Speaks the FastCGI 1.0 record protocol to a responder such as php-fpm and
//! converts its `STDOUT` stream (CGI headers + body) into an HTTP response.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{FastcgiParam, LocCfg};
use crate::conn::Conn;
use crate::http::request::Request;
use crate::http::{error_body, Body, Outcome, Response};

// ---- protocol constants ---------------------------------------------------

const FCGI_VERSION_1: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;

const MAX_STDOUT: usize = 64 * 1024 * 1024;

fn record_header(ty: u8, req_id: u16, content_len: u16, padding: u8) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = FCGI_VERSION_1;
    h[1] = ty;
    h[2..4].copy_from_slice(&req_id.to_be_bytes());
    h[4..6].copy_from_slice(&content_len.to_be_bytes());
    h[6] = padding;
    h[7] = 0;
    h
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let v = (len as u32) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Split the name/value pairs of one PARAMS record stream into <=64 KB chunks.
fn encode_params(params: &[(String, String)]) -> Vec<Vec<u8>> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::with_capacity(1024);
    for (name, value) in params {
        let mut pair = Vec::with_capacity(name.len() + value.len() + 8);
        push_len(&mut pair, name.len());
        push_len(&mut pair, value.len());
        pair.extend_from_slice(name.as_bytes());
        pair.extend_from_slice(value.as_bytes());
        if cur.len() + pair.len() > 65_000 && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
        }
        cur.extend_from_slice(&pair);
    }
    chunks.push(cur);
    chunks
}

fn write_record(out: &mut Vec<u8>, ty: u8, req_id: u16, content: &[u8]) {
    let mut off = 0;
    if content.is_empty() {
        out.extend_from_slice(&record_header(ty, req_id, 0, 0));
        return;
    }
    while off < content.len() {
        let take = (content.len() - off).min(65_535);
        out.extend_from_slice(&record_header(ty, req_id, take as u16, 0));
        out.extend_from_slice(&content[off..off + take]);
        off += take;
    }
}

// ---- request building -----------------------------------------------------

struct Vars<'a> {
    req: &'a Request,
    peer_ip: &'a str,
    server_port: u16,
    server_name: &'a str,
    document_root: &'a str,
    script_name: &'a str,
    path_info: &'a str,
    document_uri: &'a str,
    request_uri: &'a str,
    args: &'a str,
    scheme: &'a str,
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
        let name_len = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if name_len == 0 {
            out.push('$');
            i += 1;
            continue;
        }
        let name = &rest[..name_len];
        let value = match name {
            "document_root" => Some(v.document_root),
            "realpath_root" => Some(v.document_root),
            "document_uri" | "uri" => Some(v.document_uri),
            "request_uri" => Some(v.request_uri),
            "query_string" | "args" => Some(v.args),
            "request_method" => Some(v.req.method.as_str()),
            "request_scheme" | "scheme" => Some(v.scheme),
            "server_name" => Some(v.server_name),
            "server_port" => None, // formatted below
            "remote_addr" => Some(v.peer_ip),
            "remote_port" => None,
            "server_protocol" => Some(if v.req.version_minor == 1 {
                "HTTP/1.1"
            } else {
                "HTTP/1.0"
            }),
            "content_length" => v.req.headers.get("content-length"),
            "content_type" => v.req.headers.get("content-type"),
            "script_name" => Some(v.script_name),
            // fastcgi module variables
            "fastcgi_script_name" => Some(v.script_name),
            "fastcgi_path_info" => Some(v.path_info),
            "script_filename" => None,
            "path_info" => Some(v.path_info),
            "request_filename" => None,
            "host" | "http_host" => v.req.host.as_ref().map(|h| h.as_str()),
            "gateway_interface" => Some("CGI/1.1"),
            "nginx_version" => Some("1.28.0"),
            _ => {
                if let Some(h) = name.strip_prefix("http_") {
                    let key = h.replace('_', "-");
                    v.req.headers.get(&key)
                } else {
                    None
                }
            }
        };
        match value {
            Some(val) => {
                out.push_str(val);
                i += 1 + name_len;
            }
            None => {
                // numbers and computed names
                let computed = match name {
                    "server_port" => Some(v.server_port.to_string()),
                    "remote_port" => Some("0".to_string()),
                    // `$content_length` is the request header, empty when absent
                    "content_length" => Some(String::new()),
                    "script_filename" => Some(format!("{}{}", v.document_root, v.script_name)),
                    "request_filename" => Some(format!("{}{}", v.document_root, v.script_name)),
                    _ => None,
                };
                match computed {
                    Some(c) => {
                        out.push_str(&c);
                        i += 1 + name_len;
                    }
                    None => {
                        // Unknown variable: nginx refuses to start; we emit it
                        // verbatim so a typo is visible in the response.
                        out.push('$');
                        i += 1;
                    }
                }
            }
        }
    }
    out
}

/// Split SCRIPT_NAME / PATH_INFO the way `fastcgi_split_path_info` does.
fn split_path(path: &str, loc: &LocCfg) -> (String, String) {
    if let Some(re) = &loc.fastcgi_split_path_info {
        if let Some(caps) = re.captures(path) {
            let script = caps.get(1).map(|m| m.as_str()).unwrap_or(path);
            let info = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            return (script.to_string(), info.to_string());
        }
    }
    // Fallback: everything up to the last `.php` is the script.
    if let Some(idx) = path.rfind(".php") {
        let cut = idx + 4;
        return (path[..cut].to_string(), path[cut..].to_string());
    }
    (path.to_string(), String::new())
}

fn parse_cgi_response(buf: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, bool) {
    // nginx accepts both line endings here (`ngx_http_fastcgi_process_header`
    // scans for `LF LF` and tolerates the CRs), and responders in the wild use
    // both: `fastcgi_cache.t`'s script prints `Location: ...\n` alone. Looking
    // only for CRLFCRLF put the whole header block into the body.
    let (head, body) = if let Some(i) = memchr::memmem::find(buf, b"\r\n\r\n") {
        (&buf[..i], buf[i + 4..].to_vec())
    } else if let Some(i) = memchr::memmem::find(buf, b"\n\n") {
        (&buf[..i], buf[i + 2..].to_vec())
    } else {
        // No header block: treat everything as body, like nginx does for a
        // responder that forgot the blank line.
        (&buf[..0], buf.to_vec())
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

/// One FastCGI exchange, with no socket involved.
///
/// `handle` writes the result to the client connection; the auth-subrequest
/// path (`auth_request` into a `fastcgi_pass` location) needs the response
/// object instead, which is why the exchange lives on its own. `None` means the
/// location does not use FastCGI at all; an upstream failure is reported as the
/// status nginx would answer (502/504) rather than as an `Err`.
pub async fn fetch(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    body: &[u8],
    peer_ip: &str,
) -> Option<(Response, bool)> {
    let fcgi = loc.fastcgi_pass.as_ref()?;
    let addr: SocketAddr = fcgi.addr;

    // ---- build the parameter list
    let (script_name, path_info) = split_path(path, loc);
    let document_root = loc
        .alias
        .as_ref()
        .map(|a| a.to_string_lossy().to_string())
        .unwrap_or_else(|| loc.root.to_string_lossy().to_string());

    let vars = Vars {
        req,
        peer_ip,
        server_port: 80,
        server_name: req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
        document_root: &document_root,
        script_name: &script_name,
        path_info: &path_info,
        document_uri: path,
        request_uri: &req.raw_target,
        args: query,
        scheme: "http",
    };

    let mut params: Vec<(String, String)> = Vec::with_capacity(loc.fastcgi_params.len() + 8);
    params.push(("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string()));
    for p in &loc.fastcgi_params {
        let FastcgiParam { name, value } = p;
        params.push((name.clone(), expand(value, &vars)));
    }

    // ---- send it ----
    let mut stream =
        match tokio::time::timeout(loc.fastcgi_connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("ngxrs: [error] fastcgi connect {addr} failed: {e}");
                return Some((error_response(502), true));
            }
            Err(_) => {
                eprintln!("ngxrs: [error] fastcgi connect {addr} timed out");
                return Some((error_response(504), true));
            }
        };
    let _ = stream.set_nodelay(true);

    let req_id: u16 = 1;
    let mut out = Vec::with_capacity(4096);
    let mut begin = Vec::with_capacity(8);
    begin.extend_from_slice(&FCGI_RESPONDER.to_be_bytes());
    begin.push(0); // flags: no keep-alive
    begin.extend_from_slice(&[0u8; 5]);
    write_record(&mut out, FCGI_BEGIN_REQUEST, req_id, &begin);
    for chunk in encode_params(&params) {
        write_record(&mut out, FCGI_PARAMS, req_id, &chunk);
    }
    write_record(&mut out, FCGI_PARAMS, req_id, &[]);
    if !body.is_empty() {
        write_record(&mut out, FCGI_STDIN, req_id, &body);
    }
    write_record(&mut out, FCGI_STDIN, req_id, &[]);

    if let Err(e) = stream.write_all(&out).await {
        eprintln!("ngxrs: [error] fastcgi write failed: {e}");
        return Some((error_response(502), true));
    }

    // ---- read the responder's STDOUT ----
    let mut stdout: Vec<u8> = Vec::with_capacity(8192);
    let mut ended = false;
    let mut hdr = [0u8; 8];
    while !ended {
        let read =
            tokio::time::timeout(loc.fastcgi_read_timeout, stream.read_exact(&mut hdr)).await;
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => {
                eprintln!("ngxrs: [error] fastcgi read failed: {e}");
                return Some((error_response(502), true));
            }
            Err(_) => {
                crate::log::log_global(crate::log::Level::Error, "fastcgi read timed out");
                return Some((error_response(504), true));
            }
        }
        let ty = hdr[1];
        let id = u16::from_be_bytes([hdr[2], hdr[3]]);
        let len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
        let pad = hdr[6] as usize;
        let mut content = vec![0u8; len];
        if len > 0 {
            match tokio::time::timeout(loc.fastcgi_read_timeout, stream.read_exact(&mut content))
                .await
            {
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        if pad > 0 {
            let mut padding = vec![0u8; pad];
            let _ = stream.read_exact(&mut padding).await;
        }

        if id != req_id && ty != FCGI_END_REQUEST {
            continue;
        }
        match ty {
            FCGI_STDOUT => {
                if stdout.len() + content.len() > MAX_STDOUT {
                    return Some((error_response(502), true));
                }
                stdout.extend_from_slice(&content);
            }
            FCGI_STDERR => {
                let msg = String::from_utf8_lossy(&content).trim().to_string();
                if !msg.is_empty() {
                    eprintln!("ngxrs: [error] fastcgi stderr: {msg}");
                }
            }
            FCGI_END_REQUEST => ended = true,
            _ => {}
        }
    }

    let (status, headers, payload, had_length) = parse_cgi_response(&stdout);
    let mut raw = Vec::with_capacity(256);
    for (k, v) in &headers {
        raw.extend_from_slice(k.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(v.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    // The payload goes out verbatim; `had_length` says whether the responder
    // declared a length, which decides the framing at the write site.
    if had_length {
        raw.extend_from_slice(b"Content-Length: ");
        raw.extend_from_slice(payload.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    Some((Response {
        status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,
        headers_finalized: false,
        body: Body::Bytes(payload),
    }, had_length))
}

/// A FastCGI failure, as the status nginx answers for it.
fn error_response(status: u16) -> Response {
    let body = error_body(status, false);
    let mut raw = Vec::with_capacity(96);
    raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
    raw.extend_from_slice(body.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n");
    Response {
        status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,
        headers_finalized: false,
        body: Body::Bytes(body),
    }
}

/// Write a FastCGI response to the client. `None` when the location is not a
/// FastCGI one.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    tokens: bool,
) -> io::Result<Option<Outcome>> {
    if loc.fastcgi_pass.is_none() {
        return Ok(None);
    }

    // RFC 7231: never send 100 Continue to an HTTP/1.0 client.
    if req.expect_continue && req.version_minor == 1 {
        conn.send_100_continue().await?;
    }
    let body = crate::proxy::take_request_body(conn, req, 32 * 1024 * 1024).await?;
    let peer = conn.peer.ip().to_string();

    let Some((resp, had_length)) = fetch(req, path, query, loc, &body, &peer).await else {
        return Ok(None);
    };
    let status = resp.status;
    let mut resp = resp;
    // nginx streams a CGI response with no Content-Length using chunked
    // encoding; reproducing that keeps the wire format identical. `raw` already
    // carries the Content-Length when the responder declared one.
    if !had_length {
        resp.raw
            .extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        let payload = match std::mem::replace(&mut resp.body, Body::Empty) {
            Body::Bytes(b) => b,
            other => {
                resp.body = other;
                Vec::new()
            }
        };
        let mut chunked = Vec::with_capacity(payload.len() + 32);
        if !payload.is_empty() {
            chunked.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            chunked.extend_from_slice(&payload);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        resp.body = Body::Bytes(chunked);
    }
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

async fn respond(
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

#[allow(dead_code)]
fn unused(_: HashMap<String, String>, _: Duration) {}
