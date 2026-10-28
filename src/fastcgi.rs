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

use crate::config::typed::Http;
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
    /// `$slice_range`: the `Range` for the current slice, forwarded by
    /// `fastcgi_param Range $slice_range` (`ngx_http_slice_filter_module`).
    slice_range: &'a str,
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
            "slice_range" => Some(v.slice_range),
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
                } else if let Some(want) = name.strip_prefix("arg_") {
                    // `$arg_*` is needed by `fastcgi_pass $arg_b` and by
                    // `fastcgi_param X $arg_y`; nginx does not percent-decode
                    // it, and the key match ignores case.
                    v.args
                        .split('&')
                        .filter_map(|p| p.split_once('='))
                        .find(|(k, _)| k.eq_ignore_ascii_case(want))
                        .map(|(_, val)| val)
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
    let mut status_given = false;
    let mut have_location = false;
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
            status_given = true;
            continue;
        }
        if name.eq_ignore_ascii_case("location") {
            have_location = true;
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
    // `ngx_http_fastcgi_module`: no `Status` line plus a `Location` header is
    // a 302, which is how a CGI script redirects.
    if !status_given && have_location {
        status = 302;
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
    http: &Http,
    body: &[u8],
    peer_ip: &str,
    slice_range: &str,
    // `fastcgi_request_buffering off`: read the rest of the body from `conn` and
    // forward it as it arrives, instead of taking a complete body. The connection
    // to the responder is made before the body is read, which is what
    // `fastcgi_request_buffering.t` observes with `accept()`.
    mut body_stream: Option<(&mut crate::conn::Conn, u64)>,
) -> Option<(Response, bool)> {
    // `fastcgi_cache`: a hit is served without contacting the responder at all,
    // and a miss stores what came back against `fastcgi_cache_key`.
    let zone = loc
        .fastcgi_cache
        .as_deref()
        .and_then(|name| http.cache_zones.iter().find(|z| z.name == name));
    let key = zone.map(|_| fastcgi_cache_key(loc, req, slice_range));
    let mut cache_status = "MISS";
    // A hit is served without contacting the responder. It is *not* returned
    // immediately: `add_header` still has to run for it, and skipping that is
    // why a cached reply had no `X-Cache-Status` at all
    // (`slice.t`, "fastcgi cached").
    let mut hit: Option<(Response, bool)> = None;
    if let (Some(z), Some(k)) = (zone, key.as_deref()) {
        if let Some((entry, _sig)) = crate::cache::lookup(z, k, |_| String::new()) {
            if entry.is_fresh(crate::cache::now()) && entry.error.is_none() {
                let had_len = entry
                    .headers
                    .iter()
                    .any(|(h, _)| h.eq_ignore_ascii_case("content-length"));
                hit = Some((cached_to_response(&entry, "HIT"), had_len));
                cache_status = "HIT";
            }
        }
    }
    let mut out = match hit {
        Some(v) => v,
        None => {
            fetch_uncached(
                req,
                path,
                query,
                loc,
                http,
                body,
                peer_ip,
                slice_range,
                body_stream.as_mut().map(|(c, n)| (&mut **c, *n)),
            )
            .await?
        }
    };
    // `handle` writes the response straight to the connection -- it does not go
    // through `finalize_response` -- so `add_header` has to be applied here, the
    // way the proxy module does it.
    {
        let resp_headers = crate::http::split_head(&out.0.raw);
        crate::http::apply_add_headers_full(
            &mut out.0.raw,
            &loc.headers,
            out.0.status,
            cache_status,
            "",
            &resp_headers,
        );
        out.0.headers_finalized = true;
        out.0.cache_status = Some(cache_status.to_string());
    }
    if cache_status == "HIT" {
        return Some(out);
    }

    if let (Some(z), Some(k)) = (zone, key.as_deref()) {
        let resp = &out.0;
        let headers = crate::http::split_head(&resp.raw);
        // A 206 slice is stored like any other response: `slice.t` expects each
        // slice to be its own entry, keyed by `$slice_range`.
        if let Some(ttl) = crate::cache::ttl_fastcgi(loc, resp.status, &headers) {
            let stored: Vec<(String, String)> = headers
                .iter()
                .filter(|(h, _)| {
                    !h.eq_ignore_ascii_case("connection")
                        && !h.eq_ignore_ascii_case("keep-alive")
                        && !h.eq_ignore_ascii_case("transfer-encoding")
                })
                .cloned()
                .collect();
            let body_bytes = match &resp.body {
                Body::Bytes(b) => b.clone(),
                _ => Vec::new(),
            };
            let entry = crate::cache::Cached {
                status: resp.status,
                error: None,
                headers: stored,
                body: body_bytes,
                stored_at: crate::cache::now(),
                valid_for: ttl.as_secs(),
            };
            let _ = crate::cache::store(z, k, &entry);
        }
        // `$upstream_cache_status` is read by `add_header` during
        // finalisation, so it has to travel on the response.
        let mut resp = out.0;
        mark_cache_status(&mut resp, cache_status);
        return Some((resp, out.1));
    }
    Some(out)
}

/// The key `fastcgi_cache_key` expands to; `$request_uri` when unset, matching
/// nginx's default for the module.
fn fastcgi_cache_key(loc: &LocCfg, req: &Request, slice_range: &str) -> String {
    match loc.fastcgi_cache_key.as_deref() {
        None => req.raw_target.clone(),
        Some(spec) => {
            let (uri, args) = match req.raw_target.split_once('?') {
                Some((u, a)) => (u, a),
                None => (req.raw_target.as_str(), ""),
            };
            crate::cache::expand_key(
                spec,
                "http",
                "",
                req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
                &req.raw_target,
                uri,
                args,
                "",
                req.method.as_str(),
                slice_range,
            )
        }
    }
}

/// Rebuild a `Response` from a stored entry.
fn cached_to_response(entry: &crate::cache::Cached, status: &str) -> Response {
    let mut raw = Vec::with_capacity(entry.body.len() + 256);
    for (k, v) in &entry.headers {
        raw.extend_from_slice(k.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(v.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    if !entry
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        raw.extend_from_slice(b"Content-Length: ");
        raw.extend_from_slice(entry.body.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    Response {
        status: entry.status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,
        server_tokens: None,
        cache_status: Some(status.to_string()),
        headers_finalized: false,
        body: Body::Bytes(entry.body.clone()),
    }
}

/// Record the cache status for `$upstream_cache_status`.
fn mark_cache_status(resp: &mut Response, status: &str) {
    resp.cache_status = Some(status.to_string());
}

async fn fetch_uncached(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    http: &Http,
    body: &[u8],
    peer_ip: &str,
    slice_range: &str,
    mut body_stream: Option<(&mut crate::conn::Conn, u64)>,
) -> Option<(Response, bool)> {
    let fcgi = loc.fastcgi_pass.as_ref()?;
    let cap = loc.client_body_buffer_size as usize;

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
        slice_range,
    };

    // `fastcgi_pass $var` is resolved here, once the variables are known. The
    // value may be an `upstream` name or a literal `host:port`.
    let addr: SocketAddr = if fcgi.dynamic {
        let target = expand(&fcgi.spec, &vars);
        match resolve_dynamic(&target, http) {
            Some(a) => a,
            None => {
                eprintln!("ngxrs: [error] fastcgi_pass \"{target}\" is not a resolvable address");
                return Some((error_response(502), true));
            }
        }
    } else {
        fcgi.addr
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
    if body_stream.is_none() && !body.is_empty() {
        write_record(&mut out, FCGI_STDIN, req_id, &body);
    }
    if body_stream.is_none() {
        write_record(&mut out, FCGI_STDIN, req_id, &[]);
    } else if let Some((conn, left)) = body_stream.as_mut() {
        // Body bytes that arrived together with the request head go out in the
        // same write as BEGIN/PARAMS: the responder in
        // `fastcgi_request_buffering.t` does one `sysread` after `accept` and
        // expects the STDIN record to be in it (`"preread - preread"`).
        let n = conn.buffered_len().min(*left as usize);
        if n > 0 {
            match conn.take_available(n).await {
                Ok(chunk) => {
                    crate::proxy::retain_streamed_pub(req, &chunk, cap);
                    write_record(&mut out, FCGI_STDIN, req_id, &chunk);
                    *left -= chunk.len() as u64;
                }
                Err(e) => {
                    eprintln!("ngxrs: [error] fastcgi read body: {e}");
                    return Some((error_response(502), true));
                }
            }
        }
    }

    if let Err(e) = stream.write_all(&out).await {
        eprintln!("ngxrs: [error] fastcgi write failed: {e}");
        return Some((error_response(502), true));
    }

    // Unbuffered: BEGIN + PARAMS are already on the wire (so the responder can
    // start), and each body chunk travels as its own STDIN record as the client
    // produces it.
    if let Some((conn, mut left)) = body_stream {
        while left > 0 {
            let want = left.min(64 * 1024) as usize;
            let chunk = match conn.take_available(want).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("ngxrs: [error] fastcgi read body: {e}");
                    return Some((error_response(502), true));
                }
            };
            if chunk.is_empty() {
                eprintln!("ngxrs: [error] client closed before the request body was complete");
                return Some((error_response(502), true));
            }
            left -= chunk.len() as u64;
            crate::proxy::retain_streamed_pub(req, &chunk, cap);
            let mut rec = Vec::with_capacity(chunk.len() + 8);
            write_record(&mut rec, FCGI_STDIN, req_id, &chunk);
            if let Err(e) = stream.write_all(&rec).await {
                eprintln!("ngxrs: [error] fastcgi write failed: {e}");
                return Some((error_response(502), true));
            }
        }
        let mut end = Vec::with_capacity(8);
        write_record(&mut end, FCGI_STDIN, req_id, &[]);
        if let Err(e) = stream.write_all(&end).await {
            eprintln!("ngxrs: [error] fastcgi write failed: {e}");
            return Some((error_response(502), true));
        }
    }

    // ---- read the responder's STDOUT ----
    let mut stdout: Vec<u8> = Vec::with_capacity(8192);
    let mut ended = false;
    let mut caught_stderr = false;
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
                // `fastcgi_catch_stderr`: a responder that reports an error on
                // STDERR is answering 502, not a page with a hole in it.
                if caught_stderr {
                    continue;
                }
                if loc
                    .fastcgi_catch_stderr
                    .iter()
                    .any(|pat| !pat.is_empty() && msg.contains(pat.as_str()))
                {
                    caught_stderr = true;
                }
            }
            FCGI_END_REQUEST => ended = true,
            _ => {}
        }
    }

    if caught_stderr {
        return Some((error_response(502), true));
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
        server_tokens: None,
        cache_status: None,
        headers_finalized: false,
        body: Body::Bytes(payload),
    }, had_length))
}

/// Resolve a per-request `fastcgi_pass` value: an `upstream` name, or
/// `host:port`, or `unix:/path`.
///
/// nginx's `ngx_http_upstream_init_request` does the same thing: a URL whose
/// host is an upstream name goes through that upstream, anything else is
/// parsed as `host:port`.
fn resolve_dynamic(target: &str, http: &Http) -> Option<SocketAddr> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix("unix:") {
        // A unix target is not a SocketAddr; the caller cannot express it, so
        // report it rather than silently connecting to the wrong place.
        eprintln!("ngxrs: [error] fastcgi_pass unix:{rest} is not supported yet");
        return None;
    }
    let name = match target.rsplit_once(':') {
        // `host:port` and `[v6]:port` both keep the port after the last colon.
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() => {
            let _ = host;
            None
        }
        _ => Some(target),
    };
    if let Some(name) = name {
        // No port at all: an upstream name.
        let up = http.upstreams.iter().find(|u| u.name == name)?;
        let peer = up.servers.iter().find(|s| !s.down)?;
        return Some(peer.addr);
    }
    if let Some((host, port)) = target.rsplit_once(':') {
        let port: u16 = port.parse().ok()?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }
        // A hostname here would need the `resolver` at request time; nginx
        // resolves a literal upstream host at configuration time instead, so a
        // name that reaches this point is a configuration error.
        return None;
    }
    None
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
        server_tokens: None,
        cache_status: None,
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
    http: &Http,
    tokens: bool,
) -> io::Result<Option<Outcome>> {
    if loc.fastcgi_pass.is_none() {
        return Ok(None);
    }

    // RFC 7231: never send 100 Continue to an HTTP/1.0 client.
    if req.expect_continue && req.version_minor == 1 {
        conn.send_100_continue().await?;
    }
    // `fastcgi_request_buffering off`: do not read the body here — the responder
    // connection has to be made first, and the body is streamed into STDIN as it
    // arrives. A chunked body still buffers: it would have to be re-framed.
    // A chunked body still buffers. Streaming it needs the client's chunk
    // framing parsed incrementally and re-emitted as STDIN records; a first
    // attempt took `fastcgi_request_buffering_chunked.t` from 17/21 to 12/21, so
    // it is reverted rather than shipped half-working.
    let stream_rest: u64 = if loc.fastcgi_request_buffering || req.buffered_body.is_some() {
        0
    } else {
        req.body_len
    };
    let body = if stream_rest > 0 {
        Vec::new()
    } else {
        crate::proxy::take_request_body(conn, req, 32 * 1024 * 1024).await?
    };
    let peer = conn.peer.ip().to_string();

    // `slice` needs the whole entity assembled before anything is written, so a
    // sliced location takes the buffered route even on HTTP/1. nginx's slice
    // module is a filter: it drives subrequests and rewrites the response, which
    // is exactly buffering.
    let fetched = match loc.slice {
        None => {
            let hook = if stream_rest > 0 {
                Some((&mut *conn, stream_rest))
            } else {
                None
            };
            fetch(req, path, query, loc, http, &body, &peer, "", hook).await
        }
        Some(n) => crate::proxy::fetch_sliced_for(
            crate::proxy::SliceMode::Fastcgi,
            req,
            path,
            query,
            loc,
            http,
            &peer,
            n,
        )
        .await
        .map(|r| (r, true)),
    };
    let Some((resp, had_length)) = fetched else {
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
        server_tokens: None,
        cache_status: None,

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
