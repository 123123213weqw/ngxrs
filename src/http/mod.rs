//! HTTP/1.1 request handling: routing, responses, access logging.

pub mod request;
pub mod static_file;

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::timeout;

use crate::config::{Config, Http, ListenGroup, LocCfg, Server};
use crate::conn::{Conn, RecvError, MAX_HEADER_BYTES, MAX_REQUEST_LINE};
use crate::log::Logger;
use crate::util::{self, reason};

use request::{Method, Request};

pub struct Ctx {
    pub config: Arc<Config>,
    pub logger: Arc<Logger>,
}

pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    File { file: File, offset: u64, len: u64 },
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Body {
    pub fn is_empty(&self) -> bool {
        matches!(self, Body::Empty)
    }
}

impl Response {
    pub fn empty(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    pub fn bytes(status: u16, ctype: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            headers: vec![("Content-Type".to_string(), ctype.to_string())],
            body: Body::Bytes(body),
        }
    }

    pub fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_string(), v.into()));
        self
    }
}

const SMALL_FILE_WRITE: u64 = 16 * 1024;

pub struct Outcome {
    pub status: u16,
    pub bytes: u64,
    pub close: bool,
}

pub async fn handle_conn(mut conn: Conn, group: &ListenGroup, ctx: &Ctx) {
    let http = &ctx.config.http;
    let first_server = http.server(group.default_server);
    let keepalive_timeout = first_server.keepalive_timeout;
    let mut served: u64 = 0;

    loop {
        let read_timeout = if served == 0 {
            Duration::from_secs(60)
        } else {
            keepalive_timeout
        };
        let read = timeout(
            read_timeout,
            conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES),
        )
        .await;

        let req = match read {
            Err(_elapsed) => {
                if served == 0 {
                    let _ = send_error(&mut conn, 408, true, served == 0, false).await;
                }
                break;
            }
            Ok(Err(RecvError::Io(_e))) => break,
            Ok(Err(RecvError::Bad(e))) => {
                let tokens = http.server(group.default_server).server_tokens;
                let _ = send_error(&mut conn, e.status, tokens, false, false).await;
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(r))) => r,
        };
        served += 1;

        let (path, query) = match util::parse_target(&req.raw_target) {
            Ok(v) => v,
            Err(_) => {
                let tokens = http.server(group.default_server).server_tokens;
                let _ = send_error(&mut conn, 400, tokens, false, false).await;
                break;
            }
        };

        let server = select_server(http, group, req.host.as_deref());
        let loc = server.locate(&path);

        // Request body handling (static server discards it, like nginx).
        if req.chunked {
            if loc.client_max_body_size != u64::MAX && req.body_len > loc.client_max_body_size {
                let _ = send_error(&mut conn, 413, server.server_tokens, false, false).await;
                break;
            }
            if req.expect_continue {
                let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            }
            if conn.drain_chunked().await.is_err() {
                break;
            }
        } else if req.body_len > 0 {
            if loc.client_max_body_size != u64::MAX && req.body_len > loc.client_max_body_size {
                let _ = send_error(&mut conn, 413, server.server_tokens, false, false).await;
                break;
            }
            if req.expect_continue {
                let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            }
            if conn.drain_body(req.body_len).await.is_err() {
                break;
            }
        }

        let started = SystemTime::now();
        let outcome = dispatch(&mut conn, &req, &path, &query, server, loc, http, group.addr.port()).await;
        let elapsed = started.elapsed().unwrap_or_default();

        let (status, bytes, close) = match outcome {
            Ok(o) => (o.status, o.bytes, o.close),
            Err(_e) => (499, 0, true),
        };

        log_access(ctx, group, server, &req, &path, &query, status, bytes, elapsed, conn.peer);

        if close || !req.keepalive || served >= http.keepalive_requests {
            break;
        }
    }

    conn.shutdown().await;
}

async fn dispatch(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
    listen_port: u16,
) -> io::Result<Outcome> {
    let head_only = req.method == Method::Head;

    if !req.method.is_read() {
        let body = error_body(405, server.server_tokens);
        let resp = Response {
            status: 405,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ],
            body: Body::Bytes(body),
        };
        let bytes = write_response(conn, resp, req.keepalive, server.server_tokens, head_only).await?;
        return Ok(Outcome {
            status: 405,
            bytes,
            close: false,
        });
    }

    if loc.internal {
        return send_error_into(conn, 404, server.server_tokens, req.keepalive, head_only).await;
    }

    if let Some((code, body)) = &loc.ret {
        let status = *code;
        let mut resp;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            resp = Response::empty(status).header("Location", body.clone());
            resp = resp.header("Content-Length", "0");
        } else if body.is_empty() {
            resp = Response::empty(status).header("Content-Length", "0");
        } else {
            let mut r = Response::bytes(status, "text/plain", body.clone().into_bytes());
            r.headers.push(("Content-Length".into(), body.len().to_string()));
            resp = r;
        }
        let bytes = write_response(conn, resp, req.keepalive, server.server_tokens, head_only).await?;
        return Ok(Outcome {
            status,
            bytes,
            close: false,
        });
    }

    if !loc.try_files.is_empty() {
        if let Some(outcome) = try_files(conn, req, path, loc, server, http).await? {
            return Ok(outcome);
        }
    }

    let resp = match static_file::respond(req, path, query, loc, http) {
        Ok(r) => r,
        Err(_) => Response::empty(404),
    };

    let status = resp.status;
    let _ = query;

    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        return write_redirect(conn, req, resp, listen_port, server.server_tokens).await;
    }

    if status >= 400 && resp.body.is_empty() {
        return send_error_into(conn, status, server.server_tokens, req.keepalive, head_only).await;
    }
    let bytes = write_response(conn, resp, req.keepalive, server.server_tokens, head_only).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

/// nginx answers directory redirects with an absolute Location and a small
/// HTML body; mirror that (absolute_redirect / port_in_redirect defaults).
async fn write_redirect(
    conn: &mut Conn,
    req: &Request,
    resp: Response,
    listen_port: u16,
    tokens: bool,
) -> io::Result<Outcome> {
    let status = resp.status;
    let mut headers = resp.headers;
    let location = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let absolute = if location.starts_with('/') {
        let host = req.host.clone().unwrap_or_default();
        let host_has_port = host.rsplit_once(':').map(|(_, p)| p.parse::<u16>().is_ok()).unwrap_or(false);
        let host = if host_has_port || listen_port == 80 {
            host
        } else {
            format!("{host}:{listen_port}")
        };
        format!("http://{host}{location}")
    } else {
        location
    };

    headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("location")
            && !k.eq_ignore_ascii_case("content-length")
            && !k.eq_ignore_ascii_case("content-type")
    });
    headers.push(("Location".to_string(), absolute));
    let body = error_body(status, tokens);
    headers.push(("Content-Type".to_string(), "text/html".to_string()));
    headers.push(("Content-Length".to_string(), body.len().to_string()));

    let bytes = write_response(
        conn,
        Response {
            status,
            headers,
            body: Body::Bytes(body),
        },
        req.keepalive,
        tokens,
        req.method == Method::Head,
    )
    .await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

async fn try_files(
    conn: &mut Conn,
    req: &Request,
    path: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
) -> io::Result<Option<Outcome>> {
    let n = loc.try_files.len();
    for (i, cand) in loc.try_files.iter().enumerate() {
        let last = i + 1 == n;
        if let Some(code) = cand.strip_prefix('=') {
            if let Ok(status) = code.parse::<u16>() {
                let o = send_error_into(conn, status, server.server_tokens, req.keepalive, req.method == Method::Head).await?;
                return Ok(Some(o));
            }
            continue;
        }
        let expanded = cand.replace("$uri", path).replace("$uri/", path);
        let rel = expanded.trim_start_matches('/');
        let fs_path = loc.root.join(rel);
        let is_dir_hint = expanded.ends_with('/');
        if fs_path.exists() && (!is_dir_hint || fs_path.is_dir()) {
            let resp = static_file::respond_fs(req, &fs_path, path, loc, http)?;
            let status = resp.status;
            let head_only = req.method == Method::Head;
            let bytes = write_response(conn, resp, req.keepalive, server.server_tokens, head_only).await?;
            return Ok(Some(Outcome { status, bytes, close: false }));
        }
        if last {
            let o = send_error_into(conn, 404, server.server_tokens, req.keepalive, req.method == Method::Head).await?;
            return Ok(Some(o));
        }
    }
    Ok(None)
}

async fn send_error_into(
    conn: &mut Conn,
    status: u16,
    tokens: bool,
    keepalive: bool,
    head_only: bool,
) -> io::Result<Outcome> {
    let bytes = send_error(conn, status, tokens, keepalive, head_only).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

pub async fn send_error(
    conn: &mut Conn,
    status: u16,
    tokens: bool,
    keepalive: bool,
    head_only: bool,
) -> io::Result<u64> {
    let body = error_body(status, tokens);
    let resp = Response {
        status,
        headers: vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Content-Length".to_string(), body.len().to_string()),
        ],
        body: Body::Bytes(body),
    };
    write_response(conn, resp, keepalive, tokens, head_only).await
}

pub fn error_body(status: u16, tokens: bool) -> Vec<u8> {
    let reason = reason(status);
    let signature = if tokens {
        format!("nginx/{}", crate::COMPAT_VERSION)
    } else {
        "nginx".to_string()
    };
    format!(
        "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n<center><h1>{status} {reason}</h1></center>\r\n<hr><center>{signature}</center>\r\n</body>\r\n</html>\r\n"
    )
    .into_bytes()
}

pub async fn write_response(
    conn: &mut Conn,
    resp: Response,
    keepalive: bool,
    tokens: bool,
    head_only: bool,
) -> io::Result<u64> {
    let mut headers = resp.headers;
    let known = |name: &str, headers: &[(String, String)]| {
        headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    };

    let body_len = match &resp.body {
        Body::Empty => 0,
        Body::Bytes(b) => b.len() as u64,
        Body::File { len, .. } => *len,
    };

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(resp.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason(resp.status).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(if tokens {
        b"Server: nginx/1.28.0\r\n"
    } else {
        b"Server: nginx\r\n"
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    util::write_date_header(&mut out, now);

    if !known("Content-Length", &headers) && !matches!(resp.status, 204 | 304) {
        headers.push(("Content-Length".to_string(), body_len.to_string()));
    }

    for (k, v) in &headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: ");
    out.extend_from_slice(if keepalive { b"keep-alive" } else { b"close" });
    out.extend_from_slice(b"\r\n\r\n");

    if head_only {
        conn.write_all(&out).await?;
        return Ok(0);
    }

    match resp.body {
        Body::Empty => {
            conn.write_all(&out).await?;
            Ok(0)
        }
        Body::Bytes(b) => {
            out.extend_from_slice(&b);
            conn.write_all(&out).await?;
            Ok(b.len() as u64)
        }
        // Small files: one write beats header+sendfile (two segments on the
        // wire, two syscalls). Large files stay zero-copy.
        Body::File { file, offset, len } if len <= SMALL_FILE_WRITE => {
            use std::os::unix::fs::FileExt;
            let start = out.len();
            out.resize(start + len as usize, 0);
            let mut read_total = 0usize;
            while read_total < len as usize {
                match file.read_at(&mut out[start + read_total..], offset + read_total as u64) {
                    Ok(0) => break,
                    Ok(n) => read_total += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            out.truncate(start + read_total);
            conn.write_all(&out).await?;
            Ok(read_total as u64)
        }
        Body::File { file, offset, len } => {
            if conn.tcp_nopush {
                conn.set_cork(true);
                let w = conn.write_all(&out).await;
                if w.is_err() {
                    conn.set_cork(false);
                    return w.map(|_| 0);
                }
                let sent = conn.send_file(&file, offset, len).await;
                conn.set_cork(false);
                sent
            } else {
                conn.write_all(&out).await?;
                conn.send_file(&file, offset, len).await
            }
        }
    }
}

pub fn select_server<'a>(http: &'a Http, group: &ListenGroup, host: Option<&str>) -> &'a Server {
    let host = host.map(|h| {
        // strip :port, including bracketed IPv6
        if h.starts_with('[') {
            match h.find(']') {
                Some(i) => &h[..=i],
                None => h,
            }
        } else {
            match h.rfind(':') {
                Some(i) if h[i + 1..].chars().all(|c| c.is_ascii_digit()) => &h[..i],
                _ => h,
            }
        }
    });

    if let Some(h) = host {
        let lower = h.to_ascii_lowercase();
        for &idx in &group.servers {
            let s = http.server(idx);
            for n in &s.names {
                if n.eq_ignore_ascii_case(&lower) {
                    return s;
                }
            }
        }
        for &idx in &group.servers {
            let s = http.server(idx);
            for n in &s.names {
                if let Some(suffix) = n.strip_prefix("*.") {
                    if lower.ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
                        || lower == suffix.to_ascii_lowercase()
                    {
                        return s;
                    }
                } else if let Some(suffix) = n.strip_prefix('.') {
                    if lower.ends_with(&format!(".{}", suffix.to_ascii_lowercase())) {
                        return s;
                    }
                }
            }
        }
        for &idx in &group.servers {
            let s = http.server(idx);
            for re in &s.regex_names {
                if re.is_match(&lower) {
                    return s;
                }
            }
        }
    }

    http.server(group.default_server)
}

#[allow(clippy::too_many_arguments)]
fn log_access(
    ctx: &Ctx,
    group: &ListenGroup,
    server: &Server,
    req: &Request,
    path: &str,
    query: &str,
    status: u16,
    bytes: u64,
    _elapsed: Duration,
    peer: std::net::SocketAddr,
) {
    if server.access_logs.is_empty() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut request_line = String::with_capacity(64);
    request_line.push_str(req.method.as_str());
    request_line.push(' ');
    request_line.push_str(&req.raw_target);
    request_line.push_str(if req.version_minor == 1 {
        " HTTP/1.1"
    } else {
        " HTTP/1.0"
    });

    let status_s = status.to_string();
    let bytes_s = bytes.to_string();
    let port_s = group.addr.port().to_string();
    let host = req.host.as_deref().unwrap_or("");
    let ua = req.headers.get("user-agent").unwrap_or("");
    let referer = req.headers.get("referer").unwrap_or("");
    let server_name = server.names.first().map(|s| s.as_str()).unwrap_or("");
    let peer = peer.ip().to_string();

    let vars: &[(&str, &str)] = &[
        ("remote_addr", &peer),
        ("remote_port", "0"),
        ("remote_user", "-"),
        ("time_local", ""),
        ("request", &request_line),
        ("request_uri", &req.raw_target),
        ("request_method", req.method.as_str()),
        ("document_uri", path),
        ("args", query),
        ("status", &status_s),
        ("body_bytes_sent", &bytes_s),
        ("http_referer", referer),
        ("http_user_agent", ua),
        ("host", host),
        ("server_name", server_name),
        ("server_port", &port_s),
        ("scheme", "http"),
    ];

    for log in &server.access_logs {
        let line = expand_log(&log.format, vars, now);
        ctx.logger.access(&log.path, line);
    }
}

fn expand_log(fmt: &str, vars: &[(&str, &str)], now: i64) -> String {
    let mut out = String::with_capacity(fmt.len() + 64);
    let bytes = fmt.as_bytes();
    let mut i = 0;
    let time_local = util::log_time(now);
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let mut matched = false;
            for (name, val) in vars {
                if bytes[i + 1..].starts_with(name.as_bytes()) {
                    if *name == "time_local" {
                        out.push_str(&time_local);
                    } else {
                        out.push_str(val);
                    }
                    i += 1 + name.len();
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_expansion() {
        let vars = [("status", "200"), ("request_uri", "/x")];
        assert_eq!(expand_log("[$status] $request_uri", &vars, 0), "[200] /x");
    }
}
