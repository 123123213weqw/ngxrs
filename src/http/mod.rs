//! HTTP/1.1 request handling: routing, responses, access logging.

pub mod request;
pub mod static_file;

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


use crate::config::{Config, Http, IfCond, ListenGroup, LocCfg, RewriteFlag, Server};
use crate::conn::{Conn, RecvError, MAX_HEADER_BYTES, MAX_REQUEST_LINE};
use crate::log::Logger;
use crate::util::{self, reason};

use request::{Method, Request};

pub struct Ctx {
    pub config: Arc<Config>,
    pub logger: Arc<Logger>,
    /// One TLS configuration per listen group (`None` for plain HTTP).
    pub tls: Arc<Vec<Option<Arc<rustls::ServerConfig>>>>,
}

pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    File { file: File, offset: u64, len: u64 },
}

pub struct Response {
    pub status: u16,
    /// Dynamic headers that still need `Name: value` rendering.
    pub headers: Vec<(String, String)>,
    /// Pre-rendered header lines (already `Name: value\r\n`). Keeps the hot
    /// static path free of per-header `String` allocations.
    pub raw: Vec<u8>,
    /// True when `raw` already carries Content-Length.
    pub explicit_len: bool,
    /// Set for `return` responses: nginx does not run error_page on those.
    pub no_error_page: bool,
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
            raw: Vec::new(),
            explicit_len: false,
            no_error_page: false,
            body: Body::Empty,
        }
    }

    pub fn bytes(status: u16, ctype: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            headers: vec![("Content-Type".to_string(), ctype.to_string())],
            raw: Vec::new(),
            explicit_len: false,
            no_error_page: false,
            body: Body::Bytes(body),
        }
    }

    /// Fast constructor: `raw` already contains Content-Type/Content-Length.
    pub fn raw(status: u16, raw: Vec<u8>, body: Body) -> Self {
        Response {
            status,
            headers: Vec::new(),
            raw,
            explicit_len: true,
            no_error_page: false,
            body,
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

thread_local! {
    static NO_IDLE_TIMER: bool = std::env::var_os("NGXRS_NO_IDLE_TIMER").is_some();
}

pub async fn handle_conn(mut conn: Conn, group: &ListenGroup, ctx: &Ctx) {
    let http = &ctx.config.http;
    let first_server = http.server(group.default_server);
    let keepalive_timeout = first_server.keepalive_timeout;
    let mut served: u64 = 0;
    // One timer per connection, reset after each request: registering a fresh
    // timer per request costs more than the request itself at 400k rps.
    let mut idle = Box::pin(tokio::time::sleep(keepalive_timeout));

    loop {
        let read_timeout = if served == 0 {
            Duration::from_secs(60)
        } else {
            keepalive_timeout
        };
        // NGXRS_NO_IDLE_TIMER=1 disables the keepalive timeout (measurement only).
        let read = if NO_IDLE_TIMER.with(|v| *v) {
            Ok(conn
                .read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES)
                .await)
        } else {
            idle.as_mut()
                .reset(tokio::time::Instant::now() + read_timeout);
            tokio::select! {
                _ = idle.as_mut() => Err(()),
                r = conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES) => Ok(r),
            }
        };

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

        let server = select_server(http, &group.servers, group.default_server, req.host.as_deref());
        let loc = server.locate(&path);

        // Request body: upstream modules (proxy, fastcgi) forward it; every
        // other handler discards it (nginx behaves the same for static
        // content). Draining here for an upstream-backed location would make
        // the module read an already-empty body and block forever.
        let proxy_target = loc.proxy_pass.is_some() || loc.fastcgi_pass.is_some();
        if req.chunked {
            if !proxy_target {
                if req.expect_continue {
                    let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                }
                if conn.drain_chunked().await.is_err() {
                    break;
                }
            }
        } else if req.body_len > 0 {
            if loc.client_max_body_size != u64::MAX && req.body_len > loc.client_max_body_size {
                let _ = send_error(&mut conn, 413, server.server_tokens, false, false).await;
                break;
            }
            if !proxy_target {
                if req.expect_continue {
                    let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                }
                if conn.drain_body(req.body_len).await.is_err() {
                    break;
                }
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

/// Resolve a request to a `Response` without writing anything. Kept separate
/// from the writer so `error_page` internal redirects can re-route cheaply.
/// Content phase only: static files / autoindex / 404. Used after
/// `rewrite ... break`, which skips the location's `return` and `try_files`.
async fn route_content(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
) -> Response {
    if !req.method.is_read() {
        return error_response(405, server.server_tokens);
    }
    match static_file::respond(req, path, query, loc, http) {
        Ok(r) => r,
        Err(_) => error_response(404, server.server_tokens),
    }
}

async fn route(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
    allow_internal: bool,
) -> Response {
    if !req.method.is_read() {
        return error_response(405, server.server_tokens);
    }

    if loc.internal && !allow_internal {
        return error_response(404, server.server_tokens);
    }

    if let Some((code, body)) = &loc.ret {
        let status = *code;
        let mut resp = if matches!(status, 301 | 302 | 303 | 307 | 308) {
            Response::empty(status).header("Location", body.clone())
        } else if body.is_empty() {
            Response::empty(status)
        } else {
            // nginx picks the content type from the URI extension, falling
            // back to default_type (not text/plain).
            let ext = match path.rfind('.') {
                Some(i) if i + 1 < path.len() => path[i + 1..].to_ascii_lowercase(),
                _ => String::new(),
            };
            let ctype = http
                .mime
                .get(&ext)
                .unwrap_or(http.default_type.as_str())
                .to_string();
            Response::bytes(status, &ctype, body.clone().into_bytes())
        };
        resp.no_error_page = true;
        return resp;
    }

    if !loc.try_files.is_empty() {
        if let Some(resp) = try_files_sync(req, path, loc, server, http) {
            return resp;
        }
    }

    match static_file::respond(req, path, query, loc, http) {
        Ok(r) => r,
        Err(_) => error_response(404, server.server_tokens),
    }
}

fn error_response(status: u16, tokens: bool) -> Response {
    let body = error_body(status, tokens);
    Response::raw(
        status,
        {
            let mut raw = Vec::with_capacity(96);
            raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
            raw.extend_from_slice(body.len().to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
            raw
        },
        Body::Bytes(body),
    )
}

/// Variables available to `set` / `if` / `rewrite` in the rewrite phase.
struct RwVars<'a> {
    req: &'a Request,
    path: &'a str,
    query: &'a str,
    vars: &'a std::collections::HashMap<String, String>,
}

fn get_var(name: &str, v: &RwVars<'_>) -> String {
    let bare = name.trim_start_matches('$');
    if let Some(val) = v.vars.get(bare) {
        return val.clone();
    }
    match bare {
        "uri" | "document_uri" => v.path.to_string(),
        "request_uri" => v.req.raw_target.clone(),
        "args" | "query_string" => v.query.to_string(),
        "request_method" => v.req.method.as_str().to_string(),
        "host" | "http_host" => v
            .req
            .host
            .as_ref()
            .map(|h| h.as_str().to_string())
            .unwrap_or_default(),
        "remote_addr" => String::new(),
        "scheme" => "http".to_string(),
        "is_args" => {
            if v.query.is_empty() {
                String::new()
            } else {
                "?".to_string()
            }
        }
        "request_filename" | "document_root" => String::new(),
        _ => {
            if let Some(h) = bare.strip_prefix("http_") {
                let key = h.replace('_', "-");
                v.req.headers.get(&key).unwrap_or("").to_string()
            } else {
                String::new()
            }
        }
    }
}

fn eval_cond(cond: &IfCond, v: &RwVars<'_>) -> bool {
    match cond {
        IfCond::Truthy(var) => {
            let s = get_var(var, v);
            !s.is_empty() && s != "0"
        }
        IfCond::Equals(var, rhs, eq) => {
            let lhs = get_var(var, v);
            let res = lhs == *rhs || lhs == get_var(rhs, v);
            if *eq {
                res
            } else {
                !res
            }
        }
        IfCond::Match(var, re, negate) => {
            let lhs = get_var(var, v);
            let m = re.is_match(&lhs);
            if *negate {
                !m
            } else {
                m
            }
        }
        IfCond::FileTest(kind, path_expr) => {
            let p = get_var(path_expr, v);
            let path = std::path::Path::new(&p);
            match kind {
                'f' => path.is_file(),
                'd' => path.is_dir(),
                'e' => path.exists(),
                'x' => {
                    use std::os::unix::fs::PermissionsExt;
                    path.metadata()
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                }
                _ => false,
            }
        }
    }
}

/// Apply `rewrite` directives. Returns `Ok(Some(response))` for a redirect /
/// `return` the rewrite produced, `Ok(None)` with the (possibly new) URI when
/// processing should continue.
fn apply_rewrites(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    default_type: &str,
) -> RewriteOutcome {
    let mut uri = path.to_string();
    let mut args = query.to_string();
    let _ = req;

    // `set` runs first; the values feed `if` conditions and rewrites.
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, value) in &loc.sets {
        let ctx = RwVars {
            req,
            path: &uri,
            query: &args,
            vars: &vars,
        };
        let expanded = expand_vars(value, &ctx);
        vars.insert(name.trim_start_matches('$').to_string(), expanded);
    }

    // `if` blocks
    for ifb in &loc.ifs {
        let ctx = RwVars {
            req,
            path: &uri,
            query: &args,
            vars: &vars,
        };
        if !eval_cond(&ifb.cond, &ctx) {
            continue;
        }
        for (name, value) in &ifb.sets {
            let ctx = RwVars {
                req,
                path: &uri,
                query: &args,
                vars: &vars,
            };
            let expanded = expand_vars(value, &ctx);
            vars.insert(name.trim_start_matches('$').to_string(), expanded);
        }
        if let Some((code, body)) = &ifb.ret {
            let status = *code;
            let mut resp = if matches!(status, 301 | 302 | 303 | 307 | 308) {
                Response::empty(status).header("Location", body.clone())
            } else if body.is_empty() {
                Response::empty(status)
            } else {
                // nginx picks the type from the URI extension, else default_type
                let ext = match path.rfind('.') {
                    Some(i) if i + 1 < path.len() => path[i + 1..].to_ascii_lowercase(),
                    _ => String::new(),
                };
                let ctype = default_type_for(ext.as_str(), default_type);
                Response::bytes(status, &ctype, body.clone().into_bytes())
            };
            resp.no_error_page = true;
            return RewriteOutcome::Respond(resp);
        }
        for rw in &ifb.rewrites {
            if let Some(out) = apply_one(rw, &mut uri, &mut args) {
                return out;
            }
        }
    }

    for rw in &loc.rewrites {
        if let Some(out) = apply_one(rw, &mut uri, &mut args) {
            return out;
        }
    }
    let _ = server;
    RewriteOutcome::Continue(uri, args)
}

/// Apply one rewrite rule; `None` means "keep scanning".
fn apply_one(rw: &crate::config::Rewrite, uri: &mut String, args: &mut String) -> Option<RewriteOutcome> {
    if !rw.re.is_match(uri) {
        return None;
    }
    let caps = rw.re.captures(uri)?;
    let mut target = expand_captures(&rw.replacement, &caps);
    if let Some(q) = target.find('?') {
        *args = target[q + 1..].to_string();
        target.truncate(q);
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        let code = match rw.flag {
            RewriteFlag::Permanent => 301,
            _ => 302,
        };
        return Some(RewriteOutcome::Respond(
            Response::empty(code).header("Location", target),
        ));
    }
    match rw.flag {
        RewriteFlag::Permanent | RewriteFlag::Redirect => {
            let code = if rw.flag == RewriteFlag::Permanent { 301 } else { 302 };
            let mut location = target;
            if !args.is_empty() {
                location.push('?');
                location.push_str(args);
            }
            Some(RewriteOutcome::Respond(
                Response::empty(code).header("Location", location),
            ))
        }
        RewriteFlag::Last => Some(RewriteOutcome::Relocate(target, args.clone())),
        RewriteFlag::Break => Some(RewriteOutcome::Break(target, args.clone())),
        RewriteFlag::None => {
            *uri = target;
            None
        }
    }
}

/// Expand `$var` references against the rewrite-phase variable set.
fn expand_vars(spec: &str, v: &RwVars<'_>) -> String {
    let mut out = String::with_capacity(spec.len());
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            out.push(b[i] as char);
            i += 1;
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
        out.push_str(&get_var(&rest[..n], v));
        i += 1 + n;
    }
    out
}

enum RewriteOutcome {
    /// No rewrite matched: keep the URI and let `return`/content run.
    Continue(String, String),
    /// `rewrite ... last`: restart location search, then run the rewrite
    /// module (including `return`) of the new location from scratch.
    Relocate(String, String),
    /// `rewrite ... break` or a plain rewrite: nginx stops executing the
    /// remaining rewrite-module directives for this location — `return`
    /// included — and serves content with the new URI.
    Break(String, String),
    Respond(Response),
}

fn expand_captures(replacement: &str, caps: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(replacement.len());
    let b = replacement.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let n = (b[i + 1] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                out.push_str(m.as_str());
            }
            i += 2;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn default_type_for(ext: &str, default_type: &str) -> String {
    const BUILTIN: &[(&str, &str)] = &[
        ("html", "text/html"),
        ("htm", "text/html"),
        ("css", "text/css"),
        ("js", "application/javascript"),
        ("json", "application/json"),
        ("txt", "text/plain"),
        ("xml", "text/xml"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
    ];
    BUILTIN
        .iter()
        .find(|(e, _)| *e == ext)
        .map(|(_, t)| t.to_string())
        .unwrap_or_else(|| default_type.to_string())
}

/// nginx applies `add_header` to these status codes unless `always` is given.
fn add_header_applies(status: u16, always: bool) -> bool {
    always
        || matches!(
            status,
            200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
        )
}

/// Append `add_header` lines to a rendered header block.
pub fn apply_add_headers(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    vars: &AddHeaderVars<'_>,
) {
    for (name, value) in headers {
        let (value, always) = match value.rsplit_once(' ') {
            Some((v, "always")) => (v, true),
            _ => (value.as_str(), false),
        };
        if !add_header_applies(status, always) {
            continue;
        }
        let expanded = expand_add_header(value, vars);
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(expanded.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
}

pub struct AddHeaderVars<'a> {
    pub upstream_cache_status: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
}

fn expand_add_header(spec: &str, vars: &AddHeaderVars<'_>) -> String {
    let mut out = String::with_capacity(spec.len() + 8);
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            out.push(b[i] as char);
            i += 1;
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
        let v = match name {
            "upstream_cache_status" => vars.upstream_cache_status,
            "scheme" => vars.scheme,
            "host" | "http_host" => vars.host,
            _ => "",
        };
        out.push_str(v);
        i += 1 + n;
    }
    out
}

/// Resolve a request to a `Response` without touching the socket: error_page
/// internal redirects plus the gzip filter. The HTTP/1 handler writes the
/// result; the HTTP/2 handler turns it into h2 frames.
pub async fn resolve_response(
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
) -> Response {
    let mut cur_path = path.to_string();
    let mut cur_query = query.to_string();
    let mut cur_loc = loc;
    let mut depth = 0usize;

    // ---- rewrite phase ----
    let mut relocations = 0;
    let mut skip_return = false;
    loop {
        match apply_rewrites(req, &cur_path, &cur_query, cur_loc, server, &http.default_type) {
            RewriteOutcome::Respond(r) => return r,
            RewriteOutcome::Continue(p, q) => {
                cur_path = p;
                cur_query = q;
                break;
            }
            RewriteOutcome::Break(p, q) => {
                cur_path = p;
                cur_query = q;
                // Skip `return` for this location, like nginx.
                skip_return = true;
                break;
            }
            RewriteOutcome::Relocate(p, q) => {
                cur_path = p;
                cur_query = q;
                cur_loc = server.locate(&cur_path);
                relocations += 1;
                if relocations > 10 {
                    return error_response(500, server.server_tokens);
                }
            }
        }
    }

    let mut resp = if skip_return {
        // `rewrite ... break` bypasses the location's `return`, so the request
        // falls through to the content handler (static file / proxy).
        route_content(req, &cur_path, &cur_query, cur_loc, server, http).await
    } else {
        route(req, &cur_path, &cur_query, cur_loc, server, http, false).await
    };

    while resp.status >= 400 && depth < 10 && !resp.no_error_page {
        let Some(target) = cur_loc.error_pages.get(&resp.status).cloned() else {
            break;
        };
        let (new_status, uri) = match target.strip_prefix('=') {
            Some(rest) => match rest.split_once(char::is_whitespace) {
                Some((code, uri)) => (code.parse::<u16>().ok(), uri.trim().to_string()),
                None => (None, rest.trim().to_string()),
            },
            None => (None, target.clone()),
        };
        let original_status = resp.status;
        let (p, q) = match uri.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (uri.clone(), String::new()),
        };
        cur_path = p;
        cur_query = q;
        cur_loc = server.locate(&cur_path);
        depth += 1;
        let redirected = route(req, &cur_path, &cur_query, cur_loc, server, http, true).await;
        if redirected.status >= 400 {
            resp = error_response(original_status, server.server_tokens);
            break;
        }
        let mut redirected = redirected;
        redirected.status = new_status.unwrap_or(original_status);
        resp = redirected;
    }

    if resp.status >= 400 && resp.body.is_empty() {
        resp = error_response(resp.status, server.server_tokens);
    }

    crate::gzip::maybe_compress(req, resp, cur_loc, http)
}

/// Read a whole response body into memory (HTTP/2 needs the length up front
/// unless it streams, which we do not need for static content).
pub async fn body_bytes(body: Body) -> io::Result<Vec<u8>> {
    match body {
        Body::Empty => Ok(Vec::new()),
        Body::Bytes(b) => Ok(b),
        Body::File { file, offset, len } => {
            use std::os::unix::fs::FileExt;
            let mut out = vec![0u8; len as usize];
            let mut read = 0usize;
            while read < out.len() {
                match file.read_at(&mut out[read..], offset + read as u64) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            out.truncate(read);
            Ok(out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
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

    // ---- FastCGI ----
    if loc.fastcgi_pass.is_some() {
        if let Some(o) = crate::fastcgi::handle(conn, req, path, query, loc, server.server_tokens).await? {
            return Ok(o);
        }
    }

    // ---- reverse proxy (streams to the socket, cannot be resolved first) ----
    if loc.proxy_pass.is_some() {
        if let Some(o) =
            crate::proxy::handle(conn, req, path, query, loc, http, server.server_tokens).await?
        {
            return Ok(o);
        }
    }

    let resp = resolve_response(req, path, query, server, loc, http).await;
    let status = resp.status;
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        return write_redirect(conn, req, resp, listen_port, server.server_tokens).await;
    }
    let bytes = write_response(conn, resp, req.keepalive, server.server_tokens, head_only).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

async fn write_redirect(
    conn: &mut Conn,
    req: &Request,
    resp: Response,
    listen_port: u16,
    tokens: bool,
) -> io::Result<Outcome> {
    let status = resp.status;
    let Response {
        headers,
        raw,
        body,
        explicit_len,
        ..
    } = resp;
    let location = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let absolute = if location.starts_with('/') {
        let host = req.host.as_ref().map(|h| h.as_str()).unwrap_or("");
        let host_has_port = host
            .rsplit_once(':')
            .map(|(_, p)| p.parse::<u16>().is_ok())
            .unwrap_or(false);
        let host = if host_has_port || listen_port == 80 {
            host.to_string()
        } else {
            format!("{host}:{listen_port}")
        };
        format!("http://{host}{location}")
    } else {
        location
    };

    // nginx answers redirects with a small HTML body describing the status.
    let body = match body {
        Body::Bytes(b) if !b.is_empty() => b,
        _ => error_body(status, tokens),
    };

    let mut out_raw = raw;
    out_raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
    out_raw.extend_from_slice(body.len().to_string().as_bytes());
    out_raw.extend_from_slice(b"\r\nLocation: ");
    out_raw.extend_from_slice(absolute.as_bytes());
    out_raw.extend_from_slice(b"\r\n");
    let _ = explicit_len;

    let resp = Response {
        status,
        headers: Vec::new(),
        raw: out_raw,
        explicit_len: true,
        no_error_page: false,
        body: Body::Bytes(body),
    };
    let bytes = write_response(conn, resp, req.keepalive, tokens, req.method == Method::Head).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

fn try_files_sync(
    req: &Request,
    path: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
) -> Option<Response> {
    let n = loc.try_files.len();
    for (i, cand) in loc.try_files.iter().enumerate() {
        let last = i + 1 == n;
        if let Some(code) = cand.strip_prefix('=') {
            if let Ok(status) = code.parse::<u16>() {
                return Some(error_response(status, server.server_tokens));
            }
            continue;
        }
        let expanded = cand.replace("$uri", path);
        let rel = expanded.trim_start_matches('/');
        let fs_path = loc.root.join(rel);
        let is_dir_hint = expanded.ends_with('/');
        if fs_path.exists() && (!is_dir_hint || fs_path.is_dir()) {
            if let Ok(resp) = static_file::respond_fs(req, &fs_path, path, loc, http) {
                return Some(resp);
            }
        }
        if last {
            return Some(error_response(404, server.server_tokens));
        }
    }
    None
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
        headers: Vec::new(),
        raw: {
            let mut raw = Vec::with_capacity(96);
            raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
            raw.extend_from_slice(body.len().to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
            raw
        },
        no_error_page: false,
            explicit_len: true,
        body: Body::Bytes(body),
    };
    write_response(conn, resp, keepalive, tokens, head_only).await
}

pub fn error_body(status: u16, tokens: bool) -> Vec<u8> {
    let reason = crate::util::error_page_reason(status);
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

#[inline]
fn push_status_line(out: &mut Vec<u8>, status: u16) {
    match status {
        200 => out.extend_from_slice(b"HTTP/1.1 200 OK\r\n"),
        201 => out.extend_from_slice(b"HTTP/1.1 201 Created\r\n"),
        204 => out.extend_from_slice(b"HTTP/1.1 204 No Content\r\n"),
        206 => out.extend_from_slice(b"HTTP/1.1 206 Partial Content\r\n"),
        301 => out.extend_from_slice(b"HTTP/1.1 301 Moved Permanently\r\n"),
        302 => out.extend_from_slice(b"HTTP/1.1 302 Moved Temporarily\r\n"),
        304 => out.extend_from_slice(b"HTTP/1.1 304 Not Modified\r\n"),
        400 => out.extend_from_slice(b"HTTP/1.1 400 Bad Request\r\n"),
        403 => out.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n"),
        404 => out.extend_from_slice(b"HTTP/1.1 404 Not Found\r\n"),
        405 => out.extend_from_slice(b"HTTP/1.1 405 Not Allowed\r\n"),
        408 => out.extend_from_slice(b"HTTP/1.1 408 Request Time-out\r\n"),
        413 => out.extend_from_slice(b"HTTP/1.1 413 Request Entity Too Large\r\n"),
        414 => out.extend_from_slice(b"HTTP/1.1 414 Request-URI Too Large\r\n"),
        416 => out.extend_from_slice(b"HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
        429 => out.extend_from_slice(b"HTTP/1.1 429 Too Many Requests\r\n"),
        499 => out.extend_from_slice(b"HTTP/1.1 499 Client Closed Request\r\n"),
        500 => out.extend_from_slice(b"HTTP/1.1 500 Internal Server Error\r\n"),
        502 => out.extend_from_slice(b"HTTP/1.1 502 Bad Gateway\r\n"),
        503 => out.extend_from_slice(b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"),
        504 => out.extend_from_slice(b"HTTP/1.1 504 Gateway Time-out\r\n"),
        505 => out.extend_from_slice(b"HTTP/1.1 505 HTTP Version Not Supported\r\n"),
        _ => {
            out.extend_from_slice(b"HTTP/1.1 ");
            out.extend_from_slice(status.to_string().as_bytes());
            out.push(b' ');
            out.extend_from_slice(reason(status).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
}

pub async fn write_response(
    conn: &mut Conn,
    resp: Response,
    keepalive: bool,
    tokens: bool,
    head_only: bool,
) -> io::Result<u64> {
    let Response {
        status,
        headers,
        raw,
        explicit_len,
        no_error_page: _,
        body,
    } = resp;

    let body_len = match &body {
        Body::Empty => 0,
        Body::Bytes(b) => b.len() as u64,
        Body::File { len, .. } => *len,
    };

    // Reuse the connection's staging buffer instead of allocating per request.
    let mut out = std::mem::take(&mut conn.out);
    out.clear();

    push_status_line(&mut out, status);
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

    let has_cl = explicit_len
        || headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    if !has_cl && !matches!(status, 204 | 304) {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body_len.to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(&raw);
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
        let r = conn.write_all(&out).await;
        conn.out = out;
        return r.map(|_| 0);
    }

    let result = match body {
        Body::Empty => conn.write_all(&out).await.map(|_| 0),
        Body::Bytes(b) => {
            out.extend_from_slice(&b);
            conn.write_all(&out).await.map(|_| b.len() as u64)
        }
        // Small files: one write beats header+sendfile (two syscalls, two
        // segments). Large files stay zero-copy.
        Body::File { file, offset, len } if len <= SMALL_FILE_WRITE => {
            use std::os::unix::fs::FileExt;
            let start = out.len();
            out.resize(start + len as usize, 0);
            let mut read_total = 0usize;
            let mut err = None;
            while read_total < len as usize {
                match file.read_at(&mut out[start + read_total..], offset + read_total as u64) {
                    Ok(0) => break,
                    Ok(n) => read_total += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            match err {
                Some(e) => Err(e),
                None => {
                    out.truncate(start + read_total);
                    conn.write_all(&out).await.map(|_| read_total as u64)
                }
            }
        }
        Body::File { file, offset, len } => {
            if conn.tcp_nopush {
                conn.set_cork(true);
                let w = conn.write_all(&out).await;
                if w.is_err() {
                    conn.set_cork(false);
                    w.map(|_| 0)
                } else {
                    let sent = conn.send_file(&file, offset, len).await;
                    conn.set_cork(false);
                    sent
                }
            } else if let Err(e) = conn.write_all(&out).await {
                Err(e)
            } else {
                conn.send_file(&file, offset, len).await
            }
        }
    };

    out.clear();
    conn.out = out;
    result
}

/// Write a response head only (used by the proxy, which streams its own body).
pub async fn write_head(
    conn: &mut Conn,
    status: u16,
    raw: &[u8],
    keepalive: bool,
    tokens: bool,
) -> io::Result<()> {
    let mut out = std::mem::take(&mut conn.out);
    out.clear();
    push_status_line(&mut out, status);
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
    out.extend_from_slice(raw);
    out.extend_from_slice(b"Connection: ");
    out.extend_from_slice(if keepalive { b"keep-alive" } else { b"close" });
    out.extend_from_slice(b"\r\n\r\n");
    let r = conn.write_all(&out).await;
    out.clear();
    conn.out = out;
    r
}

pub fn select_server<'a>(
    http: &'a Http,
    servers: &[usize],
    default_server: usize,
    host: Option<&str>,
) -> &'a Server {
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
        for &idx in servers {
            let s = http.server(idx);
            for n in &s.names {
                if n.eq_ignore_ascii_case(&lower) {
                    return s;
                }
            }
        }
        for &idx in servers {
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
        for &idx in servers {
            let s = http.server(idx);
            for re in &s.regex_names {
                if re.is_match(&lower) {
                    return s;
                }
            }
        }
    }

    http.server(default_server)
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
