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
    /// Swappable configuration. `SIGHUP` replaces the `Arc`; connections that
    /// are already running keep the snapshot they started with (nginx's
    /// old-worker/new-worker behaviour).
    pub config: std::sync::RwLock<Arc<Config>>,
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
    /// `add_trailer` entries that produced a value; sent after the body.
    pub trailers: Vec<(String, String)>,
    /// `add_trailer` matched this status, so nginx switches to chunked even if
    /// every value expands to empty (`ngx_http_headers_filter` sets
    /// `r->expect_trailers` before the values are known).
    pub expect_trailers: bool,
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
            trailers: Vec::new(),
            expect_trailers: false,
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
            trailers: Vec::new(),
            expect_trailers: false,
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
            trailers: Vec::new(),
            expect_trailers: false,
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
    /// Response headers as sent, for `$sent_http_*` in the access log.
    pub sent: Vec<(String, String)>,
}

/// Per-connection counters that nginx exposes as `$connection_requests` and
/// `$connection_time`, and that drive `keepalive_requests` / `keepalive_time`.
#[derive(Clone, Copy)]
pub struct ConnState {
    pub requests: u64,
    pub started: std::time::Instant,
}

impl ConnState {
    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

thread_local! {
    static NO_IDLE_TIMER: bool = std::env::var_os("NGXRS_NO_IDLE_TIMER").is_some();
}

/// Number of connections currently being served. Graceful shutdown waits for
/// this to reach zero (nginx's `worker_shutdown_timeout` behaviour).
pub static ACTIVE_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Set once a graceful shutdown begins: responses served after that carry
/// `Connection: close` so clients know the connection is going away.
pub static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Wakes connection tasks that are blocked waiting for the next request on a
/// keepalive connection, so a graceful shutdown does not have to wait for
/// `keepalive_timeout` on every idle client.
static SHUTDOWN_NOTIFY: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();

pub fn shutdown_notify() -> &'static tokio::sync::Notify {
    SHUTDOWN_NOTIFY.get_or_init(tokio::sync::Notify::new)
}

pub fn is_shutting_down() -> bool {
    SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed)
}

/// RAII guard so the counter stays balanced even on early return.
pub struct ActiveGuard;

impl ActiveGuard {
    pub fn enter() -> Self {
        ACTIVE_CONNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ActiveGuard
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE_CONNS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Ctx {
    /// Cheap snapshot of the current configuration.
    pub fn cfg(&self) -> Arc<Config> {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install a new configuration (SIGHUP).
    pub fn set_cfg(&self, new: Arc<Config>) {
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = new;
    }
}

pub async fn handle_conn(conn: Conn, cfg: Arc<Config>, group_idx: usize, ctx: &Ctx) {
    // Upstream attempt timings are collected per request inside this task; the
    // value is needed by `add_header` deep in the proxy code and by the access
    // logger afterwards, which have no plumbing between them.
    crate::timing::scope(
        crate::timing::new_state(),
        handle_conn_inner(conn, cfg, group_idx, ctx),
    )
    .await
}

async fn handle_conn_inner(mut conn: Conn, cfg: Arc<Config>, group_idx: usize, ctx: &Ctx) {
    let _active = ActiveGuard::enter();
    let http = &cfg.http;
    let group = &http.groups[group_idx];
    let first_server = http.server(group.default_server);
    // The idle timeout for the next read comes from the location of the
    // request that was just served (nginx stores it in c->keepalive_timeout).
    let mut keepalive_timeout = first_server.keepalive_timeout;
    let mut served: u64 = 0;
    // Captured once: TLS facts do not change over the life of a connection.
    let tls_info = conn.tls_info().map(std::sync::Arc::new);
    let scheme = if tls_info.is_some() { "https" } else { "http" };
    let conn_started = std::time::Instant::now();
    // One timer per connection, reset after each request: registering a fresh
    // timer per request costs more than the request itself at 400k rps.
    let mut idle = Box::pin(tokio::time::sleep(keepalive_timeout));
    // Peer and local addresses never change over a connection; rendering them
    // per request cost two allocations each time.
    let client_ip_owned = conn.peer_ip_str();
    let local_ip_owned = conn
        .local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    loop {
        #[cfg(feature = "alloc-count")]
        let mark0 = crate::alloccnt::mark(0);
        let read_timeout = if served == 0 {
            Duration::from_secs(60)
        } else {
            keepalive_timeout
        };
        // NGXRS_NO_IDLE_TIMER=1 disables the keepalive timeout (measurement only).
        // An idle keepalive connection is closed as soon as a graceful shutdown
        // starts -- nginx's `ngx_close_idle_connections`. Waiting for the
        // timeout instead keeps the process (and its pid) alive for as long as
        // any client idles, which stalls `stop()` in the official test harness
        // and made a restart look like a cache miss.
        let idle_shutdown = is_shutting_down() && conn.buffered().is_empty();
        let read = if idle_shutdown {
            Err(())
        } else if NO_IDLE_TIMER.with(|v| *v) {
            tokio::select! {
                _ = shutdown_notify().notified(), if conn.buffered().is_empty() => Err(()),
                r = conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES) => Ok(r),
            }
        } else {
            idle.as_mut()
                .reset(tokio::time::Instant::now() + read_timeout);
            tokio::select! {
                _ = idle.as_mut() => Err(()),
                _ = shutdown_notify().notified(), if conn.buffered().is_empty() => Err(()),
                r = conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES) => Ok(r),
            }
        };

        #[allow(unused_mut)]
        let mut req = match read {
            Err(_elapsed) => {
                // A shutdown closes the connection without a 408.
                if is_shutting_down() {
                    break;
                }
                if served == 0 {
                    let _ = send_error(&mut conn, 408, true, served == 0, false).await;
                }
                break;
            }
            Ok(Err(RecvError::Io(_e))) => break,
            Ok(Err(RecvError::Bad(e))) => {
                // nginx runs error_page even for requests its parser rejects
                // (e.g. `Host: .`), using the default server of this socket.
                let default_server = http.server(group.default_server);
                let peer = conn.peer_ip_str();
                let synthetic = Request {
                    method: Method::Get,
                    raw_target: "/".to_string(),
                    version_minor: 0,
                    headers: crate::http::request::Headers::default(),
                    body_len: 0,
                    chunked: false,
                    keepalive: false,
                    host: None,
                    expect_continue: false,
                    tls: None,
                    started: std::time::Instant::now(),
                };
                let mut resp = error_response(e.status, default_server.server_tokens);
                let mut custom: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                let resp = finalize_response(
                    &synthetic,
                    &mut resp,
                    "/",
                    "",
                    default_server,
                    http,
                    &peer,
                    conn.peer.port(),
                    group.addr.port(),
                    &[],
                    &mut custom,
                    ConnState {
                        requests: 0,
                        started: std::time::Instant::now(),
                    },
                    &conn
                        .local_addr()
                        .map(|a| a.ip().to_string())
                        .unwrap_or_default(),
                )
                .await;
                // A redirect produced by the error page still needs the
                // absolute/port/server_name rewriting.
                if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                    let loc = default_server.default_loc.clone();
                    let local = conn
                        .local_addr()
                        .map(|a| a.ip().to_string())
                        .unwrap_or_default();
                    let _ = write_redirect(
                        &mut conn,
                        &synthetic,
                        resp,
                        &loc,
                        group.addr.port(),
                        default_server.server_tokens,
                        &local,
                    )
                    .await;
                } else {
                    let _ =
                        write_response(&mut conn, resp, false, default_server.server_tokens, false)
                            .await;
                }
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(req0))) => {
                let mut r = req0;
                // Attach the connection's TLS facts once per request so `$scheme`
                // and `$ssl_*` can be answered from any `Request` in scope.
                r.tls = tls_info.clone();
                r
            }
        };
        served += 1;

        // nginx checks `ssl_verify_client` here, against the server conf the
        // request resolved to (`ngx_http_process_request_headers`), and answers
        // 495/496 — which render as a 400 status line.
        if let Some(ti) = &tls_info {
            let mut verify_reason: Option<String> = None;
            let sni = ti.server_name.as_deref();
            let srv = select_server(http, &group.servers, group.default_server, sni);
            if srv.ssl_verify_client != 0 {
                let chain = conn.peer_chain();
                let mismatch = match &chain {
                    Some(c) if !c.is_empty() => {
                        match crate::tls::verify_client_chain(
                            srv.ssl_client_certificate.as_deref(),
                            c,
                        ) {
                            // `optional_no_ca` tolerates a chain it cannot
                            // validate, but still reports FAILED.
                            Ok(()) => None,
                            Err(reason) => {
                                if srv.ssl_verify_client == 3 {
                                    verify_reason = Some(reason);
                                    None
                                } else {
                                    Some((495u16, "The SSL certificate error"))
                                }
                            }
                        }
                    }
                    _ => {
                        if srv.ssl_verify_client == 1 {
                            Some((496u16, "No required SSL certificate was sent"))
                        } else {
                            None
                        }
                    }
                };
                // Reflect the outcome through `$ssl_client_verify`.
                if let Some(mut info) = tls_info.as_deref().cloned() {
                    info.client_verify = match (&verify_reason, &mismatch) {
                        (Some(reason), _) => format!("FAILED:{reason}"),
                        (None, Some(_)) => "NONE".to_string(),
                        (None, None) => {
                            if info.client_cert.is_empty() {
                                "NONE".to_string()
                            } else {
                                "SUCCESS".to_string()
                            }
                        }
                    };
                    req.tls = Some(std::sync::Arc::new(info));
                }
                if let Some((_code, text)) = mismatch {
                    let body = format!(
                        "<html>\r\n<head><title>400 {text}</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>{text}</center>\r\n</html>\r\n"
                    );
                    let mut resp = Response::empty(400);
                    resp.raw = body.into_bytes();
                    let _ = write_response(&mut conn, resp, false, srv.server_tokens, false).await;
                    break;
                }
            }
        }

        // A keepalive connection serves many requests from the same task.
        crate::timing::reset();
        let (path, query) = match util::parse_target(&req.raw_target) {
            Ok(v) => v,
            Err(_) => {
                let tokens = http.server(group.default_server).server_tokens;
                let _ = send_error(&mut conn, 400, tokens, false, false).await;
                // nginx still writes an access-log line, with `$uri` empty.
                let srv = http.server(group.default_server);
                log_access(
                    ctx,
                    group,
                    srv,
                    &req,
                    "",
                    "",
                    400,
                    0,
                    std::time::Duration::ZERO,
                    conn.peer,
                    &[],
                    None,
                );
                break;
            }
        };

        let (server, server_caps) = select_server_ex(
            http,
            &group.servers,
            group.default_server,
            req.host.as_deref(),
        );
        let (loc, loc_caps) = server.locate_with_captures(&path);
        // Location regex captures are ordinary variables (`$1`, `$name`), and
        // they take precedence over `server_name` captures when both exist.
        let mut all_caps: Vec<(String, String)> = loc_caps;
        all_caps.extend(server_caps.iter().cloned());
        if let Some((t, _)) = loc.keepalive_timeout {
            keepalive_timeout = t;
        }

        // Request body: upstream modules (proxy, fastcgi) forward it; every
        // other handler discards it (nginx behaves the same for static
        // content). Draining here for an upstream-backed location would make
        // the module read an already-empty body and block forever.
        let proxy_target = loc.proxy_pass.is_some()
            || loc.fastcgi_pass.is_some()
            || loc.uwsgi_pass.is_some()
            || loc.scgi_pass.is_some();
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

        #[cfg(feature = "alloc-count")]
        let mark1 = {
            crate::alloccnt::set_phase(0);
            crate::alloccnt::mark(mark0)
        };
        let started = SystemTime::now();
        let state = ConnState {
            requests: served,
            started: conn_started,
        };
        let mut guards_sink: Vec<crate::limit::ConnGuard> = Vec::new();
        let peer_port = conn.peer.port();
        let client_ip = &client_ip_owned;
        // Local address of this connection (nginx uses it when the Host header
        // is missing or unusable).
        let local_ip = &local_ip_owned;
        let outcome = dispatch(
            &mut conn,
            &req,
            &path,
            &query,
            server,
            loc,
            http,
            group.addr.port(),
            &all_caps,
            state,
            &local_ip,
            peer_port,
            &client_ip,
            &mut guards_sink,
        )
        .await;
        let elapsed = started.elapsed().unwrap_or_default();

        #[cfg(feature = "alloc-count")]
        let mark2 = {
            crate::alloccnt::set_phase(1);
            crate::alloccnt::mark(mark1)
        };
        // `limit_conn` slots are held until the response has been written.
        drop(guards_sink);
        let (status, bytes, close, sent) = match outcome {
            Ok(o) => (o.status, o.bytes, o.close, o.sent),
            Err(_e) => (499, 0, true, Vec::new()),
        };

        #[cfg(feature = "alloc-count")]
        crate::alloccnt::set_phase(2);
        log_access(
            ctx,
            group,
            server,
            &req,
            &path,
            &query,
            status,
            bytes,
            elapsed,
            conn.peer,
            &sent,
            loc.access_logs.as_deref(),
        );
        #[cfg(feature = "alloc-count")]
        let _ = {
            let m = crate::alloccnt::mark(mark2);
            crate::alloccnt::set_phase(0);
            m
        };

        if close || !req.keepalive || util::force_close(status) || served >= http.keepalive_requests
        {
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
    match static_file::respond(req, path, query, loc, http) {
        Ok(r) => r,
        Err(_) => error_response(404, server.server_tokens),
    }
}

/// The ACCESS phase: `allow`/`deny`, `auth_basic` and `auth_request`, combined
/// by `satisfy`.
///
/// These are three handlers of one nginx phase:
///
///   satisfy all (default) - the first failure wins, and later handlers do not
///                           get to override it.
///   satisfy any            - one success is enough; when everything fails 401
///                            outranks 403.
///
/// Both rules come from auth_request_satisfy.t, which asserts that `deny all`
/// next to an auth server answering 401 yields 403 under `all` but 401 under
/// `any`.
///
/// Returns `None` when the request may proceed, otherwise the response to send.
/// On success the `auth_request_set` assignments are written into `custom`,
/// which is why this takes the map mutably instead of living inside `route`.
#[allow(clippy::too_many_arguments)]
async fn access_phase(
    req: &Request,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
    vars: &ServerVars<'_>,
    sets: &mut Vec<(String, String)>,
) -> Option<Response> {
    // nginx reports `unix:` as the peer address for a unix socket, which does
    // not parse as an IP; `peer_unix` is what `allow unix:` keys off.
    let peer_addr: std::net::IpAddr = vars
        .peer_ip
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let peer_unix = vars.peer_ip == "unix:";

    for le in &loc.limit_except {
        // `limit_except` applies to every method *except* the listed ones.
        let m = req.method.as_str();
        if !le.methods.iter().any(|x| x == m)
            && crate::config::access_denied_for(&le.rules, peer_addr, peer_unix)
        {
            return Some(error_response(403, server.server_tokens));
        }
    }

    let access_code: u16 = if crate::config::access_denied_for(&loc.access, peer_addr, peer_unix) {
        403
    } else {
        0
    };
    let basic_on = loc.auth_basic.enabled();
    let request_on = loc.auth_request.is_some();

    // Only handlers that are actually configured take part: an absent
    // `allow`/`deny` must not count as a passing check, or `satisfy any` would
    // always succeed.
    let access_on = !loc.access.is_empty();
    // Response headers of the auth subrequest, for `auth_request_set`.
    let mut auth_headers: Vec<(String, String)> = Vec::new();
    if access_code != 0 || basic_on || request_on {
        // 0 marks a passing check; anything else is the status it produced.
        let mut codes: Vec<u16> = Vec::new();
        if access_on {
            codes.push(access_code);
        }
        if basic_on {
            let header = req.headers.get("authorization");
            codes.push(match crate::auth::check(&loc.auth_basic, header) {
                crate::auth::Verdict::Ok => 0,
                crate::auth::Verdict::Reject => 401,
            });
        }
        if let Some(target) = &loc.auth_request {
            let (st, hdrs) = auth_request_status(req, target, server, http, vars).await;
            codes.push(st.unwrap_or(0));
            auth_headers = hdrs;
        }

        let status = if loc.satisfy_any {
            if codes.iter().any(|c| *c == 0) {
                None
            } else if codes.contains(&401) {
                Some(401)
            } else {
                Some(codes.iter().copied().find(|c| *c != 0).unwrap_or(403))
            }
        } else {
            codes.iter().copied().find(|c| *c != 0)
        };

        if let Some(status) = status {
            let mut resp = error_response(status, server.server_tokens);
            if status == 401 {
                // nginx forwards every `WWW-Authenticate` the auth subrequest
                // produced (a proxy-based check can return several, and they
                // must all reach the client). Only when the subrequest supplied
                // none do we fall back to the realm of a local `auth_basic`.
                let from_subrequest: Vec<&str> = auth_headers
                    .iter()
                    .filter(|(k, _)| k == "upstream_http_www_authenticate")
                    .map(|(_, v)| v.as_str())
                    .collect();
                let mut extra = Vec::new();
                if from_subrequest.is_empty() {
                    let realm = loc
                        .auth_basic
                        .realm
                        .clone()
                        .unwrap_or_else(|| "restricted".to_string());
                    crate::auth::www_authenticate(&realm, &mut extra);
                } else {
                    for v in from_subrequest {
                        extra.extend_from_slice(b"WWW-Authenticate: ");
                        extra.extend_from_slice(v.as_bytes());
                        extra.extend_from_slice(b"\r\n");
                    }
                }
                resp.raw.splice(0..0, extra);
            }
            return Some(resp);
        }
    }

    // The auth subrequest succeeded: apply its `auth_request_set` values. They
    // are visible to `add_header`, to a later `proxy_pass` target (`$args`) and
    // across an `error_page` internal redirect, which is what
    // auth_request_set.t checks.
    if request_on {
        for (name, value) in &loc.auth_request_set {
            // `$upstream_http_*` names the auth subrequest's own headers; other
            // variables come from the main request.
            let expanded = if value.contains("$upstream_http_") {
                let mut out = String::with_capacity(value.len());
                let mut rest = value.as_str();
                while let Some(pos) = rest.find('$') {
                    out.push_str(&rest[..pos]);
                    let tail = &rest[pos + 1..];
                    let end = tail
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(tail.len());
                    let name = &tail[..end];
                    match name.strip_prefix("upstream_http_") {
                        Some(suffix) => {
                            let want = format!("upstream_http_{}", suffix.to_ascii_lowercase());
                            out.push_str(
                                auth_headers
                                    .iter()
                                    .find(|(k, _)| *k == want)
                                    .map(|(_, v)| v.as_str())
                                    .unwrap_or(""),
                            );
                        }
                        None => out.push_str(&vars.expand(&format!("${name}"))),
                    }
                    rest = &tail[end..];
                }
                out.push_str(rest);
                out
            } else {
                vars.expand(value)
            };
            sets.push((name.clone(), expanded));
        }
    }
    None
}

/// Run an `auth_request` subrequest and map its status the way nginx does.
///
/// 2xx allows the request, 401 and 403 are propagated, and anything else is
/// reported as 500 — nginx treats an auth server that answers 404 or 5xx as a
/// broken access check rather than a decision.
/// `None` when the auth server allowed the request, otherwise the status to
/// report. Boxed because the subrequest re-enters `resolve_response`, which
/// would otherwise make it infinitely sized.
fn auth_request_status<'a>(
    req: &'a Request,
    target: &'a str,
    server: &'a Server,
    http: &'a Http,
    vars: &'a ServerVars<'a>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = (Option<u16>, Vec<(String, String)>)> + Send + 'a>,
> {
    Box::pin(auth_request_status_inner(req, target, server, http, vars))
}

async fn auth_request_status_inner(
    req: &Request,
    target: &str,
    server: &Server,
    http: &Http,
    vars: &ServerVars<'_>,
) -> (Option<u16>, Vec<(String, String)>) {
    let (ipath, iquery) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };
    let aloc = server.locate(&ipath);
    // The subrequest inherits the client's address but carries no body: nginx
    // answers "header only" and any body read here would consume the main
    // request's.
    let sub = resolve_response(
        req,
        &ipath,
        &iquery,
        server,
        aloc,
        http,
        vars.peer_ip,
        vars.server_port,
    )
    .await;
    // The subrequest's response headers are exposed as `$upstream_http_*` to
    // the `auth_request_set` expressions that follow, which is how
    // auth_request_set.t extracts an authenticated user name.
    // Headers may live in `raw` (rendered) or in `headers` (dynamic), depending
    // on which content handler produced the subrequest response.
    let mut headers: Vec<(String, String)> = sub
        .headers
        .iter()
        // nginx spells a header variable with `_` where the header has `-`.
        .map(|(k, v)| {
            (
                format!("upstream_http_{}", k.to_ascii_lowercase().replace('-', "_")),
                v.clone(),
            )
        })
        .collect();
    headers.extend(sub.raw.split(|b| *b == b'\n').filter_map(|line| {
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        let (k, v) = line.split_once(':')?;
        if k.is_empty() || line.starts_with(|c: char| c.is_whitespace()) {
            return None;
        }
        Some((
            format!("upstream_http_{}", k.to_ascii_lowercase().replace('-', "_")),
            v.trim().to_string(),
        ))
    }));
    let code = match sub.status {
        200..=299 => None,
        401 => Some(401),
        403 => Some(403),
        _ => Some(500),
    };
    (code, headers)
}

/// Evaluate the ACCESS phase for a location whose content handler is an upstream
/// protocol.
///
/// `auth_basic`, `auth_request` and `allow`/`deny` are ACCESS-phase handlers, so
/// nginx runs them *before* the content phase. The upstream protocols here are
/// dispatched ahead of the generic route, which means without this a
/// `location / { auth_basic ...; proxy_pass ...; }` would proxy the request
/// without ever asking for credentials.
///
/// Returns the response to send when the request is denied, plus the query the
/// content handler must use: `auth_request_set $args ...` rewrites the request
/// arguments, and nginx passes the rewritten value on to the upstream.
#[allow(clippy::too_many_arguments)]
async fn access_guard(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    state: ConnState,
    custom: &mut std::collections::HashMap<String, String>,
) -> (Option<Response>, Option<String>) {
    if !loc.auth_basic.enabled()
        && loc.auth_request.is_none()
        && loc.access.is_empty()
        && loc.limit_except.is_empty()
    {
        return (None, None);
    }
    let root = loc.root.to_string_lossy().to_string();
    let mut sets: Vec<(String, String)> = Vec::new();
    let denied = {
        let vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port,
            peer_ip,
            peer_port,
            scheme: if req.tls.is_some() { "https" } else { "http" },
            document_root: &root,
            upstream_cache_status: "",
            custom,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &[],
        };
        access_phase(req, loc, server, http, &vars, &mut sets).await
    };
    if denied.is_some() {
        return (denied, None);
    }
    for (name, value) in sets {
        custom.insert(name, value);
    }
    (None, custom.get("args").cloned())
}

/// ACCESS phase followed by the content phase, so every entry point (initial
/// dispatch, `error_page` file target, `error_page` named location) runs the
/// same checks in nginx's order.
///
/// The `ServerVars` view is built here, from the pieces, rather than passed in:
/// the access phase needs `&mut` access to the variable map to apply
/// `auth_request_set`, which cannot coexist with a borrowed view.
#[allow(clippy::too_many_arguments)]
async fn access_then_route(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
    allow_internal: bool,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    state: ConnState,
    custom: &mut std::collections::HashMap<String, String>,
) -> Response {
    let root = loc.root.to_string_lossy().to_string();
    // A macro rather than a closure: the borrow of `custom` has to be reborrowed
    // for each use, and a closure would pin it to one lifetime.
    macro_rules! view {
        ($c:expr) => {
            ServerVars {
                req,
                path,
                query,
                server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                server_port,
                peer_ip,
                peer_port,
                scheme: if req.tls.is_some() { "https" } else { "http" },
                document_root: &root,
                upstream_cache_status: "",
                custom: $c,
                connection_requests: state.requests,
                connection_time: state.elapsed_secs(),
                sent: &[],
            }
        };
    }
    // The assignments are collected first and applied after the borrow of the
    // map by `ServerVars` ends.
    let mut sets: Vec<(String, String)> = Vec::new();
    let check = access_phase(req, loc, server, http, &view!(custom), &mut sets).await;
    if let Some(denied) = check {
        return denied;
    }
    for (name, value) in sets {
        custom.insert(name, value);
    }
    // `auth_request_set $args ...` rewrites the request arguments, so the
    // content phase (and any `proxy_pass` target) sees the new value. nginx
    // stores one string for `$args`, and setting it updates `r->args`.
    let rewritten = custom.get("args").cloned();
    let query = rewritten.as_deref().unwrap_or(query);
    route(
        req,
        path,
        query,
        loc,
        server,
        http,
        allow_internal,
        &view!(custom),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn route(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    server: &Server,
    http: &Http,
    allow_internal: bool,
    vars: &ServerVars<'_>,
) -> Response {
    let peer_addr: std::net::IpAddr = vars
        .peer_ip
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    // A location named `/foo/` makes `/foo` redirect to `/foo/`.
    if let Some(location) = server.auto_redirect(path) {
        let mut target = util::escape_uri(&location);
        if !query.is_empty() {
            target.push('?');
            target.push_str(query);
        }
        return Response::empty(301).header("Location", target);
    }

    if loc.internal && !allow_internal {
        return error_response(404, server.server_tokens);
    }

    if let Some((code, body)) = &loc.ret {
        let status = *code;
        // nginx expands variables in both the URL and the body text.
        let body = &vars.expand(body);
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

    // A `proxy_pass` location reached through `route` -- an `error_page`
    // target, or a named location -- must actually reach the upstream. `route`
    // is the socket-free resolver used by those paths, and without this branch
    // the request fell through to the static handler and answered 404, so
    // `error_page 404 = /fallback` (bare `=`, adopt the target's status)
    // reported the original 404 instead of the proxied status.
    if loc.proxy_pass.is_some() {
        return match crate::proxy::fetch(req, path, query, loc, http, vars.peer_ip, vars.custom)
            .await
        {
            Some(resp) => resp,
            None => error_response(502, server.server_tokens),
        };
    }

    match static_file::respond(req, path, query, loc, http) {
        Ok(r) => r,
        Err(_) => error_response(404, server.server_tokens),
    }
}

pub fn error_response(status: u16, tokens: bool) -> Response {
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
                v.req.headers.get_joined(&key).unwrap_or_default()
            } else if let Some(want) = bare.strip_prefix("arg_") {
                v.query
                    .split('&')
                    .filter_map(|p| p.split_once('='))
                    .find(|(k, _)| k.eq_ignore_ascii_case(want))
                    .map(|(_, val)| val.to_string())
                    .unwrap_or_default()
            } else if let Some(want) = bare.strip_prefix("cookie_") {
                cookie_value(v.req, want)
            } else if bare == "is_args" || bare == "query_string" || bare == "args" {
                v.query.to_string()
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
            // The right-hand side is only a variable when it actually contains
            // `$`. Treating a bare literal as a variable made it expand to the
            // empty string, so `if ($args = "novary")` matched an empty `$args`.
            let rhs_val = if rhs.contains('$') {
                get_var(rhs, v)
            } else {
                rhs.clone()
            };
            let res = lhs == rhs_val;
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
    apply_rewrites_parts(
        req,
        path,
        query,
        &loc.sets,
        &loc.ifs,
        &loc.steps,
        &loc.rewrites,
        server,
        default_type,
    )
}

/// Same, but with the three directive lists supplied explicitly (server-level
/// `set`/`if` have no location of their own).
#[allow(clippy::too_many_arguments)]
fn apply_rewrites_parts(
    req: &Request,
    path: &str,
    query: &str,
    sets: &[(String, String)],
    ifs: &[crate::config::IfBlock],
    steps: &[crate::config::Step],
    rewrites: &[crate::config::Rewrite],
    server: &Server,
    default_type: &str,
) -> RewriteOutcome {
    apply_rewrites_full(
        req,
        path,
        query,
        sets,
        ifs,
        steps,
        rewrites,
        server,
        default_type,
    )
    .0
}

/// Same, but also returns the variables `set` produced.
#[allow(clippy::too_many_arguments)]
fn apply_rewrites_full(
    req: &Request,
    path: &str,
    query: &str,
    sets: &[(String, String)],
    ifs: &[crate::config::IfBlock],
    steps: &[crate::config::Step],
    rewrites: &[crate::config::Rewrite],
    server: &Server,
    default_type: &str,
) -> (RewriteOutcome, std::collections::HashMap<String, String>) {
    let mut uri = path.to_string();
    let mut args = query.to_string();
    let _ = req;

    // nginx runs `set` and `if` interleaved, in source order; a config that
    // re-assigns a variable between two `if`s depends on that order.
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let default_order: Vec<crate::config::Step>;
    let order: &[crate::config::Step] = if steps.is_empty() {
        default_order = sets
            .iter()
            .enumerate()
            .map(|(i, _)| crate::config::Step::Set(i))
            .chain(
                ifs.iter()
                    .enumerate()
                    .map(|(i, _)| crate::config::Step::If(i)),
            )
            .collect();
        &default_order
    } else {
        steps
    };

    for step in order {
        match *step {
            crate::config::Step::Set(idx) => {
                let Some((name, value)) = sets.get(idx) else {
                    continue;
                };
                let ctx = RwVars {
                    req,
                    path: &uri,
                    query: &args,
                    vars: &vars,
                };
                let expanded = expand_vars(value, &ctx);
                vars.insert(name.trim_start_matches('$').to_string(), expanded);
            }
            crate::config::Step::If(idx) => {
                let Some(ifb) = ifs.get(idx) else {
                    continue;
                };
                if let Some(out) = run_if(
                    ifb,
                    req,
                    &mut uri,
                    &mut args,
                    &mut vars,
                    rewrites,
                    default_type,
                ) {
                    return (out, vars);
                }
            }
        }
    }
    for rw in rewrites {
        if let Some(out) = apply_one(rw, &mut uri, &mut args) {
            return (out, vars);
        }
    }
    let _ = server;
    (RewriteOutcome::Continue(uri, args), vars)
}

/// Evaluate one `if` block: its `set`s, an optional `return`, then rewrites.
///
/// `None` means "carry on with the next step"; `Some` is a terminal outcome.
#[allow(clippy::too_many_arguments)]
fn run_if(
    ifb: &crate::config::IfBlock,
    req: &Request,
    uri: &mut String,
    args: &mut String,
    vars: &mut std::collections::HashMap<String, String>,
    _rewrites: &[crate::config::Rewrite],
    default_type: &str,
) -> Option<RewriteOutcome> {
    let cond = {
        let ctx = RwVars {
            req,
            path: uri,
            query: args,
            vars,
        };
        eval_cond(&ifb.cond, &ctx)
    };
    if !cond {
        return None;
    }
    for (name, value) in &ifb.sets {
        let ctx = RwVars {
            req,
            path: uri,
            query: args,
            vars,
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
            // nginx picks the type from the URI extension, else default_type.
            let ext = match uri.rfind('.') {
                Some(i) if i + 1 < uri.len() => uri[i + 1..].to_ascii_lowercase(),
                _ => String::new(),
            };
            let ctype = default_type_for(ext.as_str(), default_type);
            Response::bytes(status, &ctype, body.clone().into_bytes())
        };
        // A `return` produced by `if` is not subject to `error_page`.
        resp.no_error_page = true;
        return Some(RewriteOutcome::Respond(resp));
    }
    for rw in &ifb.rewrites {
        if let Some(out) = apply_one(rw, uri, args) {
            return Some(out);
        }
    }
    None
}

/// Apply one rewrite rule; `None` means "keep scanning".
fn apply_one(
    rw: &crate::config::Rewrite,
    uri: &mut String,
    args: &mut String,
) -> Option<RewriteOutcome> {
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
            let code = if rw.flag == RewriteFlag::Permanent {
                301
            } else {
                302
            };
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

/// Split rendered header lines back into (name, value) pairs.
/// `$sent_http_*` is the only consumer of the sent-header list, and building it
/// costs two `String`s per header line. With no access log configured that work
/// is pure waste, so callers gate on this.
#[inline]
fn sent_headers_needed(server: &Server) -> bool {
    !server.access_logs.is_empty()
}

/// Parse a rendered header block into `(name, value)` pairs.
pub fn split_head(raw: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(raw).split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Apply the `expires` directive to a rendered header block.
pub fn apply_expires(raw: &mut Vec<u8>, loc: &LocCfg) {
    let Some(spec) = &loc.expires else { return };
    let spec = spec.trim();
    let (expires_value, cache_control): (String, Option<CacheControl>) = match spec {
        "off" => (String::new(), None),
        "epoch" => (
            "Thu, 01 Jan 1970 00:00:01 GMT".to_string(),
            Some(CacheControl::Fixed("no-cache")),
        ),
        "max" => (
            "Thu, 31 Dec 2037 23:55:55 GMT".to_string(),
            Some(CacheControl::Fixed("max-age=315360000")),
        ),
        other => {
            let (neg, body) = match other.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, other),
            };
            match crate::config::parse_time(body) {
                Some(d) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let secs = d.as_secs() as i64;
                    let at = if neg { now - secs } else { now + secs };
                    let max_age = if neg { 0 } else { secs };
                    (util::http_date(at), Some(CacheControl::MaxAge(max_age)))
                }
                None => (String::new(), None),
            }
        }
    };
    // nginx's expires *replaces* any Cache-Control the upstream produced.
    if cache_control.is_some() || !expires_value.is_empty() {
        let text = String::from_utf8_lossy(raw).to_string();
        let kept: Vec<&str> = text
            .split("\r\n")
            .filter(|line| {
                !line.is_empty()
                    && !line.to_ascii_lowercase().starts_with("cache-control:")
                    && !(cache_control.is_some()
                        && line.to_ascii_lowercase().starts_with("expires:"))
            })
            .collect();
        let mut rebuilt = Vec::with_capacity(raw.len());
        for line in kept {
            rebuilt.extend_from_slice(line.as_bytes());
            rebuilt.extend_from_slice(b"\r\n");
        }
        *raw = rebuilt;
    }

    if !expires_value.is_empty() {
        raw.extend_from_slice(b"Expires: ");
        raw.extend_from_slice(expires_value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    match cache_control {
        Some(CacheControl::Fixed(v)) => {
            raw.extend_from_slice(b"Cache-Control: ");
            raw.extend_from_slice(v.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        Some(CacheControl::MaxAge(n)) => {
            raw.extend_from_slice(b"Cache-Control: max-age=");
            raw.extend_from_slice(n.to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        None => {}
    }
}

/// `Cache-Control` value produced by `expires`.
enum CacheControl {
    Fixed(&'static str),
    MaxAge(i64),
}

/// Parse a nginx rate/size string: `40k` -> 40960, `1m` -> 1048576, junk -> 0.
fn parse_rate(spec: &str) -> u64 {
    let spec = spec.trim();
    if spec.is_empty() {
        return 0;
    }
    let (digits, mult) = match spec.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&spec[..spec.len() - 1], 1024u64),
        Some(b'm') | Some(b'M') => (&spec[..spec.len() - 1], 1024 * 1024),
        Some(b'g') | Some(b'G') => (&spec[..spec.len() - 1], 1024 * 1024 * 1024),
        _ => (spec, 1),
    };
    digits.trim().parse::<u64>().map(|n| n * mult).unwrap_or(0)
}

/// Decode the user part of an HTTP Basic credential.
fn base64_decode_user(b64: &str) -> Option<String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out: Vec<u8> = Vec::with_capacity(b64.len());
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in b64.bytes() {
        let v = match ch {
            b'=' => break,
            c => TABLE.iter().position(|t| *t == c)? as u32,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    text.split_once(':').map(|(u, _)| u.to_string())
}

/// Resolve `$name` exactly as `ServerVars::get` would. Used by `proxy_pass`
/// target expansion so the two never drift.
pub(crate) fn resolve_var_for_proxy(
    name: &str,
    req: &Request,
    peer_ip: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    args: &str,
    server_port: u16,
) -> Option<String> {
    thread_local! {
        static EMPTY_CUSTOM: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
    }
    EMPTY_CUSTOM.with(|c| {
        let v = ServerVars {
            req,
            path: uri,
            query: args,
            server_name: host,
            server_port,
            peer_ip,
            peer_port: 0,
            scheme,
            document_root: "",
            upstream_cache_status: "",
            custom: c,
            connection_requests: 0,
            connection_time: 0,
            sent: &[],
        };
        Some(v.get(name))
    })
}

pub(crate) fn cookie_value(req: &Request, want: &str) -> String {
    let Some(cookie) = req.headers.get_joined("cookie") else {
        return String::new();
    };
    let mut out: Vec<&str> = Vec::new();
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim().eq_ignore_ascii_case(want) {
                out.push(v.trim());
            }
        }
    }
    out.join(", ")
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
/// Variant for the proxy paths: knows the cache status and `$upstream_addr`.

/// Evaluate `add_trailer` for a response.
///
/// Mirrors `ngx_http_headers_filter`: any directive whose status matches sets
/// `expect_trailers` (which forces chunked encoding) *before* the value is
/// known, so `add_trailer X ""` still produces a chunked response with no
/// trailer lines. Only non-empty values become actual trailers, and later
/// directives can see earlier ones through `$sent_trailer_*`.
pub fn eval_trailers(
    trailers: &[(String, String)],
    status: u16,
    vars: &ServerVars<'_>,
) -> (bool, Vec<(String, String)>) {
    let mut expect = false;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for (name, value) in trailers {
        let (value, always) = match value.rsplit_once(' ') {
            Some((v, "always")) => (v, true),
            _ => (value.as_str(), false),
        };
        if !add_header_applies(status, always) {
            continue;
        }
        expect = true;

        let mut custom = vars.custom.clone();
        for (k, v) in &seen {
            custom.insert(k.clone(), v.clone());
        }
        let scoped = ServerVars {
            custom: &custom,
            ..*vars
        };
        let expanded = scoped.expand(value);
        if expanded.is_empty() {
            continue;
        }
        let key = name.to_ascii_lowercase().replace('-', "_");
        seen.entry(format!("sent_trailer_{key}"))
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&expanded);
            })
            .or_insert_with(|| expanded.clone());
        out.push((name.clone(), expanded));
    }
    (expect, out)
}

/// `add_header` is *not* always additive: nginx's `ngx_http_set_headers` table
/// gives `Last-Modified` and `ETag` a setter that replaces the existing value
/// (`Cache-Control` and `Link` append to a list instead).
///
/// `proxy_force_ranges.t` depends on this: an upstream `add_header ETag "..."` is
/// seen by `If-Range`, which only works because the file's own ETag is gone.
fn drop_replaced_header(raw: &mut Vec<u8>, name: &str) {
    if !name.eq_ignore_ascii_case("last-modified") && !name.eq_ignore_ascii_case("etag") {
        return;
    }
    let src = std::mem::take(raw);
    let mut pos = 0usize;
    let mut out = Vec::with_capacity(src.len());
    while pos < src.len() {
        let end = memchr::memmem::find(&src[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(src.len());
        let line = &src[pos..end];
        let same = line.len() > name.len()
            && line[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            && line[name.len()] == b':';
        if !same {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        pos = end + 2;
    }
    *raw = out;
}

pub fn apply_add_headers_upstream(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    upstream_cache_status: &str,
    upstream_addr: &str,
) {
    apply_add_headers_full(
        raw,
        headers,
        status,
        upstream_cache_status,
        upstream_addr,
        &[],
    )
}

/// Same, but with the configured `proxy_pass` authority for `$proxy_host` /
/// `$proxy_port` (the backend address is not the same thing).
#[allow(clippy::too_many_arguments)]
pub fn apply_add_headers_proxy(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    upstream_cache_status: &str,
    upstream_addr: &str,
    upstream_headers: &[(String, String)],
    proxy_host: &str,
    ctx_vars: Option<&ServerVars<'_>>,
) {
    apply_add_headers_ctx(
        raw,
        headers,
        status,
        upstream_cache_status,
        upstream_addr,
        upstream_headers,
        ctx_vars,
        proxy_host,
    )
}

/// Full variant, with the upstream response headers for `$upstream_http_*`.
pub fn apply_add_headers_full(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    upstream_cache_status: &str,
    upstream_addr: &str,
    upstream_headers: &[(String, String)],
) {
    apply_add_headers_ctx(
        raw,
        headers,
        status,
        upstream_cache_status,
        upstream_addr,
        upstream_headers,
        None,
        "",
    )
}

/// Variant that can expand every variable; used when a `ServerVars` is in scope.
#[allow(clippy::too_many_arguments)]
pub fn apply_add_headers_ctx(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    upstream_cache_status: &str,
    upstream_addr: &str,
    upstream_headers: &[(String, String)],
    ctx_vars: Option<&ServerVars<'_>>,
    proxy_host: &str,
) {
    let mut sent: Vec<(String, String)> = split_head(raw);
    for (name, value) in headers {
        let (value, always) = match value.rsplit_once(' ') {
            Some((v, "always")) => (v, true),
            _ => (value.as_str(), false),
        };
        if !add_header_applies(status, always) {
            continue;
        }
        // Upstream variables first: the generic resolver would drop them as
        // unknown.
        let proxy_port = match proxy_host.rsplit_once(':') {
            Some((_, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => p.to_string(),
            _ => "80".to_string(),
        };
        let mut expanded = expand_upstream_vars(value, upstream_headers)
            .replace("$upstream_cache_status", upstream_cache_status)
            .replace("$upstream_addr", upstream_addr)
            .replace("$proxy_host", proxy_host)
            .replace("$proxy_port", &proxy_port)
            .replace("$status", &status.to_string());
        expanded = crate::timing::expand(&expanded);
        if expanded.contains("$proxy_add_x_forwarded_for") {
            if let Some(v) = ctx_vars {
                let prior = v
                    .req
                    .headers
                    .get("x-forwarded-for")
                    .unwrap_or("")
                    .to_string();
                let xff = if prior.is_empty() {
                    v.peer_ip.to_string()
                } else {
                    format!("{prior}, {}", v.peer_ip)
                };
                expanded = expanded.replace("$proxy_add_x_forwarded_for", &xff);
            }
        }
        if let Some(v) = ctx_vars {
            let local = ServerVars {
                req: v.req,
                path: v.path,
                query: v.query,
                server_name: v.server_name,
                server_port: v.server_port,
                peer_ip: v.peer_ip,
                peer_port: v.peer_port,
                scheme: v.scheme,
                document_root: v.document_root,
                upstream_cache_status,
                custom: v.custom,
                connection_requests: v.connection_requests,
                connection_time: v.connection_time,
                sent: &sent,
            };
            expanded = local.expand(&expanded);
        }
        if expanded.is_empty() {
            continue;
        }
        drop_replaced_header(raw, name);
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(expanded.as_bytes());
        raw.extend_from_slice(b"\r\n");
        sent.push((name.clone(), expanded));
    }
}

/// Replace `$upstream_http_*` and `$upstream_cookie_*` from an upstream reply.
fn expand_upstream_vars(spec: &str, upstream: &[(String, String)]) -> String {
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
        let name = &rest[..n];
        let value = if let Some(h) = name.strip_prefix("upstream_http_") {
            let key = h.replace('_', "-");
            let vals: Vec<&str> = upstream
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(&key))
                .map(|(_, v)| v.as_str())
                .collect();
            Some(vals.join(", "))
        } else if let Some(c) = name.strip_prefix("upstream_cookie_") {
            // nginx joins repeated Set-Cookie headers with ", " before parsing.
            let joined = upstream
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let mut found: Vec<&str> = Vec::new();
            for part in joined.split(&[';', ','][..]) {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    if k.trim().eq_ignore_ascii_case(c) {
                        found.push(v.trim());
                    }
                }
            }
            Some(found.join(", "))
        } else {
            None
        };
        match value {
            Some(v) => {
                out.push_str(&v);
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

/// Minimal variant for callers that only know the cache status (the proxy
/// paths already hold the rendered response and no `ServerVars`).
pub fn apply_add_headers_simple(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    upstream_cache_status: &str,
) {
    for (name, value) in headers {
        let (value, always) = match value.rsplit_once(' ') {
            Some((v, "always")) => (v, true),
            _ => (value.as_str(), false),
        };
        if !add_header_applies(status, always) {
            continue;
        }
        let expanded = value.replace("$upstream_cache_status", upstream_cache_status);
        if expanded.is_empty() {
            continue;
        }
        drop_replaced_header(raw, name);
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(expanded.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
}

pub fn apply_add_headers(
    raw: &mut Vec<u8>,
    headers: &[(String, String)],
    status: u16,
    vars: &ServerVars<'_>,
) {
    // nginx evaluates add_header left to right, so `$sent_http_*` in a later
    // header sees the ones already added.
    let mut sent: Vec<(String, String)> = split_head(raw);
    for (name, value) in headers {
        let (value, always) = match value.rsplit_once(' ') {
            Some((v, "always")) => (v, true),
            _ => (value.as_str(), false),
        };
        if !add_header_applies(status, always) {
            continue;
        }
        let local = ServerVars {
            req: vars.req,
            path: vars.path,
            query: vars.query,
            server_name: vars.server_name,
            server_port: vars.server_port,
            peer_ip: vars.peer_ip,
            peer_port: vars.peer_port,
            scheme: vars.scheme,
            document_root: vars.document_root,
            upstream_cache_status: vars.upstream_cache_status,
            custom: vars.custom,
            connection_requests: vars.connection_requests,
            connection_time: vars.connection_time,
            sent: &sent,
        };
        let expanded = local.expand(value);
        // nginx drops the header when the value expands to nothing.
        if expanded.is_empty() {
            continue;
        }
        drop_replaced_header(raw, name);
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(expanded.as_bytes());
        raw.extend_from_slice(b"\r\n");
        sent.push((name.clone(), expanded));
    }
}

pub struct AddHeaderVars<'a> {
    pub upstream_cache_status: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
}

/// Full variable set available to `return`, `add_header`, `rewrite` and the
/// upstream `*_set_header`/`*_param` directives.
pub struct ServerVars<'a> {
    pub req: &'a Request,
    pub path: &'a str,
    pub query: &'a str,
    pub server_name: &'a str,
    pub server_port: u16,
    pub peer_ip: &'a str,
    pub peer_port: u16,
    pub scheme: &'a str,
    pub document_root: &'a str,
    pub upstream_cache_status: &'a str,
    /// Values from `set`, which override the built-ins.
    pub custom: &'a std::collections::HashMap<String, String>,
    pub connection_requests: u64,
    pub connection_time: u64,
    /// Response headers already produced for this reply; backs `$sent_http_*`.
    pub sent: &'a [(String, String)],
}

thread_local! {
    /// Guards against `map` cycles (`map $a $b` + `map $b $a`).
    static MAP_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

impl<'a> ServerVars<'a> {
    /// Resolve a `map`-defined variable, if `name` is one.
    fn map_var(&self, name: &str) -> Option<String> {
        let maps = crate::config::maps();
        let def = maps.iter().find(|m| m.var == name)?;
        if MAP_DEPTH.with(|d| d.get()) > 16 {
            return Some(String::new());
        }
        let source = self.expand(&def.source);
        let value = def.lookup(&source)?.to_string();
        MAP_DEPTH.with(|d| d.set(d.get() + 1));
        let out = self.expand(&value);
        MAP_DEPTH.with(|d| d.set(d.get() - 1));
        Some(out)
    }

    /// Resolve a `geo`-defined variable, if `name` is one.
    fn geo_var(&self, name: &str) -> Option<String> {
        let geos = crate::config::geos();
        let def = geos.iter().find(|g| g.var == name)?;
        // The source defaults to `$remote_addr`, which `proxy` may replace
        // with an X-Forwarded-For entry.
        let addr = match &def.source {
            Some(src) => self.expand(src),
            None => {
                let xff = self.req.headers.get("x-forwarded-for");
                def.resolve_addr(self.peer_ip, xff)
            }
        };
        let value = def.lookup(&addr)?.to_string();
        Some(self.expand(&value))
    }

    pub fn get(&self, name: &str) -> String {
        // `$limit_rate` has its own get handler: the stored string is parsed as
        // a rate, not returned verbatim.
        if name == "limit_rate" {
            let raw = self.custom.get(name).cloned().unwrap_or_default();
            return parse_rate(&raw).to_string();
        }
        if let Some(v) = self.custom.get(name) {
            return v.clone();
        }
        if let Some(v) = self.map_var(name) {
            return v;
        }
        if let Some(v) = self.geo_var(name) {
            return v;
        }
        let tls = self.req.tls.as_deref();
        match name {
            "host" => self
                .req
                .host
                .as_ref()
                .map(|h| h.as_str().to_string())
                // No Host header at all: nginx reports the selected server_name.
                .unwrap_or_else(|| {
                    if self.req.headers.get("host").is_some() {
                        String::new()
                    } else {
                        self.server_name.trim_start_matches('.').to_string()
                    }
                }),
            "http_host" => self.req.headers.get("host").unwrap_or("").to_string(),
            "uri" | "document_uri" => self.path.to_string(),
            "request_uri" => self.req.raw_target.clone(),
            "args" | "query_string" => self.query.to_string(),
            "is_args" => {
                if self.query.is_empty() {
                    String::new()
                } else {
                    "?".to_string()
                }
            }
            "request_method" => self.req.method.as_str().to_string(),
            // Derive from the connection rather than each call site's default:
            // the same `ServerVars` must answer correctly for TLS connections.
            "scheme" => {
                if self.req.tls.is_some() {
                    "https".to_string()
                } else {
                    self.scheme.to_string()
                }
            }
            // `$ssl_*` come straight from the TLS session. On plaintext they are
            // empty, which is also nginx's behaviour.
            "ssl_protocol" => tls.map(|t| t.version.clone()).unwrap_or_default(),
            "ssl_cipher" => tls.map(|t| t.cipher.clone()).unwrap_or_default(),
            "ssl_server_name" => tls.and_then(|t| t.server_name.clone()).unwrap_or_default(),
            "ssl_client_verify" => tls.map(|t| t.client_verify.clone()).unwrap_or_default(),
            "ssl_client_cert" => tls.map(|t| t.client_cert.clone()).unwrap_or_default(),
            "ssl_client_s_dn" => tls.map(|t| t.client_s_dn.clone()).unwrap_or_default(),
            "ssl_client_i_dn" => tls.map(|t| t.client_i_dn.clone()).unwrap_or_default(),
            "ssl_client_serial" => tls.map(|t| t.client_serial.clone()).unwrap_or_default(),
            "ssl_client_fingerprint" => tls
                .map(|t| t.client_fingerprint.clone())
                .unwrap_or_default(),
            "ssl_client_v_start" => tls.map(|t| t.client_v_start.clone()).unwrap_or_default(),
            "ssl_client_v_end" => tls.map(|t| t.client_v_end.clone()).unwrap_or_default(),
            "ssl_client_v_remain" => "0".to_string(),
            // nginx's default format for these two is
            // "Mon, 02 Jan 2006 15:04:05 GMT" (ngx_http_ssi_timefmt), and they
            // are available to every variable consumer, not just SSI.
            "date_gmt" | "date_local" => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                crate::util::strftime_gmt(now, "%A, %d-%b-%Y %H:%M:%S %Z")
            }
            "server_name" => self.server_name.trim_start_matches('.').to_string(),
            "server_port" => self.server_port.to_string(),
            "server_protocol" => {
                if self.req.version_minor == 1 {
                    "HTTP/1.1".to_string()
                } else {
                    "HTTP/1.0".to_string()
                }
            }
            "remote_addr" => self.peer_ip.to_string(),
            "remote_port" => self.peer_port.to_string(),
            // nginx: current time with millisecond resolution, `sec.msec`.
            "msec" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                format!("{}.{:03}", now.as_secs(), now.subsec_millis())
            }
            "remote_user" => self
                .req
                .headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Basic ").and_then(|b| base64_decode_user(b)))
                .unwrap_or_default(),
            "document_root" => self.document_root.to_string(),
            "request_filename" => format!("{}{}", self.document_root, self.path),
            "upstream_cache_status" => self.upstream_cache_status.to_string(),
            "content_length" => self
                .req
                .headers
                .get("content-length")
                .unwrap_or("")
                .to_string(),
            "content_type" => self
                .req
                .headers
                .get_joined("content-type")
                .unwrap_or_default(),
            "connection_requests" => self.connection_requests.to_string(),
            "connection_time" => self.connection_time.to_string(),
            // Second with millisecond precision, as nginx formats it
            // (`%T.%03M` from the request start).
            "request_time" => {
                let d = self.req.started.elapsed();
                format!("{}.{:03}", d.as_secs(), d.subsec_millis())
            }
            "hostname" => "ngxrs".to_string(),
            "nginx_version" => crate::COMPAT_VERSION.to_string(),
            _ => {
                if let Some(h) = name.strip_prefix("http_") {
                    let key = h.replace('_', "-");
                    self.req.headers.get_joined(&key).unwrap_or_default()
                } else if let Some(want) = name.strip_prefix("cookie_") {
                    cookie_value(self.req, want)
                } else if let Some(h) = name.strip_prefix("sent_http_") {
                    let key = h.replace('_', "-");
                    let joined: Vec<&str> = self
                        .sent
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case(&key))
                        .map(|(_, v)| v.as_str())
                        .collect();
                    joined.join(", ")
                } else if let Some(want) = name.strip_prefix("arg_") {
                    // $arg_name looks the key up in the query string. An empty
                    // value (`?a=`) is present-but-empty, which SSI's `#echo`
                    // must render as "" rather than "(none)", so it is carried
                    // through as a sentinel that the SSI host understands.
                    self.query
                        .split('&')
                        .filter_map(|pair| pair.split_once('='))
                        .find(|(k, _)| k.eq_ignore_ascii_case(want))
                        .map(|(_, v)| v.to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            }
        }
    }

    /// Expand `$var` / `${var}` references.
    pub fn expand(&self, spec: &str) -> String {
        let mut out = String::with_capacity(spec.len() + 8);
        let b = spec.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'$' {
                out.push(b[i] as char);
                i += 1;
                continue;
            }
            // ${name} or $name
            if i + 1 < b.len() && b[i + 1] == b'{' {
                if let Some(end) = spec[i + 2..].find('}') {
                    out.push_str(&self.get(&spec[i + 2..i + 2 + end]));
                    i += 2 + end + 1;
                    continue;
                }
                out.push('$');
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
            out.push_str(&self.get(&rest[..n]));
            i += 1 + n;
        }
        out
    }
}

/// Resolve a request to a `Response` without touching the socket: error_page
/// internal redirects plus the gzip filter. The HTTP/1 handler writes the
/// result; the HTTP/2 handler turns it into h2 frames.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_response(
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
    peer_ip: &str,
    server_port: u16,
) -> Response {
    resolve_response_caps(
        req,
        path,
        query,
        server,
        loc,
        http,
        peer_ip,
        0,
        server_port,
        &[],
    )
    .await
}

/// Result of the rewrite + try_files phase: either a final location, or a
/// response produced without consulting any content handler.
pub enum Target<'a> {
    /// Path, query, location, whether `rewrite ... break` skipped `return`,
    /// and the variables produced by `set`.
    Loc(
        String,
        String,
        &'a LocCfg,
        bool,
        std::collections::HashMap<String, String>,
    ),
    Done(Response),
}

/// Apply `rewrite`, `if`/`set` and `try_files` to find the target location.
pub fn resolve_target<'a>(
    req: &Request,
    path: &str,
    query: &str,
    server: &'a Server,
    loc: &'a LocCfg,
    http: &Http,
) -> Target<'a> {
    let mut cur_path = path.to_string();
    let mut cur_query = query.to_string();
    let mut cur_loc = loc;
    let mut relocations = 0usize;
    let mut skip_return = false;

    // Server-level `set` / `if` run before location selection.
    if !server.sets.is_empty() || !server.ifs.is_empty() {
        match apply_rewrites_parts(
            req,
            &cur_path,
            &cur_query,
            &server.sets,
            &server.ifs,
            &server.steps,
            &[],
            server,
            &http.default_type,
        ) {
            RewriteOutcome::Respond(r) => return Target::Done(r),
            RewriteOutcome::Continue(p, q) | RewriteOutcome::Relocate(p, q) => {
                cur_path = p;
                cur_query = q;
            }
            RewriteOutcome::Break(p, q) => {
                cur_path = p;
                cur_query = q;
                skip_return = true;
            }
        }
    }

    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    loop {
        let (outcome, phase_vars) = apply_rewrites_full(
            req,
            &cur_path,
            &cur_query,
            &cur_loc.sets,
            &cur_loc.ifs,
            &cur_loc.steps,
            &cur_loc.rewrites,
            server,
            &http.default_type,
        );
        vars.extend(phase_vars);
        match outcome {
            RewriteOutcome::Respond(r) => return Target::Done(r),
            RewriteOutcome::Continue(p, q) => {
                cur_path = p;
                cur_query = q;
                break;
            }
            RewriteOutcome::Break(p, q) => {
                cur_path = p;
                cur_query = q;
                skip_return = true;
                break;
            }
            RewriteOutcome::Relocate(p, q) => {
                cur_path = p;
                cur_query = q;
                cur_loc = server.locate(&cur_path);
                relocations += 1;
                if relocations > 10 {
                    return Target::Done(error_response(500, server.server_tokens));
                }
            }
        }
    }

    if !cur_loc.try_files.is_empty() && !skip_return {
        match try_files_action(req, &cur_path, cur_loc) {
            Some(TryFilesAction::Serve(uri)) => cur_path = uri,
            Some(TryFilesAction::Redirect(uri)) => {
                let (p, q) = match uri.split_once('?') {
                    Some((p, q)) => (p.to_string(), q.to_string()),
                    None => (uri, String::new()),
                };
                cur_path = p;
                cur_query = q;
                cur_loc = server.locate(&cur_path);
            }
            Some(TryFilesAction::Status(code)) => {
                return Target::Done(error_response(code, server.server_tokens))
            }
            None => {}
        }
    }

    Target::Loc(cur_path, cur_query, cur_loc, skip_return, vars)
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_response_caps(
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
) -> Response {
    resolve_response_local(
        req,
        path,
        query,
        server,
        loc,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        ConnState {
            requests: 0,
            started: std::time::Instant::now(),
        },
        "127.0.0.1",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_response_local(
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
) -> Response {
    let mut custom: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (k, v) in captures {
        custom.insert(k.clone(), v.clone());
    }
    // Reverse proxying needs a socket for streaming in HTTP/1; when this
    // resolver is used without one (HTTP/2), buffer the upstream reply instead.
    //
    // The ACCESS phase has to run first for the same reason as in `dispatch`:
    // these handlers are ahead of the generic route, so `auth_basic` /
    // `auth_request` / `allow`+`deny` would otherwise be skipped over HTTP/2.
    let (path_owned, query_owned);
    let (path, query) = {
        let (denied, args) = access_guard(
            req,
            path,
            query,
            loc,
            server,
            http,
            peer_ip,
            peer_port,
            server_port,
            state,
            &mut custom,
        )
        .await;
        if let Some(mut d) = denied {
            return finalize_response(
                req,
                &mut d,
                path,
                query,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                &mut custom,
                state,
                local_addr,
            )
            .await;
        }
        match args {
            Some(a) => {
                path_owned = path.to_string();
                query_owned = a;
                (path_owned.as_str(), query_owned.as_str())
            }
            None => (path, query),
        }
    };
    if loc.grpc_pass.is_some() {
        // `grpc_pass` accepts variables, so build the same variable view the
        // rest of the request uses rather than only handling literal targets.
        let grpc_vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port,
            peer_ip,
            peer_port,
            scheme: "http",
            document_root: loc.root.to_str().unwrap_or(""),
            upstream_cache_status: "",
            custom: &custom,
            connection_requests: state.requests,
            connection_time: 0,
            sent: &[],
        };
        if let Some(resp) =
            crate::grpc::fetch(http, loc, req, path, query, peer_ip, Some(&grpc_vars)).await
        {
            let mut resp = resp;
            return finalize_response(
                req,
                &mut resp,
                path,
                query,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                &mut custom,
                state,
                local_addr,
            )
            .await;
        }
    }

    if loc.proxy_pass.is_some() {
        if let Some(resp) = crate::proxy::fetch(req, path, query, loc, http, peer_ip, &custom).await
        {
            let mut resp = resp;
            return finalize_response(
                req,
                &mut resp,
                path,
                query,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                &mut custom,
                state,
                local_addr,
            )
            .await;
        }
    }

    let mut resp = match resolve_target(req, path, query, server, loc, http) {
        Target::Done(r) => r,
        Target::Loc(p, q, l, skip, set_vars) => {
            return render_resolved_state(
                req,
                &p,
                &q,
                l,
                skip,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                state,
                local_addr,
            )
            .await
        }
    };
    finalize_response(
        req,
        &mut resp,
        path,
        query,
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        &mut custom,
        state,
        local_addr,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_response_state(
    req: &Request,
    path: &str,
    query: &str,
    server: &Server,
    loc: &LocCfg,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
    state: ConnState,
) -> Response {
    let local_addr = "127.0.0.1";
    let mut cur_path = path.to_string();
    let mut cur_query = query.to_string();
    let mut cur_loc = loc;
    let mut depth = 0usize;

    // Named captures from `server_name ~regex` are ordinary variables.
    let mut custom: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (k, v) in captures {
        custom.insert(k.clone(), v.clone());
    }

    // Reverse proxying needs a socket for streaming in HTTP/1; when this
    // resolver is used without one (HTTP/2), buffer the upstream reply instead.
    if loc.proxy_pass.is_some() {
        if let Some(resp) = crate::proxy::fetch(req, path, query, loc, http, peer_ip, &custom).await
        {
            let mut resp = resp;
            return finalize_response(
                req,
                &mut resp,
                path,
                query,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                &mut custom,
                state,
                local_addr,
            )
            .await;
        }
    }

    let mut resp = match resolve_target(req, path, query, server, loc, http) {
        Target::Done(r) => r,
        Target::Loc(p, q, l, skip, set_vars) => {
            return render_resolved_state(
                req,
                &p,
                &q,
                l,
                skip,
                server,
                http,
                peer_ip,
                peer_port,
                server_port,
                captures,
                state,
                local_addr,
            )
            .await;
        }
    };
    let _ = &mut resp;
    finalize_response(
        req,
        &mut resp,
        path,
        query,
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        &mut custom,
        state,
        local_addr,
    )
    .await
}

/// Render an already-resolved target (rewrite/try_files done).
#[allow(clippy::too_many_arguments)]
pub async fn render_resolved(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    skip_return: bool,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
) -> Response {
    render_resolved_state(
        req,
        path,
        query,
        loc,
        skip_return,
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        ConnState {
            requests: 0,
            started: std::time::Instant::now(),
        },
        "127.0.0.1",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn render_resolved_ctx(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    skip_return: bool,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
) -> Response {
    render_resolved_state(
        req,
        path,
        query,
        loc,
        skip_return,
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        state,
        local_addr,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn render_resolved_state(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    skip_return: bool,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
) -> Response {
    render_resolved_vars(
        req,
        path,
        query,
        loc,
        skip_return,
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        captures,
        state,
        local_addr,
        &std::collections::HashMap::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn render_resolved_vars(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    skip_return: bool,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
    set_vars: &std::collections::HashMap<String, String>,
) -> Response {
    // TRACE is rejected during config lookup, which in nginx happens *before*
    // the rewrite phase — so a `return 200` in the location never runs and the
    // client sees 405. Handling it here (before the rewrite walk) reproduces
    // that ordering.
    if req.method == Method::Trace {
        return error_response(405, server.server_tokens);
    }
    let mut custom: std::collections::HashMap<String, String> = set_vars.clone();
    for (k, v) in captures {
        custom.insert(k.clone(), v.clone());
    }
    {
        let mut resp = if skip_return {
            route_content(req, path, query, loc, server, http).await
        } else {
            let root_str = loc.root.to_string_lossy().to_string();
            let vars = ServerVars {
                req,
                path,
                query,
                server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                server_port,
                peer_ip,
                peer_port,
                scheme: "http",
                document_root: &root_str,
                upstream_cache_status: "",
                custom: &custom,
                connection_requests: state.requests,
                connection_time: state.elapsed_secs(),
                sent: &[],
            };
            access_then_route(
                req,
                path,
                query,
                loc,
                server,
                http,
                false,
                peer_ip,
                peer_port,
                server_port,
                state,
                &mut custom,
            )
            .await
        };
        finalize_response(
            req,
            &mut resp,
            path,
            query,
            server,
            http,
            peer_ip,
            peer_port,
            server_port,
            captures,
            &mut custom,
            state,
            local_addr,
        )
        .await
    }
}

/// Expand a limit zone key (`$binary_remote_addr`, `$server_name`, ...).
fn limit_key(spec: &str, vars: &ServerVars<'_>) -> String {
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
        // `$binary_remote_addr` is the packed form; the textual address is an
        // equivalent map key for our purposes.
        match &rest[..n] {
            "binary_remote_addr" => out.push_str(vars.peer_ip),
            other => out.push_str(&vars.get(other)),
        }
        i += 1 + n;
    }
    out
}

/// Apply `limit_req` / `limit_conn`. Returns a response when the request must
/// be rejected; `limit_conn` slots are pushed into `guards` so they are held
/// until the response has been written.
async fn check_limits(
    loc: &LocCfg,
    http: &Http,
    vars: &ServerVars<'_>,
    guards: &mut Vec<crate::limit::ConnGuard>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> Option<Response> {
    for lr in &loc.limit_reqs {
        let Some(zone) = http.limit_req_zones.iter().find(|z| z.name == lr.zone) else {
            continue;
        };
        let key = limit_key(&zone.key, vars);
        match zone.state.account(&key, lr.burst, lr.nodelay, lr.delay) {
            None => {
                // nginx writes this once per configured `error_log` of the
                // location, at `limit_req_log_level`. Two `error_log`
                // directives pointing at the same file therefore produce two
                // identical lines (error_log.t checks exactly that).
                let msg = format!(
                    "limiting requests, excess: zone=\"{}\" key=\"{key}\"",
                    lr.zone
                );
                for spec in &loc.error_logs {
                    if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                        crate::log::log_to(&[sink], loc.limit_req_log_level, &msg);
                    }
                }
                if loc.error_logs.is_empty() {
                    crate::log::error_log(loc.limit_req_log_level.name(), &msg);
                }
                return Some(error_response(loc.limit_req_status, true));
            }
            Some(delay) if !delay.is_zero() => {
                // nginx holds the request for the computed delay, without
                // blocking its worker. Sleeping the thread here stalls every
                // other connection multiplexed on that runtime thread; with a
                // single worker it serialises the whole server.
                tokio::time::sleep(delay.min(std::time::Duration::from_secs(10))).await;
            }
            _ => {}
        }
    }

    for lc in &loc.limit_conns {
        let Some(zone) = http.limit_conn_zones.iter().find(|z| z.name == lc.zone) else {
            continue;
        };
        let key = limit_key(&zone.key, vars);
        match zone.state.acquire(&key, lc.limit, client_fd) {
            Some(guard) => guards.push(guard),
            None => {
                let msg = format!("limiting connections by zone \"{}\"", lc.zone);
                for spec in &loc.error_logs {
                    if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                        crate::log::log_to(&[sink], loc.limit_conn_log_level, &msg);
                    }
                }
                // The main-context log still sees it, as in nginx.
                if loc.error_logs.is_empty() {
                    crate::log::error_log(loc.limit_conn_log_level.name(), &msg);
                }
                return Some(error_response(loc.limit_conn_status, true));
            }
        }
    }

    None
}

/// Apply `error_page`, `add_header` and `gzip` to a response the content phase
/// produced (including ones from `return` / `rewrite`).
#[allow(clippy::too_many_arguments)]
async fn finalize_response(
    req: &Request,
    resp: &mut Response,
    path: &str,
    query: &str,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    _captures: &[(String, String)],
    custom: &mut std::collections::HashMap<String, String>,
    state: ConnState,
    local_addr: &str,
) -> Response {
    let mut cur_path = path.to_string();
    let mut cur_query = query.to_string();
    let mut cur_loc = server.locate(&cur_path);
    let mut depth = 0usize;
    let root_str = cur_loc.root.to_string_lossy().to_string();

    while depth < 10 && util::is_special_status(resp.status) && resp.status >= 300 {
        let Some(target) = cur_loc.error_pages.get(&resp.status).cloned() else {
            break;
        };
        // `error_page 404 /a.html` keeps the original status;
        // `error_page 404 =200 /a.html` forces 200; a bare `=`
        // (`error_page 404 = /a.html`, `... = @named`) adopts whatever status
        // the target produced.
        let (new_status, use_target_status, uri) = match target.strip_prefix('=') {
            Some(rest) => {
                let rest = rest.trim_start();
                match rest.split_once(char::is_whitespace) {
                    Some((first, tail)) => match first.parse::<u16>() {
                        Ok(code) => (Some(code), false, tail.trim().to_string()),
                        Err(_) => (None, true, rest.to_string()),
                    },
                    None => (None, true, rest.to_string()),
                }
            }
            None => (None, false, target.clone()),
        };
        let original_status = resp.status;
        // nginx keeps `r->uri` untouched when the error page target is a named
        // location, so remember the URI that failed.
        let uri_before = cur_path.clone();
        let (p, q) = match uri.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (uri.clone(), String::new()),
        };
        cur_path = p;
        cur_query = q;
        depth += 1;

        let expanded = {
            let vars = ServerVars {
                req,
                path: &cur_path,
                query: &cur_query,
                server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                server_port,
                peer_ip,
                peer_port,
                scheme: "http",
                document_root: &root_str,
                upstream_cache_status: "",
                custom: &custom,
                connection_requests: state.requests,
                connection_time: state.elapsed_secs(),
                sent: &[],
            };
            vars.expand(&cur_path)
        };

        // `error_page 302 http://example.com/` is an external redirect.
        if expanded.starts_with("http://") || expanded.starts_with("https://") {
            let mut location = expanded;
            if !cur_query.is_empty() {
                location.push(if location.contains('?') { '&' } else { '?' });
                location.push_str(&cur_query);
            }
            *resp = Response::empty(new_status.unwrap_or(302)).header("Location", location);
            break;
        }

        cur_path = expanded;
        if !cur_query.is_empty() {
            let vars = ServerVars {
                req,
                path: &cur_path,
                query: query,
                server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                server_port,
                peer_ip,
                peer_port,
                scheme: "http",
                document_root: &root_str,
                upstream_cache_status: "",
                custom: &custom,
                connection_requests: state.requests,
                connection_time: state.elapsed_secs(),
                sent: &[],
            };
            cur_query = vars.expand(&cur_query);
        }
        // `error_page 404 = @fallback` jumps to a named location. Named
        // locations take no part in prefix/regex matching: nginx just swaps the
        // location config and runs its content phase, leaving `r->uri` alone.
        if let Some(named) = server.locate_named(&cur_path) {
            cur_loc = named;
            cur_path = uri_before;
            let vars = ServerVars {
                req,
                path: &cur_path,
                query: &cur_query,
                server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                server_port,
                peer_ip,
                peer_port,
                scheme: "http",
                document_root: &root_str,
                upstream_cache_status: "",
                custom: &custom,
                connection_requests: state.requests,
                connection_time: state.elapsed_secs(),
                sent: &[],
            };
            let redirected = access_then_route(
                req,
                &cur_path,
                &cur_query,
                named,
                server,
                http,
                true,
                peer_ip,
                peer_port,
                server_port,
                state,
                custom,
            )
            .await;
            let redirected_status = redirected.status;
            *resp = redirected;
            resp.status = if use_target_status {
                redirected_status
            } else {
                match new_status {
                    Some(code) => code,
                    None if (300..400).contains(&redirected_status) => redirected_status,
                    None => original_status,
                }
            };
            continue;
        }
        cur_loc = server.locate(&cur_path);

        // The error page target runs the full rewrite phase too, so a
        // `rewrite ^ http://...` inside it produces the redirect.
        let redirected = match resolve_target(req, &cur_path, &cur_query, server, cur_loc, http) {
            Target::Done(r) => r,
            Target::Loc(p, q, l, _skip, _set_vars) => {
                cur_path = p;
                cur_query = q;
                let vars = ServerVars {
                    req,
                    path: &cur_path,
                    query: &cur_query,
                    server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                    server_port,
                    peer_ip,
                    peer_port,
                    scheme: "http",
                    document_root: &root_str,
                    upstream_cache_status: "",
                    custom,
                    connection_requests: state.requests,
                    connection_time: state.elapsed_secs(),
                    sent: &[],
                };
                access_then_route(
                    req,
                    &cur_path,
                    &cur_query,
                    l,
                    server,
                    http,
                    true,
                    peer_ip,
                    peer_port,
                    server_port,
                    state,
                    custom,
                )
                .await
            }
        };
        // A redirect generated while serving the error page (directory
        // auto-redirect, `rewrite ... permanent`, ...) keeps its own status;
        // otherwise the original error status is preserved. A bare `=` adopts
        // the target's status outright. An empty body here is normal — `return
        // 403;` has none and gets the error page generated after the loop.
        let redirected_status = redirected.status;
        *resp = redirected;
        resp.status = if use_target_status {
            redirected_status
        } else {
            match new_status {
                Some(code) => code,
                None if (300..400).contains(&redirected_status) => redirected_status,
                None => original_status,
            }
        };
    }

    if resp.status >= 400 && resp.body.is_empty() {
        *resp = error_response(resp.status, server.server_tokens);
    }

    let mut out = crate::gzip::maybe_compress(
        req,
        std::mem::replace(resp, Response::empty(200)),
        cur_loc,
        http,
    );

    apply_expires(&mut out.raw, cur_loc);

    if !cur_loc.headers.is_empty() || !cur_loc.trailers.is_empty() {
        // `$sent_http_*` sees the headers produced so far (nginx evaluates
        // add_header left to right, so earlier ones are visible).
        let existing = split_head(&out.raw);
        let vars = ServerVars {
            req,
            path: &cur_path,
            query: &cur_query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port,
            peer_ip,
            peer_port,
            scheme: "http",
            document_root: &root_str,
            upstream_cache_status: "",
            custom,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &existing,
        };
        apply_add_headers(&mut out.raw, &cur_loc.headers, out.status, &vars);
        if !cur_loc.trailers.is_empty() {
            let (expect, list) = eval_trailers(&cur_loc.trailers, out.status, &vars);
            out.expect_trailers = expect;
            out.trailers = list;
        }
    }

    out
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
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
    peer_port: u16,
    client_ip: &str,
    guards: &mut Vec<crate::limit::ConnGuard>,
) -> io::Result<Outcome> {
    // Measurement endpoint for `--features alloc-count`: reports the global
    // allocation counters so a request's heap cost can be read, not guessed.
    #[cfg(feature = "alloc-count")]
    if path == "/_alloc" {
        let a = crate::alloccnt::ALLOCS.load(std::sync::atomic::Ordering::Relaxed);
        let b = crate::alloccnt::BYTES.load(std::sync::atomic::Ordering::Relaxed);
        let p: Vec<String> = (0..3)
            .map(|i| {
                crate::alloccnt::PHASE[i]
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .to_string()
            })
            .collect();
        let body = format!("{a} {b} {}\n", p.join(" ")).into_bytes();
        let len = body.len() as u64;
        let mut resp = Response::bytes(200, "text/plain", body);
        let sent = if sent_headers_needed(server) {
            split_head(&resp.raw)
        } else {
            Vec::new()
        };
        let written = write_response(
            conn,
            resp,
            true,
            server.server_tokens,
            req.method == Method::Head,
        )
        .await?;
        return Ok(Outcome {
            status: 200,
            bytes: written,
            close: false,
            sent: sent,
        });
    }
    let head_only = req.method == Method::Head;
    let mut keepalive_allowed = keepalive_policy(req, loc, state);
    let ka_header = loc.keepalive_timeout.and_then(|(_, h)| h);

    // Rewrite/try_files may point at a different location; resolve it before
    // choosing a content handler so `/x -> /fallback` can reach a proxy.
    let (resolved_path, resolved_query, resolved_loc, skip_return, pre, set_vars) =
        match resolve_target(req, path, query, server, loc, http) {
            Target::Done(r) => (
                path.to_string(),
                query.to_string(),
                loc,
                false,
                Some(r),
                Default::default(),
            ),
            Target::Loc(p, q, l, skip, set_vars) => (p, q, l, skip, None, set_vars),
        };
    let (path, query, loc) = (
        resolved_path.as_str(),
        resolved_query.as_str(),
        resolved_loc,
    );

    // A response produced by `return`/`rewrite` still goes through error_page.
    if let Some(mut r) = pre {
        let mut custom: std::collections::HashMap<String, String> = set_vars.clone();
        for (k, v) in captures {
            custom.insert(k.clone(), v.clone());
        }
        let root = loc.root.to_string_lossy().to_string();
        let _ = root;
        let peer = conn.peer_ip_str();
        let resp = finalize_response(
            req,
            &mut r,
            path,
            query,
            server,
            http,
            &peer,
            peer_port,
            listen_port,
            captures,
            &mut custom,
            state,
            local_addr,
        )
        .await;
        let status = resp.status;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            return write_redirect(
                conn,
                req,
                resp,
                loc,
                listen_port,
                server.server_tokens,
                local_addr,
            )
            .await;
        }
        let sent = if sent_headers_needed(server) {
            split_head(&resp.raw)
        } else {
            Vec::new()
        };
        let bytes = write_response_ka(
            conn,
            resp,
            keepalive_allowed,
            server.server_tokens,
            head_only,
            ka_header,
        )
        .await?;
        return Ok(Outcome {
            status,
            bytes,
            close: !keepalive_allowed,
            sent,
        });
    }

    // ---- ACCESS phase, ahead of any upstream content handler -------------
    //
    // These protocols are dispatched before the generic route, so the ACCESS
    // phase has to be evaluated here for them; otherwise credentials and
    // `allow`/`deny` would only be enforced for static content.
    let mut set_vars = set_vars;
    let upstream_content = loc.grpc_pass.is_some()
        || loc.fastcgi_pass.is_some()
        || loc.uwsgi_pass.is_some()
        || loc.scgi_pass.is_some()
        || loc.proxy_pass.is_some();
    let args_override;
    let query = if upstream_content {
        let mut access_custom = set_vars.clone();
        for (k, v) in captures {
            access_custom.insert(k.clone(), v.clone());
        }
        let (denied, args) = access_guard(
            req,
            path,
            query,
            loc,
            server,
            http,
            &conn.peer_ip_str(),
            peer_port,
            listen_port,
            state,
            &mut access_custom,
        )
        .await;
        if let Some(mut d) = denied {
            let peer = conn.peer_ip_str();
            let resp = finalize_response(
                req,
                &mut d,
                path,
                query,
                server,
                http,
                &peer,
                peer_port,
                listen_port,
                captures,
                &mut access_custom,
                state,
                local_addr,
            )
            .await;
            let status = resp.status;
            let sent = if sent_headers_needed(server) {
                split_head(&resp.raw)
            } else {
                Vec::new()
            };
            let bytes = write_response_ka(
                conn,
                resp,
                keepalive_allowed,
                server.server_tokens,
                req.method == Method::Head,
                None,
            )
            .await?;
            return Ok(Outcome {
                status,
                bytes,
                close: !keepalive_allowed,
                sent,
            });
        }
        // The auth subrequest's `auth_request_set` values are ordinary
        // variables from here on, visible to `add_header` and to the upstream
        // request line.
        set_vars = access_custom;
        args_override = args;
        match &args_override {
            Some(a) => a.as_str(),
            None => query,
        }
    } else {
        query
    };

    // ---- gRPC ----
    if loc.grpc_pass.is_some() {
        let grpc_vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port: listen_port,
            peer_ip: client_ip,
            peer_port,
            scheme: "http",
            document_root: loc.root.to_str().unwrap_or(""),
            upstream_cache_status: "",
            custom: &set_vars,
            connection_requests: state.requests,
            connection_time: 0,
            sent: &[],
        };
        if let Some(resp) =
            crate::grpc::fetch(http, loc, req, path, query, client_ip, Some(&grpc_vars)).await
        {
            let mut resp = resp;
            let mut set_vars_mut = set_vars.clone();
            let resp = finalize_response(
                req,
                &mut resp,
                path,
                query,
                server,
                http,
                client_ip,
                peer_port,
                listen_port,
                captures,
                &mut set_vars_mut,
                state,
                local_addr,
            )
            .await;
            let status = resp.status;
            let sent = if sent_headers_needed(server) {
                split_head(&resp.raw)
            } else {
                Vec::new()
            };
            let bytes = write_response_ka(
                conn,
                resp,
                keepalive_allowed,
                server.server_tokens,
                req.method == Method::Head,
                None,
            )
            .await?;
            return Ok(Outcome {
                status,
                bytes,
                close: !keepalive_allowed,
                sent,
            });
        }
    }

    // ---- FastCGI ----
    if loc.fastcgi_pass.is_some() {
        if let Some(o) =
            crate::fastcgi::handle(conn, req, path, query, loc, server.server_tokens).await?
        {
            return Ok(o);
        }
    }

    // ---- uwsgi / scgi ----
    if loc.uwsgi_pass.is_some() {
        if let Some(o) =
            crate::uwsgi_scgi::handle_uwsgi(conn, req, path, query, loc, server.server_tokens)
                .await?
        {
            return Ok(o);
        }
    }
    if loc.scgi_pass.is_some() {
        if let Some(o) =
            crate::uwsgi_scgi::handle_scgi(conn, req, path, query, loc, server.server_tokens)
                .await?
        {
            return Ok(o);
        }
    }

    // ngx_http_limit_req / limit_conn run in the PREACCESS phase, before any
    // content handler (including the proxy).
    {
        let root = loc.root.to_string_lossy().to_string();
        let limit_vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port: listen_port,
            peer_ip: client_ip,
            peer_port,
            scheme: "http",
            document_root: &root,
            upstream_cache_status: "",
            custom: &set_vars,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &[],
        };
        if let Some(reject) = check_limits(loc, http, &limit_vars, guards, conn.raw_fd()).await {
            let status = reject.status;
            let sent = split_head(&reject.raw);
            let bytes = write_response(
                conn,
                reject,
                keepalive_allowed,
                server.server_tokens,
                head_only,
            )
            .await?;
            return Ok(Outcome {
                status,
                bytes,
                close: !keepalive_allowed,
                sent,
            });
        }
    }

    // `limit_req` delays run above, so a request can survive into a graceful
    // shutdown. nginx decides keepalive once the request is finished
    // (`ngx_http_set_keepalive`), so re-check after the delay; otherwise a
    // connection about to be closed would not carry `Connection: close`.
    keepalive_allowed = keepalive_allowed && keepalive_policy(req, loc, state);

    // `ssi on` has to see the entire body before anything is written, so a
    // proxied response is fetched whole and then run through the same filter
    // as a static one. nginx's filter chain reaches the same effect: the SSI
    // filter runs only after the upstream body is complete. Without this the
    // proxy branch wrote straight to the socket and SSI never ran.
    //
    // gzip needs the whole body for the same reason: nginx compresses proxied
    // responses as an output filter, and a streaming write cannot know the
    // compressed length before the head goes out.
    //
    // A location that also uses `proxy_cache` keeps the streaming path: the
    // cache decision table (Vary variants, revalidation, stale-while-revalidate,
    // lock takeover) lives there, and routing those requests through the
    // buffered fetcher would mean maintaining a second, weaker copy of it.
    // Cached replies are still compressed, because `serve_cached` runs the gzip
    // filter; only a cache *miss* on such a location goes out uncompressed.
    let wants_buffered =
        loc.ssi || (loc.gzip && crate::gzip::accepts_gzip(req) && loc.proxy_cache.is_none());
    let mut ssi_proxied: Option<Response> = None;
    if loc.proxy_pass.is_some() && wants_buffered && req.method != Method::Head {
        ssi_proxied = crate::proxy::fetch(req, path, query, loc, http, client_ip, &set_vars).await;
    }

    // ---- reverse proxy (streams to the socket, cannot be resolved first) ----
    if loc.proxy_pass.is_some() && ssi_proxied.is_none() {
        let proxy_root = loc.root.to_string_lossy().to_string();
        let proxy_vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port: listen_port,
            peer_ip: client_ip,
            peer_port,
            scheme: "http",
            document_root: &proxy_root,
            upstream_cache_status: "",
            custom: &set_vars,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &[],
        };
        match crate::proxy::handle(
            conn,
            req,
            path,
            query,
            loc,
            http,
            server.server_tokens,
            &proxy_vars,
        )
        .await?
        {
            Some(crate::proxy::Proxied::Written(o)) => return Ok(o),
            Some(crate::proxy::Proxied::Intercept { status, headers }) => {
                // `proxy_intercept_errors`: nothing has been written, so run the
                // normal error_page/headers pipeline for this status. The final
                // status stays the upstream one (nginx keeps `err_status`).
                let mut resp = error_response(status, false);
                let preserved = headers;
                let peer_ip = conn.peer_ip_str();
                let mut set_vars_owned = set_vars.clone();
                resp = finalize_response(
                    req,
                    &mut resp,
                    path,
                    query,
                    server,
                    http,
                    &peer_ip,
                    peer_port,
                    listen_port,
                    captures,
                    &mut set_vars_owned,
                    state,
                    local_addr,
                )
                .await;
                // `WWW-Authenticate` from upstream goes in front of the headers
                // the error page produced, matching the order nginx emits.
                if !preserved.is_empty() {
                    let mut raw = Vec::with_capacity(resp.raw.len() + 64);
                    for (k, v) in &preserved {
                        raw.extend_from_slice(k.as_bytes());
                        raw.extend_from_slice(b": ");
                        raw.extend_from_slice(v.as_bytes());
                        raw.extend_from_slice(b"\r\n");
                    }
                    raw.extend_from_slice(&resp.raw);
                    resp.raw = raw;
                }
                let status = resp.status;
                let sent = if sent_headers_needed(server) {
                    split_head(&resp.raw)
                } else {
                    Vec::new()
                };
                let bytes = write_response_ka(
                    conn,
                    resp,
                    keepalive_allowed,
                    server.server_tokens,
                    head_only,
                    ka_header,
                )
                .await?;
                return Ok(Outcome {
                    status,
                    bytes,
                    close: !keepalive_allowed,
                    sent,
                });
            }
            None => {}
        }
    }

    let peer_ip = conn.peer_ip_str();
    let resp = match ssi_proxied {
        Some(r) => r,
        None => {
            render_resolved_vars(
                req,
                path,
                query,
                loc,
                skip_return,
                server,
                http,
                &peer_ip,
                peer_port,
                listen_port,
                captures,
                state,
                local_addr,
                &set_vars,
            )
            .await
        }
    };
    // gzip is an output filter that runs after SSI, so a buffered proxied body
    // is compressed here. Already-compressed replies and non-gzip locations
    // fall straight through.
    let resp = crate::gzip::maybe_compress(req, resp, loc, http);
    // `ssi on` rewrites the body before it is written. HEAD has no body to
    // process, and nginx skips the filter for non-200 replies.
    let resp = if loc.ssi && resp.status == 200 && req.method != Method::Head {
        let root = loc.root.to_string_lossy().to_string();
        let vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port: listen_port,
            peer_ip: &peer_ip,
            peer_port,
            scheme: if req.tls.is_some() { "https" } else { "http" },
            document_root: &root,
            upstream_cache_status: "",
            custom: &set_vars,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &[],
        };
        apply_ssi(req, resp, server, http, &vars).await
    } else {
        resp
    };
    let status = resp.status;
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        return write_redirect(
            conn,
            req,
            resp,
            loc,
            listen_port,
            server.server_tokens,
            local_addr,
        )
        .await;
    }
    let sent = if sent_headers_needed(server) {
        split_head(&resp.raw)
    } else {
        Vec::new()
    };
    let bytes = write_response_ka(
        conn,
        resp,
        keepalive_allowed,
        server.server_tokens,
        head_only,
        ka_header,
    )
    .await?;
    Ok(Outcome {
        status,
        bytes,
        close: !keepalive_allowed,
        sent,
    })
}

/// nginx's keepalive decision for one request: `keepalive_requests`,
/// `keepalive_time`, `keepalive_timeout 0` and `keepalive_disable` all veto it.
fn keepalive_policy(req: &Request, loc: &LocCfg, state: ConnState) -> bool {
    if !req.keepalive {
        return false;
    }
    if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    // nginx answers TRACE with 405 and always closes the connection; other
    // disallowed methods (POST/PUT to static content) keep it alive.
    if req.method == Method::Trace {
        return false;
    }
    if let Some((timeout, _)) = loc.keepalive_timeout {
        if timeout.is_zero() {
            return false;
        }
    }
    if let Some(n) = loc.keepalive_requests {
        if state.requests >= n {
            return false;
        }
    }
    if let Some(t) = loc.keepalive_time {
        if state.started.elapsed() >= t {
            return false;
        }
    }
    let ua = req.headers.get("user-agent").unwrap_or("");
    match loc.keepalive_disable {
        crate::config::KeepaliveDisable::None => {}
        crate::config::KeepaliveDisable::Msie6 => {
            // nginx's user-agent parser flags MSIE 6 and older (it looks for
            // "MSIE " anywhere) and then refuses keepalive for non-GET.
            if req.method != Method::Get {
                if let Some(idx) = ua.to_ascii_lowercase().find("msie ") {
                    let rest = &ua[idx + 5..];
                    let major: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(v) = major.parse::<u32>() {
                        if v <= 6 {
                            return false;
                        }
                    }
                }
            }
        }
        crate::config::KeepaliveDisable::Safari => {
            if ua.contains("Safari/") && ua.contains("Mac OS X") {
                return false;
            }
        }
    }
    true
}

/// Build the `Location` for a redirect, honouring `absolute_redirect`,
/// `server_name_in_redirect` and `port_in_redirect` (nginx's
/// `ngx_http_header_filter` logic).
fn redirect_location(
    req: &Request,
    loc: &LocCfg,
    raw_location: &str,
    listen_port: u16,
    local_addr: &str,
) -> String {
    if !raw_location.starts_with('/') || !loc.absolute_redirect {
        return raw_location.to_string();
    }
    let host = if loc.server_name_in_redirect && !loc.server_name.is_empty() {
        loc.server_name.clone()
    } else {
        let h = req.host.as_ref().map(|h| h.as_str()).unwrap_or("");
        if h.is_empty() || !crate::http::request::host_is_usable(h) {
            // nginx falls back to the address of the listening socket.
            local_addr.to_string()
        } else {
            h.to_string()
        }
    };
    let mut out = String::with_capacity(host.len() + raw_location.len() + 16);
    out.push_str("http://");
    out.push_str(&host);
    let host_has_port = host
        .rsplit_once(':')
        .map(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false);
    if loc.port_in_redirect && !host_has_port && listen_port != 80 {
        out.push(':');
        out.push_str(&listen_port.to_string());
    }
    out.push_str(raw_location);
    out
}

async fn write_redirect(
    conn: &mut Conn,
    req: &Request,
    resp: Response,
    loc: &LocCfg,
    listen_port: u16,
    tokens: bool,
    local_addr: &str,
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
    let absolute = redirect_location(req, loc, &location, listen_port, local_addr);

    let body = match body {
        Body::Bytes(b) if !b.is_empty() => b,
        _ => error_body(status, tokens),
    };

    let mut out_raw = Vec::with_capacity(raw.len() + 160);
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    if !text.contains("content-type:") {
        out_raw.extend_from_slice(b"Content-Type: text/html\r\n");
    }
    if !text.contains("content-length:") {
        out_raw.extend_from_slice(b"Content-Length: ");
        out_raw.extend_from_slice(body.len().to_string().as_bytes());
        out_raw.extend_from_slice(b"\r\n");
    }
    for line in String::from_utf8_lossy(&raw).split("\r\n") {
        if line.is_empty() || line.to_ascii_lowercase().starts_with("location:") {
            continue;
        }
        out_raw.extend_from_slice(line.as_bytes());
        out_raw.extend_from_slice(b"\r\n");
    }
    out_raw.extend_from_slice(b"Location: ");
    out_raw.extend_from_slice(absolute.as_bytes());
    out_raw.extend_from_slice(b"\r\n");
    let _ = explicit_len;

    let resp = Response {
        status,
        headers: Vec::new(),
        raw: out_raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,
        body: Body::Bytes(body),
    };
    let bytes = write_response(
        conn,
        resp,
        req.keepalive,
        tokens,
        req.method == Method::Head,
    )
    .await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
        sent: Vec::new(),
    })
}

/// What a `try_files` chain decided, mirroring `ngx_http_try_files_handler`.
enum TryFilesAction {
    /// A candidate matched: serve this URI using the current location's
    /// root/alias (nginx sets `r->uri` and returns NGX_DECLINED).
    Serve(String),
    /// The last argument is a URI: internal redirect (new location search).
    Redirect(String),
    /// The last argument is `=code`.
    Status(u16),
}

/// Resolve `try_files` for one request. `None` means "no directive here".
fn try_files_action(req: &Request, path: &str, loc: &LocCfg) -> Option<TryFilesAction> {
    let n = loc.try_files.len();
    for (i, cand) in loc.try_files.iter().enumerate() {
        let last = i + 1 == n;

        // The last argument is never tested on disk: `=code` or a URI.
        if last {
            if let Some(code) = cand.strip_prefix('=') {
                return code.parse::<u16>().ok().map(TryFilesAction::Status);
            }
            let expanded = cand
                .replace("$uri", path)
                .replace("$request_uri", &req.raw_target)
                .replace("$args", "");
            return Some(TryFilesAction::Redirect(expanded));
        }

        // nginx strips a trailing `/` and remembers that a directory is wanted.
        let (name, want_dir) = match cand.strip_suffix('/') {
            Some(stripped) => (stripped, true),
            None => (cand.as_str(), false),
        };
        let uri = name
            .replace("$uri", path)
            .replace("$request_uri", &req.raw_target)
            .replace("$args", "");
        if uri.is_empty() {
            continue;
        }
        let uri = if uri.starts_with('/') {
            uri
        } else {
            format!("/{uri}")
        };

        let fs_path = static_file::map_path(&uri, loc);
        let meta = std::fs::metadata(&fs_path).ok();
        match (meta, want_dir) {
            (Some(m), true) if m.is_dir() => return Some(TryFilesAction::Serve(uri)),
            (Some(m), false) if m.is_file() => return Some(TryFilesAction::Serve(uri)),
            _ => continue,
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
        sent: Vec::new(),
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
        trailers: Vec::new(),
        expect_trailers: false,
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
    write_response_ka(conn, resp, keepalive, tokens, head_only, None).await
}

pub async fn write_response_ka(
    conn: &mut Conn,
    resp: Response,
    keepalive: bool,
    tokens: bool,
    head_only: bool,
    keepalive_header: Option<u32>,
) -> io::Result<u64> {
    let Response {
        status,
        headers,
        raw,
        explicit_len,
        no_error_page: _,
        trailers,
        expect_trailers,
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

    // `add_trailer` forces chunked: the length is no longer the message
    // delimiter, so a Content-Length must not be emitted.
    let chunked = expect_trailers && !matches!(status, 204 | 304);
    let has_cl = !chunked
        && (explicit_len
            || headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length")));
    if chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    if !has_cl && !chunked && !matches!(status, 204 | 304) {
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
    // nginx force-closes after certain error statuses so clients that wait for
    // EOF (including its own test suite) are not left hanging.
    let keepalive = keepalive && !util::force_close(status);
    out.extend_from_slice(b"Connection: ");
    out.extend_from_slice(if keepalive { b"keep-alive" } else { b"close" });
    out.extend_from_slice(b"\r\n");
    // nginx sends `Keep-Alive: timeout=N` when the second keepalive_timeout
    // argument is set and the connection is being kept alive.
    if keepalive {
        if let Some(secs) = keepalive_header {
            out.extend_from_slice(b"Keep-Alive: timeout=");
            out.extend_from_slice(secs.to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");

    if head_only {
        let r = conn.write_all(&out).await;
        conn.out = out;
        return r.map(|_| 0);
    }

    let result = match body {
        Body::Empty => {
            if chunked {
                out.extend_from_slice(b"0\r\n");
                push_trailers(&mut out, &trailers);
            }
            conn.write_all(&out).await.map(|_| 0)
        }
        Body::Bytes(b) => {
            if chunked {
                if !b.is_empty() {
                    out.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
                    out.extend_from_slice(&b);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n");
                push_trailers(&mut out, &trailers);
                conn.write_all(&out).await.map(|_| b.len() as u64)
            } else {
                out.extend_from_slice(&b);
                conn.write_all(&out).await.map(|_| b.len() as u64)
            }
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

/// Bridge between the SSI renderer and the request pipeline.
///
/// `#include virtual` needs a subrequest, which is async, but the renderer is
/// synchronous. So rendering runs repeatedly: any include that is not cached
/// yet is recorded and returns `None`, the driver fetches it, and the body is
/// re-rendered. Each pass adds at least one URI, so it converges, and the loop
/// is bounded in case of a self-including file.
struct SsiHost<'a> {
    vars: &'a ServerVars<'a>,
    include_cache: std::collections::HashMap<String, Option<Vec<u8>>>,
    wanted: Vec<(String, bool)>,
    /// Seconds since the epoch, for `$date_gmt` / `$date_local`.
    now: i64,
}

impl crate::ssi::Host for SsiHost<'_> {
    fn var(&self, name: &str, ctx: &crate::ssi::Ctx) -> Option<String> {
        // `#set` variables shadow everything else.
        if let Some(v) = ctx.vars.get(name) {
            return Some(v.clone());
        }
        match name {
            "date_gmt" => Some(crate::util::strftime_gmt(self.now, &ctx.timefmt)),
            "date_local" => Some(crate::util::strftime_gmt(self.now, &ctx.timefmt)),
            _ => {
                // `$arg_x` is present-but-empty for `?x=`, which renders as ""
                // rather than "(none)". Presence has to be tested against the
                // query itself because the rendered value cannot tell them apart.
                if let Some(want) = name.strip_prefix("arg_") {
                    let present = self
                        .vars
                        .query
                        .split('&')
                        .filter_map(|pair| pair.split_once('='))
                        .any(|(k, _)| k.eq_ignore_ascii_case(want));
                    if present {
                        return Some(self.vars.get(name));
                    }
                }
                let v = self.vars.get(name);
                if v.is_empty() {
                    None
                } else {
                    Some(v)
                }
            }
        }
    }

    fn include(&mut self, uri: &str, has_stub: bool) -> Option<Vec<u8>> {
        match self.include_cache.get(uri) {
            Some(v) => v.clone(),
            None => {
                if !self.wanted.iter().any(|(w, _)| w == uri) {
                    self.wanted.push((uri.to_string(), has_stub));
                } else if let Some(slot) = self.wanted.iter_mut().find(|(w, _)| w == uri) {
                    slot.1 = has_stub;
                }
                None
            }
        }
    }
}

thread_local! {
    /// Nesting depth of SSI subrequests, so `#include` cycles terminate.
    static SSI_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Run the SSI filter over a response body, resolving includes through the
/// normal location pipeline.
/// Boxed so SSI subrequests can recurse (an `#include` may target a document
/// that is itself filtered).
fn apply_ssi<'a>(
    req: &'a Request,
    resp: Response,
    server: &'a Server,
    http: &'a Http,
    vars: &'a ServerVars<'a>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'a>> {
    Box::pin(apply_ssi_inner(req, resp, server, http, vars))
}

async fn apply_ssi_inner(
    req: &Request,
    mut resp: Response,
    server: &Server,
    http: &Http,
    vars: &ServerVars<'_>,
) -> Response {
    let body = match std::mem::replace(&mut resp.body, Body::Empty) {
        Body::Empty => return resp,
        Body::Bytes(b) => b,
        Body::File { file, offset, len } => {
            use std::os::unix::fs::FileExt;
            let mut buf = vec![0u8; len as usize];
            let mut read = 0usize;
            while read < buf.len() {
                match file.read_at(&mut buf[read..], offset + read as u64) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            buf.truncate(read);
            buf
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut host = SsiHost {
        vars,
        include_cache: std::collections::HashMap::new(),
        wanted: Vec::new(),
        now,
    };

    let mut rendered = crate::ssi::render(&body, &mut host);

    // Resolve includes pass by pass. Bounded so a self-including document
    // cannot spin forever (nginx errors out instead; the bound keeps the
    // output deterministic).
    for _ in 0..8 {
        if host.wanted.is_empty() {
            break;
        }
        let batch = std::mem::take(&mut host.wanted);
        for (uri, has_stub) in batch {
            if host.include_cache.contains_key(&uri) {
                continue;
            }
            let (ipath, iquery) = crate::ssi::split_include_uri(&uri);
            let iloc = server.locate(&ipath);
            let sub = resolve_response(
                req,
                &ipath,
                &iquery,
                server,
                iloc,
                http,
                &vars.peer_ip.to_string(),
                vars.server_port,
            )
            .await;
            let mut sub = sub;
            // The included document is itself filtered: nginx runs the same
            // SSI filter for the subrequest, so a nested `#include` or `#echo`
            // inside it is expanded too. Depth is bounded to stop a document
            // from including itself forever.
            if iloc.ssi && sub.status == 200 && SSI_DEPTH.with(|d| d.get()) < 8 {
                let iroot = iloc.root.to_string_lossy().to_string();
                let ivars = ServerVars {
                    req,
                    path: &ipath,
                    query: &iquery,
                    server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
                    server_port: vars.server_port,
                    peer_ip: vars.peer_ip,
                    peer_port: vars.peer_port,
                    scheme: vars.scheme,
                    document_root: &iroot,
                    upstream_cache_status: "",
                    custom: vars.custom,
                    connection_requests: vars.connection_requests,
                    connection_time: vars.connection_time,
                    sent: &[],
                };
                SSI_DEPTH.with(|d| d.set(d.get() + 1));
                sub = apply_ssi(req, sub, server, http, &ivars).await;
                SSI_DEPTH.with(|d| d.set(d.get() - 1));
            }
            // A failed include is inlined verbatim -- nginx emits the
            // subrequest's own output, so a 404 shows up as its error page body
            // and the main response stays 200. Verified against nginx 1.28.
            // With a `stub="name"`, though, the stub replaces the output on
            // failure, so the include has to keep reporting failure and let the
            // renderer emit the stub instead.
            let value = if sub.status >= 400 && has_stub {
                None
            } else {
                Some(body_bytes(sub.body).await.unwrap_or_default())
            };
            host.include_cache.insert(uri, value);
        }
        rendered = crate::ssi::render(&body, &mut host);
    }

    resp.body = Body::Bytes(rendered);
    // The length changed, so any pre-rendered Content-Length is now wrong.
    strip_content_length(&mut resp);
    // nginx's SSI filter clears these two: the body is no longer the file it
    // came from, so a validator would be a lie.
    strip_header(&mut resp, "Last-Modified");
    strip_header(&mut resp, "Accept-Ranges");
    resp
}

/// Remove a pre-rendered header line (case-insensitive) from the raw block.
fn strip_header(resp: &mut Response, name: &str) {
    let raw = std::mem::take(&mut resp.raw);
    let mut out = Vec::with_capacity(raw.len());
    let mut start = 0usize;
    while start < raw.len() {
        let end = match memchr::memchr(b'\n', &raw[start..]) {
            Some(p) => start + p + 1,
            None => raw.len(),
        };
        let line = &raw[start..end];
        let hit = line.len() > name.len()
            && line[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            && line[name.len()] == b':';
        if !hit {
            out.extend_from_slice(line);
        }
        start = end;
    }
    resp.raw = out;
    resp.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
}

/// Remove a pre-rendered `Content-Length:` line from a raw header block.
fn strip_content_length(resp: &mut Response) {
    if !resp.explicit_len {
        return;
    }
    let raw = std::mem::take(&mut resp.raw);
    let mut out = Vec::with_capacity(raw.len());
    let mut start = 0usize;
    while start < raw.len() {
        let end = match memchr::memchr(b'\n', &raw[start..]) {
            Some(p) => start + p + 1,
            None => raw.len(),
        };
        let line = &raw[start..end];
        let is_cl = line.len() > 15 && line[..15].eq_ignore_ascii_case(b"Content-Length:");
        if !is_cl {
            out.extend_from_slice(line);
        }
        start = end;
    }
    resp.raw = out;
    resp.explicit_len = false;
}

/// Append trailer lines plus the terminating chunk.
fn push_trailers(out: &mut Vec<u8>, trailers: &[(String, String)]) {
    for (k, v) in trailers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
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
    // nginx force-closes after certain error statuses so clients that wait for
    // EOF (including its own test suite) are not left hanging.
    let keepalive = keepalive && !util::force_close(status);
    out.extend_from_slice(b"Connection: ");
    out.extend_from_slice(if keepalive { b"keep-alive" } else { b"close" });
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"\r\n");
    let r = conn.write_all(&out).await;
    out.clear();
    conn.out = out;
    r
}

/// Same as [`select_server`] but also returns the named captures of a matching
/// `server_name ~regex`, which nginx exposes as `$name` variables.
pub fn select_server_ex<'a>(
    http: &'a Http,
    servers: &[usize],
    default_server: usize,
    host: Option<&str>,
) -> (&'a Server, Vec<(String, String)>) {
    let Some(raw_host) = host else {
        return (
            select_server(http, servers, default_server, None),
            Vec::new(),
        );
    };
    let lowered = raw_host.to_ascii_lowercase();
    let host = strip_host_port(&lowered);

    let server = select_server(http, servers, default_server, Some(raw_host));

    // Recover named captures when the winner was chosen by regex.
    let mut caps = Vec::new();
    let chosen = server.idx;
    let mut regex_winner = false;
    for &idx in servers {
        if idx != chosen {
            continue;
        }
        let srv = http.server(idx);
        for (re, src) in &srv.regex_names_src {
            if let Some(c) = re.captures(host) {
                if !srv.names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
                    regex_winner = true;
                }
                for name in re.capture_names().flatten() {
                    if let Some(m) = c.name(name) {
                        caps.push((name.to_string(), m.as_str().to_string()));
                    }
                }
                let _ = src;
                break;
            }
        }
        break;
    }
    if !regex_winner {
        caps.clear();
    }
    (server, caps)
}

/// nginx's server_name lookup order (ngx_http_core_find_server):
/// 1. exact name
/// 2. longest wildcard starting with `*`, then the longest ending with `*`
/// 3. `.example.com` also matches the bare `example.com`
/// 4. first matching regex, in configuration order
/// 5. the default server
pub fn select_server<'a>(
    http: &'a Http,
    servers: &[usize],
    default_server: usize,
    host: Option<&str>,
) -> &'a Server {
    let Some(raw_host) = host else {
        // A request without a Host header (legal in HTTP/1.0) has an empty
        // server name, which `server_name ""` matches — nginx does the same.
        for &idx in servers {
            let s = http.server(idx);
            if s.names.iter().any(|n| n.is_empty()) {
                return s;
            }
        }
        return http.server(default_server);
    };
    let lowered = raw_host.to_ascii_lowercase();
    let host = strip_host_port(&lowered);

    // 1. exact
    for &idx in servers {
        let s = http.server(idx);
        if s.names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
            return s;
        }
    }

    // 2. wildcards: the longest matching pattern wins
    let mut best: Option<(usize, &'a Server)> = None;
    for &idx in servers {
        let s = http.server(idx);
        for n in &s.names {
            let n_lower = n.to_ascii_lowercase();
            if let Some(suffix) = n_lower.strip_prefix("*.") {
                // `*.example.com` matches `x.example.com` (never `example.com`)
                if host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                {
                    if best.map_or(true, |(len, _)| suffix.len() > len) {
                        best = Some((suffix.len(), s));
                    }
                }
            } else if let Some(rest) = n_lower.strip_prefix('.') {
                // `.example.com` is shorthand for `example.com` + `*.example.com`
                if host.ends_with(rest)
                    && (host.len() == rest.len()
                        || host.as_bytes()[host.len() - rest.len() - 1] == b'.')
                {
                    if best.map_or(true, |(len, _)| rest.len() > len) {
                        best = Some((rest.len(), s));
                    }
                }
            } else if let Some(prefix) = n_lower.strip_suffix(".*") {
                // `www.example.*` matches `www.example.com`
                if host.len() > prefix.len()
                    && host.starts_with(prefix)
                    && host.as_bytes()[prefix.len()] == b'.'
                {
                    if best.map_or(true, |(len, _)| prefix.len() > len) {
                        best = Some((prefix.len(), s));
                    }
                }
            }
        }
    }
    if let Some((_, s)) = best {
        return s;
    }

    // 3. `.example.com` also matches `example.com` itself
    for &idx in servers {
        let s = http.server(idx);
        for n in &s.names {
            if let Some(rest) = n.strip_prefix('.') {
                if host.eq_ignore_ascii_case(rest) {
                    return s;
                }
            }
        }
    }

    // 4. regex, in configuration order
    for &idx in servers {
        let s = http.server(idx);
        for re in &s.regex_names {
            if re.is_match(host) {
                return s;
            }
        }
    }

    // 5. default
    http.server(default_server)
}

/// Drop `:port` (and the brackets of an IPv6 literal) from a host value.
fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(i) => &host[..=i],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
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
    sent: &[(String, String)],
    loc_logs: Option<&[crate::config::AccessLog]>,
) {
    // nginx: a location `access_log` replaces the server's, and `off` clears it.
    let logs: &[crate::config::AccessLog] = match loc_logs {
        Some(l) => l,
        None => &server.access_logs,
    };
    if logs.is_empty() {
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

    // `$sent_http_*` values, resolved up front so the slice can borrow them.
    // Repeated headers are comma-joined, like nginx's `$sent_http_*`.
    let mut sent_map: Vec<(String, String)> = Vec::new();
    for (k, v) in sent {
        let name = format!("sent_http_{}", k.to_ascii_lowercase().replace('-', "_"));
        match sent_map.iter_mut().find(|(n, _)| *n == name) {
            Some((_, existing)) => {
                existing.push_str(", ");
                existing.push_str(v);
            }
            None => sent_map.push((name, v.clone())),
        }
    }
    let sent_refs: Vec<(&str, &str)> = sent_map
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Upstream attempt timings; nginx prints a comma-separated list, `-` for a
    // value an attempt never reached.
    let t_connect = crate::timing::variable("upstream_connect_time").unwrap_or_default();
    let t_header = crate::timing::variable("upstream_header_time").unwrap_or_default();
    let t_response = crate::timing::variable("upstream_response_time").unwrap_or_default();
    let scheme = if req.tls.is_some() { "https" } else { "http" };

    let mut vars: Vec<(&str, &str)> = vec![
        ("remote_addr", &peer),
        ("remote_port", "0"),
        ("remote_user", "-"),
        ("time_local", ""),
        ("request", &request_line),
        ("request_uri", &req.raw_target),
        ("request_method", req.method.as_str()),
        ("document_uri", path),
        ("uri", path),
        ("args", query),
        ("status", &status_s),
        ("body_bytes_sent", &bytes_s),
        ("http_referer", referer),
        ("http_user_agent", ua),
        ("host", host),
        ("server_name", server_name),
        ("server_port", &port_s),
        ("scheme", scheme),
        ("upstream_connect_time", &t_connect),
        ("upstream_header_time", &t_header),
        ("upstream_response_time", &t_response),
    ];
    vars.extend(sent_refs);

    let vars = &vars[..];

    for log in logs {
        let line = expand_log(&log.format, vars, now);
        ctx.logger.access(&log.path, line);
    }
}

/// nginx's built-in `combined` format, used whenever `access_log` names no
/// format. Without it the literal word `combined` was written to the log.
pub const COMBINED: &str = "$remote_addr - $remote_user [$time_local] \"$request\" \
$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

pub(crate) fn expand_log(fmt: &str, vars: &[(&str, &str)], now: i64) -> String {
    let fmt = if fmt == "combined" { COMBINED } else { fmt };
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
            // nginx logs "-" for a variable it cannot resolve.
            let rest = &fmt[i + 1..];
            let n = rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            if n > 0 {
                out.push('-');
                i += 1 + n;
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
    fn rate_parsing() {
        assert_eq!(parse_rate("40k"), 40960);
        assert_eq!(parse_rate("1m"), 1048576);
        assert_eq!(parse_rate("512"), 512);
        assert_eq!(parse_rate(""), 0);
        assert_eq!(parse_rate("nonsense"), 0);
    }

    #[test]
    fn log_expansion() {
        let vars = [("status", "200"), ("request_uri", "/x")];
        assert_eq!(expand_log("[$status] $request_uri", &vars, 0), "[200] /x");
    }
}
