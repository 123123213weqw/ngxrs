//! HTTP/1.1 request handling: routing, responses, access logging.

pub mod request;
pub mod small;
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

/// Spill a request body to `client_body_temp_path`, returning the file name.
///
/// nginx buffers a body in memory up to `client_body_buffer_size` and writes it
/// to a temp file beyond that, or always under `client_body_in_file_only`. Once
/// it is on disk `$request_body` renders empty and `$request_body_file` carries
/// the path.
/// The error `take_body`/`take_chunked_body` report when the limit is exceeded,
/// so a caller can answer 413 rather than 400.
pub fn body_too_large() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "body too large")
}

pub fn write_body_file(http: &Http, body: &[u8]) -> Option<std::path::PathBuf> {
    use std::io::Write;
    let dir = &http.client_body_temp_path;
    std::fs::create_dir_all(dir).ok()?;
    let n = NEXT_BODY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("{}{:010}", std::process::id(), n));
    let mut f = std::fs::File::create(&path).ok()?;
    f.write_all(body).ok()?;
    f.flush().ok()?;
    Some(path)
}

static NEXT_BODY_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Does any `add_header` value reference `$request_body` (or its file)?
pub fn references_body_var(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(_, v)| v.contains("$request_body"))
}

/// Does this location want the body on disk?
///
/// `client_body_in_file_only` forces it; otherwise the body spills once it is
/// larger than `client_body_buffer_size`.
pub fn body_needs_file(loc: &LocCfg, len: usize) -> bool {
    loc.client_body_in_file_only.is_some()
        || (len > 0 && len as u64 > loc.client_body_buffer_size)
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
    /// `add_header` / `add_trailer` have already been applied to `raw`.
    ///
    /// The socket-free path (HTTP/2, HTTP/3, SSI, auth subrequests) renders the
    /// upstream response inside the proxy module, where `$upstream_*` is in
    /// scope; `finalize_response` must then not apply the location's headers a
    /// second time. On HTTP/1.1 the proxy streams straight to the client and
    /// this stays `false`.
    pub headers_finalized: bool,
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

            headers_finalized: false,
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

            headers_finalized: false,
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

            headers_finalized: false,
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
/// Set `NGXRS_SKIP_AFTER_PARSE=1` to answer right after parsing (measurement).
static SKIP_AFTER_PARSE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Graduated measurement stops: each value answers as soon as that stage has
/// completed, so the cost of one stage is the difference between neighbours.
/// 1 = after parsing, 2 = after URL normalisation, 3 = after location match.
static STOP_STAGE: std::sync::OnceLock<u8> = std::sync::OnceLock::new();

fn stop_stage() -> u8 {
    *STOP_STAGE.get_or_init(|| {
        std::env::var("NGXRS_STOP_STAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    })
}

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
    let serial = crate::stats::accepted();
    crate::timing::scope(
        crate::timing::new_state(),
        crate::stats::scope_conn_serial(serial, handle_conn_inner(conn, cfg, group_idx, ctx)),
    )
    .await
}

async fn handle_conn_inner(mut conn: Conn, cfg: Arc<Config>, group_idx: usize, ctx: &Ctx) {
    let _active = ActiveGuard::enter();
    let conn_serial = crate::stats::conn_serial();
    // `writing` must fall back to "waiting" when the connection goes idle or
    // closes, so the guard clears it on every exit path.
    struct StatGuard;
    impl Drop for StatGuard {
        fn drop(&mut self) {
            crate::stats::closed();
        }
    }
    let _stats = StatGuard;
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
    // Likewise one shutdown registration per *connection*. tokio's `Notify`
    // keeps its waiter list behind a mutex, so building a `Notified` inside the
    // request loop made every request contend on it across all workers: measured
    // at 2.20x nginx's CPU per request with 64 workers against 1.14x with one.
    let mut shutdown_wait = Box::pin(shutdown_notify().notified());
    // Peer and local addresses never change over a connection; rendering them
    // per request cost two allocations each time.
    let client_ip_owned = conn.peer_ip_str();
    let local_ip_owned = conn
        .local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // `listen ... proxy_protocol`: the header sits in front of the first
    // request, so it is consumed once -- before the loop, so the request
    // timeout does not apply to it and the parser never sees it.
    if group.proxy_protocol && conn.proxy_protocol.is_none() {
        if let Err(e) = conn.read_proxy_protocol().await {
            crate::log::error_log("error", &format!("PROXY protocol: {e}"));
            let _ = send_error(&mut conn, 400, first_server.server_tokens, served == 0, false).await;
            return;
        }
    }

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
        let prof_parse = crate::prof::start();
        // `$pipe`: bytes for this request were already in the buffer while the
        // previous one was still being handled.
        let pipelined = !conn.buffered().is_empty() && served > 0;
        let read = if idle_shutdown {
            Err(())
        } else if NO_IDLE_TIMER.with(|v| *v) {
            tokio::select! {
                _ = &mut shutdown_wait, if conn.buffered().is_empty() => Err(()),
                r = conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES) => Ok(r),
            }
        } else {
            idle.as_mut()
                .reset(tokio::time::Instant::now() + read_timeout);
            tokio::select! {
                _ = idle.as_mut() => Err(()),
                _ = &mut shutdown_wait, if conn.buffered().is_empty() => Err(()),
                r = conn.read_request(MAX_REQUEST_LINE, MAX_HEADER_BYTES) => Ok(r),
            }
        };

        crate::prof::record(0, prof_parse);
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
                    proxy_protocol: None,
                    request_id: crate::util::new_request_id(),
                    version_minor: 0,
                    headers: crate::http::request::Headers::default(),
                    body_len: 0,
                    buffered_body: None,
                    request_body_file: None,
                    chunked: false,
                    keepalive: false,
                    host: None,
                    expect_continue: false,
                    // The TLS facts belong to the connection, not the request:
                    // nginx fills `$ssl_client_verify` at handshake time, so it
                    // is available even for a request the parser rejects. The
                    // per-server verdict is recomputed here against the default
                    // server, which is the one nginx uses on this path.
                    tls: conn.tls_info().map(|mut info| {
                        if default_server.ssl_verify_client != 0 {
                            if let Some(chain) = conn.peer_chain() {
                                if !chain.is_empty() {
                                    let mut bundles: Vec<&std::path::Path> = Vec::new();
                                    if let Some(p) = default_server.ssl_client_certificate.as_deref()
                                    {
                                        bundles.push(p);
                                    }
                                    if let Some(p) =
                                        default_server.ssl_trusted_certificate.as_deref()
                                    {
                                        bundles.push(p);
                                    }
                                    info.client_verify =
                                        match crate::tls::verify_client_chain_multi(bundles, &chain) {
                                            Ok(()) => "SUCCESS".to_string(),
                                            Err(reason) => format!("FAILED:{reason}"),
                                        };
                                }
                            }
                        }
                        std::sync::Arc::new(info)
                    }),
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
                r.proxy_protocol = conn.proxy_protocol.clone();
                r
            }
        };
        served += 1;

        // Measurement only: `NGXRS_SKIP_AFTER_PARSE=1` answers immediately after
        // the request head has been parsed, with the same status and body length
        // as `location /ret { return 200 "hello"; }`. The difference against a
        // real `/ret` is therefore the cost of routing, filtering and rendering,
        // and the difference against a bare tokio server is our parser and
        // connection loop.
        if stop_stage() == 1
            || *SKIP_AFTER_PARSE
                .get_or_init(|| std::env::var_os("NGXRS_SKIP_AFTER_PARSE").is_some())
        {
            let resp = Response::bytes(200, "text/plain", b"hello".to_vec());
            let _ = write_response_ka(&mut conn, resp, true, true, false, None).await;
            continue;
        }

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
                        // nginx adds both bundles to the verify store:
                        // `ssl_client_certificate` also defines the CA names
                        // sent in the CertificateRequest, while
                        // `ssl_trusted_certificate` only contributes trust
                        // anchors (`ngx_ssl_trusted_certificate`). A config that
                        // sets just the latter must still verify.
                        let mut bundles: Vec<&std::path::Path> = Vec::new();
                        if let Some(p) = srv.ssl_client_certificate.as_deref() {
                            bundles.push(p);
                        }
                        if let Some(p) = srv.ssl_trusted_certificate.as_deref() {
                            bundles.push(p);
                        }
                        match crate::tls::verify_client_chain_multi(bundles, c) {
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

        // The header is parsed; the connection is producing a response now.
        conn.set_writing(true);
        // A keepalive connection serves many requests from the same task.
        crate::timing::reset();
        let (path, query) = match util::parse_target(&req.raw_target) {
            Ok(v) => v,
            Err(_) => {
                let tokens = http.server(group.default_server).server_tokens;
                let _ = send_error(&mut conn, 400, tokens, false, false).await;
                // nginx still writes an access-log line, with `$uri` empty.
                let srv = http.server(group.default_server);
                let (log_peer_ip, log_peer_port) = match &conn.proxy_protocol {
                    Some(p) if !p.src_addr.is_empty() => {
                        (p.src_addr.clone(), p.src_port.to_string())
                    }
                    _ => (conn.peer_ip_str(), conn.peer.port().to_string()),
                };
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
                    0,
                    0,
                    false,
                    crate::config::OpenFileCache::default(),
                    (&log_peer_ip, &log_peer_port),
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
        if stop_stage() == 2 {
            let resp = Response::bytes(200, "text/plain", b"hello".to_vec());
            let _ = write_response_ka(&mut conn, resp, true, true, false, None).await;
            continue;
        }

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
        // A DAV `PUT` reads the body itself (`ngx_http_read_client_request_body`
        // in `ngx_http_dav_put_handler`), so it belongs on this list too: the
        // request body used to be drained above and the handler then blocked
        // waiting for bytes that had already been thrown away.
        let dav_put = req.method == Method::Put && loc.dav_methods & crate::dav::flags::PUT != 0;
        // `$request_body` has a get_handler, so nginx reads the body the first
        // time the variable is evaluated -- which is the `add_header` after the
        // upstream answered. The body therefore has to be in memory *before*
        // dispatch, not consumed by the upstream module. `body_chunked.t` is
        // exactly this: a chunked request proxied onward, whose response carries
        // `X-Body: $request_body`.
        let body_vars = references_body_var(&loc.headers)
            || loc.ret.as_ref().map(|(_, t)| t.contains("$request_body")).unwrap_or(false)
            // An `error_page` target runs as an internal subrequest after the
            // upstream failed, and `$request_body` is still readable there --
            // which needs the body to have been kept, not consumed by the
            // upstream module (`proxy_request_buffering.t`, "body in error
            // page").
            || !loc.error_pages.is_empty();
        let proxy_target = loc.proxy_pass.is_some()
            || loc.fastcgi_pass.is_some()
            || loc.uwsgi_pass.is_some()
            || loc.scgi_pass.is_some()
            || dav_put
            || body_vars;
        // Read it here rather than in the upstream module, so both the module and
        // the variable see the same bytes.
        if body_vars && (req.chunked || req.body_len > 0) {
            if req.expect_continue {
                let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            }
            // `client_max_body_size` bounds a chunked body too, and the limit is
            // enforced while reading rather than after (`body_chunked.t`,
            // "body too large").
            let limit = if loc.client_max_body_size == u64::MAX {
                crate::proxy::MAX_PROXY_BODY
            } else {
                (loc.client_max_body_size as usize).min(crate::proxy::MAX_PROXY_BODY)
            };
            let read = if req.chunked {
                conn.take_chunked_body(limit).await
            } else if req.body_len > limit as u64 {
                Err(body_too_large())
            } else {
                conn.take_body(req.body_len as usize).await
            };
            match read {
                Ok(b) => {
                    // `client_body_in_file_only`, or a body over
                    // `client_body_buffer_size`, spills to a temp file; then
                    // `$request_body` renders empty and `$request_body_file`
                    // names the file (`body_needs_file`).
                    if body_needs_file(loc, b.len()) {
                        req.request_body_file = write_body_file(http, &b);
                    }
                    req.buffered_body = Some(b);
                }
                Err(e) => {
                    // A body over the limit is 413; broken chunk framing is 400.
                    let status = if e.kind() == std::io::ErrorKind::InvalidData
                        && e.to_string() == "body too large"
                    {
                        413
                    } else {
                        400
                    };
                    let _ = send_error(&mut conn, status, server.server_tokens, false, false).await;
                    break;
                }
            }
        }
        if req.chunked {
            if !proxy_target {
                if req.expect_continue {
                    let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                }
                let limit = if loc.client_max_body_size == u64::MAX {
                    usize::MAX
                } else {
                    loc.client_max_body_size as usize
                };
                match conn.drain_chunked_limited(limit).await {
                    Ok(()) => {}
                    Err(e) => {
                        let status = if e.to_string() == "body too large" { 413 } else { 400 };
                        let _ =
                            send_error(&mut conn, status, server.server_tokens, false, false).await;
                        break;
                    }
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
                    let _ = send_error(&mut conn, 400, server.server_tokens, false, false).await;
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
        let prof_dispatch = crate::prof::start();
        let mut remote_eff: (String, String) = (conn.peer_ip_str(), peer_port.to_string());
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
            &mut remote_eff,
        )
        .await;
        crate::prof::record(1, prof_dispatch);
        if crate::prof::enabled() {
            crate::prof::REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
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
            conn.last_head_len + req.body_len,
            conn.last_bytes_sent,
            pipelined,
            loc.open_log_file_cache,
            (&remote_eff.0, &remote_eff.1),
            &sent,
            loc.access_logs.as_deref(),
        );
        #[cfg(feature = "alloc-count")]
        let _ = {
            let m = crate::alloccnt::mark(mark2);
            crate::alloccnt::set_phase(0);
            m
        };

        // The response is out; the connection returns to `waiting`.
        conn.set_writing(false);
        if close || !req.keepalive || util::force_close(status) || served >= http.keepalive_requests
        {
            break;
        }
    }

    // Every break path lands here, so this is the single place the counters are
    // cleared before the connection is closed.
    conn.clear_stats();
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
    // nginx evaluates ACCESS *after* `real_ip_*` (the realip module is
    // POST_READ), so `allow`/`deny` see the rewritten address. `vars` carries
    // it under `remote_addr` once realip ran; the connection value is the
    // fallback.
    let effective = vars.get("remote_addr");
    let peer_addr: std::net::IpAddr = effective
        .parse()
        .or_else(|_| vars.peer_ip.parse())
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
            // `auth_basic_user_file` may contain variables; a relative path is
            // already anchored to the configuration prefix at parse time.
            let path = loc
                .auth_basic
                .user_file
                .as_ref()
                .map(|p| std::path::PathBuf::from(vars.expand(&p.to_string_lossy())));
            codes.push(match crate::auth::check(&loc.auth_basic, header, path.as_deref()) {
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
    // `$invalid_referer` is a per-location value that nginx evaluates lazily.
    // Carrying it in the variable map keeps `ServerVars` (and its nineteen
    // construction sites) unchanged while still letting `if` and `return` see
    // the location's own `valid_referers`.
    if let Some(rules) = &loc.valid_referers {
        let val = if rules.invalid(req.headers.get("referer")) {
            "1"
        } else {
            ""
        };
        custom.insert("invalid_referer".to_string(), val.to_string());
    }
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

    // `index` is a complex value: expand it here, where the request variables
    // (`$variant` from `split_clients`, `$arg_*`, ...) are available.
    let expanded_index: Option<Vec<String>> = if loc.index.iter().any(|i| i.contains('$')) {
        Some(loc.index.iter().map(|i| vars.expand(i)).collect())
    } else {
        None
    };
    let index_ref = expanded_index.as_deref();
    let prof_content = crate::prof::start();
    let out = match static_file::respond_indexed(req, path, loc, http, index_ref) {
        Ok(r) => r,
        Err(_) => error_response(404, server.server_tokens),
    };
    crate::prof::record(2, prof_content);
    out
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
    server_port: u16,
    /// `$server_name` / `$host`: `index $server_name.html` is a documented
    /// pattern (`index.t`, "var").
    server_name: &'a str,
    /// The location whose `if` is being evaluated. `disable_symlinks` is a
    /// location directive, and a `-f` test has to honour it.
    loc: Option<&'a LocCfg>,
}

fn get_var(name: &str, v: &RwVars<'_>) -> String {
    let bare = name.trim_start_matches('$');
    if let Some(val) = v.vars.get(bare) {
        return val.clone();
    }
    match bare {
        "uri" | "document_uri" => v.path.to_string(),
        "server_name" => v
            .vars
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| v.server_name.trim_start_matches('.').to_string()),
        "host" => v
            .vars
            .get("host")
            .cloned()
            .unwrap_or_else(|| {
                v.req
                    .host
                    .as_ref()
                    .map(|h| h.to_string())
                    .unwrap_or_default()
            }),
        "request_uri" => v.req.raw_target.clone(),
        "args" | "query_string" => v.query.to_string(),
        "request_method" => v.req.method.as_str().to_string(),
        // nginx's rewrite phase evaluates these from the request's server
        // context; without them `if ($server_port = ...)` can never match.
        "server_port" => v.server_port.to_string(),
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
        // Both were empty, which made `if (-f $request_filename)` never match --
        // `http_disable_symlinks.t`'s "if (if_not_owner, same uid)" pins this
        // down because the `if` has to answer 204 rather than fall through to
        // the static handler.
        "document_root" => match v.loc {
            Some(loc) => static_file::document_root_of(loc)
                .to_string_lossy()
                .to_string(),
            None => String::new(),
        },
        "request_filename" => match v.loc {
            Some(loc) => static_file::map_path(v.path, loc)
                .to_string_lossy()
                .to_string(),
            None => String::new(),
        },
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
        IfCond::FileTest(kind, path_expr, negated) => {
            // The operand is a path with variables in it
            // (`-f /srv/$arg_c`), not a variable name: `get_var` would look up
            // the whole string as a name and always answer empty.
            let p = expand_vars(path_expr, v);
            let path = std::path::Path::new(&p);
            // A path `disable_symlinks` refuses is not a file as far as the test
            // is concerned (`ngx_open_file` fails with ELOOP).
            let refused = v
                .loc
                .map(|loc| static_file::symlinks_disallowed(path, loc, &loc.root))
                .unwrap_or(false);
            let hit = match kind {
                'f' => !refused && path.is_file(),
                'd' => !refused && path.is_dir(),
                'e' => !refused && path.exists(),
                'x' => {
                    use std::os::unix::fs::PermissionsExt;
                    path.metadata()
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                }
                _ => false,
            };
            hit != *negated
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
    server_port: u16,
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
        server_port,
        &secure_link_seed(loc, req),
    )
}

/// The `$secure_link` / `$secure_link_expires` pair, ready to seed the rewrite
/// variable map.
///
/// nginx resolves these through variable get_handlers, so the work happens on
/// the first read -- which in practice is the `if ($secure_link = ...)` a
/// config always has. Seeding before the rewrite steps is equivalent and also
/// makes the values visible to `return`, `add_header` and the access log.
fn secure_link_seed(loc: &LocCfg, req: &Request) -> Vec<(&'static str, String)> {
    match crate::secure_link::evaluate(loc, req) {
        Some((link, expires)) => vec![("secure_link", link), ("secure_link_expires", expires)],
        None => Vec::new(),
    }
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
    server_port: u16,
    seed: &[(&str, String)],
) -> RewriteOutcome {
    let mut ignored_override = None;
    let mut ignored_seen = false;
    let mut ignored_missing = false;
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
        server_port,
        &mut ignored_override,
        &mut ignored_seen,
        &mut ignored_missing,
        seed,
        // The server-level pass has no location of its own.
        None,
        server.name_display(),
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
    server_port: u16,
    // Set when a matching `if` carried its own `proxy_pass`, which nginx lets
    // override the location's target while the condition holds.
    proxy_override: &mut Option<(crate::config::ProxyPass, Option<String>)>,
    // Whether any matching `if` declared `proxy_pass`.
    if_proxy_seen: &mut bool,
    // A matching `if` installed a proxy handler but left it without a target.
    proxy_override_missing: &mut bool,
    // Variables already resolved for this request before the rewrite phase.
    // `$secure_link` is nginx's clearest case: the module exposes it through a
    // get_handler, so the first read -- the `if` that a config always has --
    // computes it. Seeding reproduces that without a lazy callback.
    seed: &[(&str, String)],
    // The location these `if` blocks belong to, for `-f` and friends, which
    // have to honour `disable_symlinks`.
    if_loc: Option<&LocCfg>,
    // `$server_name` inside `set` / `if`.
    if_server_name: &str,
) -> (RewriteOutcome, std::collections::HashMap<String, String>) {
    let mut uri = path.to_string();
    let mut args = query.to_string();
    let _ = req;

    // nginx runs `set` and `if` interleaved, in source order; a config that
    // re-assigns a variable between two `if`s depends on that order.
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, value) in seed {
        vars.insert((*name).to_string(), value.clone());
    }
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
                    server_port,
                    server_name: if_server_name,
                    loc: if_loc,
                };
                let expanded = expand_vars(value, &ctx);
                vars.insert(name.trim_start_matches('$').to_string(), expanded);
            }
            crate::config::Step::If(idx) => {
                let Some(ifb) = ifs.get(idx) else {
                    continue;
                };
                // nginx gives each matching `if` an implicit location whose conf
                // is a copy of the enclosing location with the `if`'s own
                // directives applied, and the **last** matching `if` wins. So a
                // matching `if` without `proxy_pass` clears the override that an
                // earlier one installed -- that is why two `if`s both true, the
                // first carrying `proxy_pass`, answer 500 (no target), while a
                // single one answers with its own target.
                let if_proxy = ifb
                    .proxy_pass
                    .clone()
                    .map(|pp| (pp, ifb.proxy_upstream_name.clone()));
                let mut matched = false;
                if let Some(out) = run_if(
                    ifb,
                    req,
                    &mut uri,
                    &mut args,
                    &mut vars,
                    rewrites,
                    default_type,
                    server_port,
                    &mut matched,
                    if_loc,
                    server.name_display(),
                ) {
                    return (out, vars);
                }
                if matched {
                    if if_proxy.is_some() {
                        *if_proxy_seen = true;
                    }
                    // Every matching `if` replaces the effective target: its own
                    // `proxy_pass`, or none.
                    *proxy_override = if_proxy;
                    if *if_proxy_seen && proxy_override.is_none() {
                        // A proxy handler is active but has no target: nginx
                        // answers 500 (proxy module with an empty conf).
                        *proxy_override_missing = true;
                    } else {
                        *proxy_override_missing = false;
                    }
                }
            }
        }
    }
    for rw in rewrites {
        if let Some(out) = apply_one(rw, &mut uri, &mut args, req, &vars, server_port) {
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
    server_port: u16,
    // Set to whether the condition held. `None` alone cannot distinguish "the
    // condition was false" from "the condition held but produced no terminal
    // outcome", and `proxy_pass` inside `if` needs that difference.
    matched: &mut bool,
    if_loc: Option<&LocCfg>,
    if_server_name: &str,
) -> Option<RewriteOutcome> {
    let cond = {
        let ctx = RwVars {
            req,
            path: uri,
            query: args,
            vars,
            server_port,
            server_name: if_server_name,
            loc: if_loc,
        };
        eval_cond(&ifb.cond, &ctx)
    };
    *matched = cond;
    if !cond {
        return None;
    }
    for (name, value) in &ifb.sets {
        let ctx = RwVars {
            req,
            path: uri,
            query: args,
            vars,
            server_port,
            server_name: if_server_name,
            loc: if_loc,
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
        if let Some(out) = apply_one(rw, uri, args, req, vars, server_port) {
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
    req: &Request,
    vars: &std::collections::HashMap<String, String>,
    server_port: u16,
) -> Option<RewriteOutcome> {
    if !rw.re.is_match(uri) {
        return None;
    }
    let caps = rw.re.captures(uri)?;
    // nginx splits the replacement at the first `?` of the *template*: the
    // part before is the new URI, the part after is the new args. A trailing
    // `?` drops the request's original args, plain new args are appended to
    // them with `&`, and no `?` at all keeps them verbatim.
    let (uri_tmpl, arg_tmpl) = match rw.replacement.find('?') {
        Some(q) => (&rw.replacement[..q], Some(&rw.replacement[q + 1..])),
        None => (rw.replacement.as_str(), None),
    };
    let drop_args = arg_tmpl.is_some_and(|a| a.ends_with('?'));
    let arg_tmpl = arg_tmpl.map(|a| a.trim_end_matches('?'));
    // Capture values that land in the args part are escaped there
    // (`$1` containing `%` becomes `%25`, nginx's NGX_ESCAPE_ARGS); values in
    // the URI part keep their unescaped form.
    // nginx compiles the replacement as a complex value, so `$1` and
    // `$secure_link` are expanded in the same pass -- a rewrite that uses a
    // named variable (`rewrite ^ /$secure_link break;`) is ordinary usage.
    let expanded_uri = |tmpl: &str| {
        expand_replacement(tmpl, &caps, req, uri, args, vars, server_port, false)
    };
    let target = expanded_uri(uri_tmpl);
    let new_args = match arg_tmpl {
        Some(t) if !t.is_empty() => {
            let a = expand_replacement(t, &caps, req, uri, args, vars, server_port, true);
            if drop_args || args.is_empty() {
                a
            } else {
                format!("{a}&{}", args)
            }
        }
        Some(_) => {
            // A bare `?` keeps the original args, `??` drops them.
            if drop_args {
                String::new()
            } else {
                args.clone()
            }
        }
        None => args.clone(),
    };
    *args = new_args.clone();
    let location_with_args = |loc: String| {
        if new_args.is_empty() {
            loc
        } else {
            format!("{loc}?{new_args}")
        }
    };
    if target.starts_with("http://") || target.starts_with("https://") {
        let code = match rw.flag {
            RewriteFlag::Permanent => 301,
            _ => 302,
        };
        return Some(RewriteOutcome::Respond(
            Response::empty(code).header("Location", location_with_args(target)),
        ));
    }
    match rw.flag {
        RewriteFlag::Permanent | RewriteFlag::Redirect => {
            let code = if rw.flag == RewriteFlag::Permanent {
                301
            } else {
                302
            };
            Some(RewriteOutcome::Respond(
                Response::empty(code).header("Location", location_with_args(target)),
            ))
        }
        RewriteFlag::Last => Some(RewriteOutcome::Relocate(target, new_args)),
        RewriteFlag::Break => Some(RewriteOutcome::Break(target, new_args)),
        RewriteFlag::None => {
            *uri = target;
            None
        }
    }
}

/// Escape a value substituted into the args part of a rewrite replacement
/// (nginx `NGX_ESCAPE_ARGS`): `%`, space and the characters that would
/// otherwise be parsed as delimiters or markup in a query string.
fn escape_arg_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            ' ' => out.push_str("%20"),
            '"' | '#' | '<' | '>' | '\'' => {
                out.push('%');
                out.push_str(&format!("{:02X}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// `expand_captures`, but every capture value is escaped for the args part
/// of a rewrite replacement.
fn expand_captures_args(replacement: &str, caps: &regex::Captures<'_>) -> String {
    let plain = expand_captures(replacement, caps);
    if plain == replacement {
        // No captures in the template: the literal text stays as written.
        return plain;
    }
    // Re-expand value by value so only the substituted parts get escaped.
    let mut out = String::with_capacity(replacement.len());
    let b = replacement.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            out.push_str(&replacement[start..i]);
            let n = b[i + 1] - b'0';
            if let Some(m) = caps.get(n as usize) {
                out.push_str(&escape_arg_value(m.as_str()));
            }
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&replacement[start..]);
    out
}

/// Expand `$var` references against the rewrite-phase variable set.
///
/// The literal runs are copied as `&str` slices, not byte by byte: pushing
/// `b as char` maps each byte to a Latin-1 code point, so a non-ASCII literal
/// (`return 200 "模様"`, a `sub_filter` pattern) was re-encoded as mojibake and
/// could never match the UTF-8 body it was meant for. `$` and the characters of
/// a variable name are ASCII, so every slice boundary is a char boundary.
fn expand_vars(spec: &str, v: &RwVars<'_>) -> String {
    let mut out = String::with_capacity(spec.len());
    let b = spec.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        let rest = &spec[i + 1..];
        let n = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        out.push_str(&spec[start..i]);
        if n == 0 {
            // `${name}` is the braced spelling, needed when the name is
            // followed by more identifier characters -- `index ${server_name}.html`
            // (`index.t`, "var 2").
            if rest.starts_with('{') {
                if let Some(close) = rest.find('}') {
                    let name = &rest[1..close];
                    out.push_str(&get_var(name, v));
                    i += 1 + close + 1;
                    start = i;
                    continue;
                }
            }
            out.push('$');
            i += 1;
        } else {
            out.push_str(&get_var(&rest[..n], v));
            i += 1 + n;
        }
        start = i;
    }
    out.push_str(&spec[start..]);
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
    let mut start = 0usize;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            out.push_str(&replacement[start..i]);
            let n = (b[i + 1] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                out.push_str(m.as_str());
            }
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&replacement[start..]);
    out
}

/// Expand a `rewrite` replacement: `$1`..`$9` from the regex captures and
/// `$name` from the rewrite-phase variable map, in one left-to-right pass, the
/// way nginx's compiled complex value does it.
///
/// `escape_args` applies nginx's `NGX_ESCAPE_ARGS` to the *capture* text, which
/// is what a substitution into the args part requires.
#[allow(clippy::too_many_arguments)]
fn expand_replacement(
    tmpl: &str,
    caps: &regex::Captures<'_>,
    req: &Request,
    path: &str,
    query: &str,
    vars: &std::collections::HashMap<String, String>,
    server_port: u16,
    escape_args: bool,
) -> String {
    let ctx = RwVars {
        req,
        path,
        query,
        vars,
        server_port,
        server_name: "",
        loc: None,
    };
    let mut out = String::with_capacity(tmpl.len());
    let b = tmpl.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        out.push_str(&tmpl[start..i]);
        let rest = &tmpl[i + 1..];
        // `$1`..`$9` are captures; longer runs of digits are nginx's `$10`+,
        // which only exist with named captures, so one digit is right here.
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            let n = (rest.as_bytes()[0] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                if escape_args {
                    out.push_str(&escape_arg_value(m.as_str()));
                } else {
                    out.push_str(m.as_str());
                }
            }
            i += 2;
            start = i;
            continue;
        }
        let n = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if n == 0 {
            out.push('$');
            i += 1;
        } else {
            let name = rest[..n].trim_start_matches('$');
            let value = match vars.get(name) {
                Some(v) => v.clone(),
                None => get_var(name, &ctx),
            };
            out.push_str(&value);
            i += 1 + n;
        }
        start = i;
    }
    out.push_str(&tmpl[start..]);
    out
}

/// `$proxy_protocol_addr` / `$proxy_protocol_server_addr`.
fn pp_addr(req: &Request) -> String {
    req.proxy_protocol
        .as_ref()
        .map(|p| p.src_addr.clone())
        .unwrap_or_default()
}

fn pp_server_addr(req: &Request) -> String {
    req.proxy_protocol
        .as_ref()
        .map(|p| p.dst_addr.clone())
        .unwrap_or_default()
}

/// A PROXY port renders as the empty string when it is 0, which is what
/// `ngx_http_variable_proxy_protocol_port` does and why `PROXY UNKNOWN` reads
/// `X-PP: !`.
fn pp_port(req: &Request, server: bool) -> String {
    let Some(p) = req.proxy_protocol.as_ref() else {
        return String::new();
    };
    let port = if server { p.dst_port } else { p.src_port };
    crate::proxyproto::Pp::port_text(port)
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
/// The `Last-Modified` epoch of a rendered header block, if present.
fn last_modified_of(raw: &[u8]) -> Option<i64> {
    let text = String::from_utf8_lossy(raw);
    for line in text.split("\r\n") {
        if let Some(v) = line
            .to_ascii_lowercase()
            .starts_with("last-modified:")
            .then(|| line[15..].trim())
        {
            if let Some(t) = crate::util::parse_http_date(v) {
                return Some(t);
            }
        }
    }
    None
}

/// The server's local UTC offset at `t` (seconds east), via libc's localtime.
fn local_utc_offset(t: i64) -> i64 {
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let tt = t as libc::time_t;
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
}

pub fn apply_expires(raw: &mut Vec<u8>, loc: &LocCfg, status: u16, expanded: Option<&str>) {
    let Some(raw_spec) = &loc.expires else { return };
    // `expires` shares `add_header`'s filter, so it has the same status gate.
    if !add_header_applies(status, false) {
        return;
    }
    // `expires` is a complex value (`expires $arg_e`), expanded by the caller.
    let spec = expanded.unwrap_or(raw_spec).trim();

    // `ngx_http_parse_expires`: the epoch/max/off shortcuts are only recognised
    // when the directive was NOT written as `modified ...`.
    let mut modified = false;
    let mut rest = spec;
    if let Some(r) = spec.strip_prefix("modified") {
        if r.is_empty() || r.starts_with(' ') {
            modified = true;
            rest = r.trim();
        }
    }

    #[derive(PartialEq, Clone, Copy)]
    enum Kind {
        Epoch,
        Max,
        Daily,
        Access,
    }
    let mut kind = Kind::Access;
    let mut offset: i64 = 0;

    if !modified {
        match rest {
            "epoch" => kind = Kind::Epoch,
            "max" => kind = Kind::Max,
            "off" => return,
            _ => {}
        }
    }
    if !matches!(kind, Kind::Epoch | Kind::Max) {
        // A `+`/`-` prefix sign, then the time itself.
        let (neg, body) = match rest.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, rest.strip_prefix('+').unwrap_or(rest)),
        };
        if let Some(daily) = body.strip_prefix('@') {
            // A config-time `expires modified @...` is rejected while parsing;
            // a variable that expands into one emits nothing.
            if modified {
                return;
            }
            let Some(d) = crate::config::parse_time(daily) else {
                return;
            };
            kind = Kind::Daily;
            offset = (d.as_secs() % 86_400) as i64;
        } else {
            // An empty or unparseable value emits nothing at all -- not even a
            // zero-length Expires (`headers.t`, "expires var empty" / "bad").
            let Some(d) = crate::config::parse_time(body) else {
                return;
            };
            offset = if neg {
                -(d.as_secs() as i64)
            } else {
                d.as_secs() as i64
            };
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (expires_value, cache_control): (String, CacheControl) = match kind {
        Kind::Epoch => (
            "Thu, 01 Jan 1970 00:00:01 GMT".to_string(),
            CacheControl::Fixed("no-cache"),
        ),
        Kind::Max => (
            "Thu, 31 Dec 2037 23:55:55 GMT".to_string(),
            CacheControl::Fixed("max-age=315360000"),
        ),
        Kind::Daily | Kind::Access => {
            let (at, max_age) = if kind == Kind::Daily {
                // nginx reads the daily time in the server's *local* zone
                // (`ngx_time_next_expiration` works on broken-down time).
                let local = now + local_utc_offset(now);
                let today_start = local - local % 86_400;
                let mut local_at = today_start + offset;
                if local_at <= local {
                    local_at += 86_400;
                }
                let at = local_at - local_utc_offset(local_at);
                (at, at - now)
            } else if modified {
                // Anchored on Last-Modified, falling back to "now" when the
                // response has none (`last_modified_time == -1`).
                let base = last_modified_of(raw).unwrap_or(now);
                let at = base + offset;
                (at, at - now)
            } else {
                (now + offset, offset)
            };
            let cc = if offset < 0 || max_age < 0 {
                CacheControl::Fixed("no-cache")
            } else {
                CacheControl::MaxAge(max_age)
            };
            (util::http_date(at), cc)
        }
    };

    // nginx's expires *replaces* any Cache-Control the upstream produced —
    // in place: a proxied `Cache-Control` keeps its slot and the new value,
    // while a response without one gets both headers appended (Expires first,
    // then Cache-Control, as `ngx_http_headers_filter` orders them).
    if !expires_value.is_empty() {
        let text = String::from_utf8_lossy(raw).to_string();
        let mut rebuilt = Vec::with_capacity(raw.len());
        let mut cc_placed = false;
        for line in text.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("cache-control:") {
                if let (cc, false) = (&cache_control, cc_placed) {
                    rebuilt.extend_from_slice(b"Cache-Control: ");
                    let v = match cc {
                        CacheControl::Fixed(v) => v.to_string(),
                        CacheControl::MaxAge(n) => format!("max-age={n}"),
                    };
                    rebuilt.extend_from_slice(v.as_bytes());
                    rebuilt.extend_from_slice(b"\r\n");
                    cc_placed = true;
                }
                continue;
            }
            if lower.starts_with("expires:") {
                continue;
            }
            if line.is_empty() {
                continue;
            }
            rebuilt.extend_from_slice(line.as_bytes());
            rebuilt.extend_from_slice(b"\r\n");
        }
        *raw = rebuilt;
        // A response that had no Cache-Control gets both appended, Expires
        // first (`ngx_http_headers_filter`'s order); one that had it keeps the
        // slot, handled above.
        if !cc_placed {
            raw.extend_from_slice(b"Expires: ");
            raw.extend_from_slice(expires_value.as_bytes());
            raw.extend_from_slice(b"\r\n");
            raw.extend_from_slice(b"Cache-Control: ");
            let v = match &cache_control {
                CacheControl::Fixed(v) => v.to_string(),
                CacheControl::MaxAge(n) => format!("max-age={n}"),
            };
            raw.extend_from_slice(v.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
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
        // `$upstream_addr` in `add_header` shows every attempt, not just the
        // one that answered; fall back to the single address when the
        // task-local list is empty (h2 spawned paths).
        let addr_list =
            crate::timing::variable("upstream_addr").unwrap_or_else(|| upstream_addr.to_string());
        let mut expanded = expand_upstream_vars(value, upstream_headers)
            .replace("$upstream_cache_status", upstream_cache_status)
            .replace("$upstream_addr", &addr_list)
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
        if expanded.is_empty() {
            // `add_header` handles `ETag` and `Last-Modified` through
            // `ngx_http_set_response_header`, whose empty value **clears** the
            // header the handler had produced -- `headers.t` asserts this with
            // `add_header ETag '' always`. Every other name is simply skipped
            // (`ngx_http_add_header` drops a zero-length value).
            if name.eq_ignore_ascii_case("etag") || name.eq_ignore_ascii_case("last-modified") {
                drop_replaced_header(raw, name);
                sent.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            }
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
        // `split_clients` results are ordinary variables, resolved the same way
        // as `map`: expand the source, hash it, pick the bucket, then expand the
        // bucket's value.
        if let Some(sc) = crate::config::splits()
            .iter()
            .find(|s| s.var == name)
            .cloned()
        {
            let source = self.expand(&sc.source);
            let value = sc.pick(&source)?.to_string();
            return Some(self.expand(&value));
        }
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
            _ if name.starts_with("proxy_protocol_tlv_") => {
                // `$proxy_protocol_tlv_<name>` / `_0xNN` / `_ssl_<sub>`.
                match self.req.proxy_protocol.as_ref() {
                    Some(pp) => match pp.tlv(&name["proxy_protocol_tlv_".len()..]) {
                        Ok(Some(v)) => String::from_utf8_lossy(&v).to_string(),
                        // Absent and malformed both render empty here; nginx
                        // answers 500 for the malformed case, which no test
                        // exercises and which would need an error channel this
                        // function does not have.
                        _ => String::new(),
                    },
                    None => String::new(),
                }
            }
            // nginx exposes the body only once it has been read; over HTTP/1.1
            // our dispatcher streams it straight to the upstream, so this is
            // populated on HTTP/2 and HTTP/3, where it arrives before routing.
            // `$request_body_file` needs `client_body_in_file_only`, and the
            // path is threaded in by the caller that wrote the file.
            "request_body" => {
                // Once the body is on disk nginx reports it as empty.
                if self.req.request_body_file.is_some() {
                    String::new()
                } else {
                    self.req
                        .buffered_body
                        .as_ref()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .unwrap_or_default()
                }
            }
            "request_body_file" => self
                .req
                .request_body_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
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
            "ssl_session_reused" => tls
                .map(|t| if t.session_reused { "r" } else { "." })
                .unwrap_or(".")
                .to_string(),
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
            // `listen ... proxy_protocol` values. Absent (no header on this
            // connection) is "not found", which is why these are empty and not
            // the connection's address -- `proxy_protocol.t` asserts that.
            "proxy_protocol_addr" => pp_addr(self.req),
            "proxy_protocol_port" => pp_port(self.req, false),
            "proxy_protocol_server_addr" => pp_server_addr(self.req),
            "proxy_protocol_server_port" => pp_port(self.req, true),
            // nginx: without a rewrite these alias the connection values.
            "realip_remote_addr" => self
                .custom
                .get("realip_remote_addr")
                .cloned()
                .unwrap_or_else(|| self.peer_ip.to_string()),
            "realip_remote_port" => self
                .custom
                .get("realip_remote_port")
                .cloned()
                .unwrap_or_else(|| self.peer_port.to_string()),
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
            // `$request_id`: 32 lowercase hex digits, generated once per request
            // so the header, an SSI subrequest and the log line all agree.
            "request_id" => self.req.request_id.clone(),
            // One entry per upstream attempt, ", "-joined (nginx's
            // `u->state` list); empty when this request never proxied.
            "upstream_addr" | "upstream_status" => {
                crate::timing::variable(name).unwrap_or_default()
            }
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
            // `$connection` is the connection's serial number (`c->number`),
            // which `split_clients $connection ...` buckets on.
            "connection" => crate::stats::conn_serial().to_string(),
            // `stub_status` counters, exposed as variables the same way nginx
            // does (`ngx_stat_active` etc.).
            "connections_active" => crate::stats::ACTIVE
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_string(),
            "connections_reading" => crate::stats::READING
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_string(),
            "connections_writing" => crate::stats::WRITING
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_string(),
            "connections_waiting" => {
                let a = crate::stats::ACTIVE.load(std::sync::atomic::Ordering::Relaxed);
                let r = crate::stats::READING.load(std::sync::atomic::Ordering::Relaxed);
                let w = crate::stats::WRITING.load(std::sync::atomic::Ordering::Relaxed);
                a.saturating_sub(r + w).to_string()
            }
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
                // Literal runs are copied as slices; see `expand_vars` for why
                // a byte-wise `push(b as char)` corrupts non-ASCII text.
                let end = memchr::memchr(b'$', &b[i..])
                    .map(|p| i + p)
                    .unwrap_or(b.len());
                out.push_str(&spec[i..end]);
                i = end;
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
    /// whether a rewrite inside the *current* location changed the URI
    /// (nginx then ignores a `proxy_pass` URI part), and the `set` variables.
    Loc(
        String,
        String,
        std::borrow::Cow<'a, LocCfg>,
        bool,
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
    server_port: u16,
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
            server_port,
            &secure_link_seed(loc, req),
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
    // Whether a rewrite inside the location currently being processed changed
    // the URI (a relocation starts fresh rules for the new location).
    let mut uri_rewritten = false;
    // `proxy_pass` supplied by a matching `if` or `limit_except`, which replaces
    // the location's target for this request.
    let mut proxy_override: Option<(crate::config::ProxyPass, Option<String>)> = None;
    let mut if_proxy_seen = false;
    let mut proxy_override_missing = false;
    // `limit_except GET { proxy_pass ...; }` applies to every method *not*
    // listed, so it is decided once from the request method.
    for le in &cur_loc.limit_except {
        if !le.methods.iter().any(|m| m == req.method.as_str()) {
            if le.proxy_pass.is_some() {
                proxy_override = le
                    .proxy_pass
                    .clone()
                    .map(|pp| (pp, le.proxy_upstream_name.clone()));
            }
            break;
        }
    }
    loop {
        let loc_path_in = cur_path.clone();
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
            server_port,
            &mut proxy_override,
            &mut if_proxy_seen,
            &mut proxy_override_missing,
            &secure_link_seed(cur_loc, req),
            Some(cur_loc),
            server.name_display(),
        );
        vars.extend(phase_vars);
        // The location loop starts each pass with an empty map, so the secure
        // link verdict has to be carried across: `return 200 x$secure_link` in
        // a later `if` (and the access log) reads it from here.
        for (name, value) in secure_link_seed(cur_loc, req) {
            vars.entry(name.to_string()).or_insert(value);
        }
        match outcome {
            RewriteOutcome::Respond(r) => return Target::Done(r),
            RewriteOutcome::Continue(p, q) => {
                cur_path = p;
                cur_query = q;
                uri_rewritten = cur_path != loc_path_in;
                break;
            }
            RewriteOutcome::Break(p, q) => {
                cur_path = p;
                cur_query = q;
                skip_return = true;
                uri_rewritten = true;
                break;
            }
            RewriteOutcome::Relocate(p, q) => {
                cur_path = p;
                cur_query = q;
                cur_loc = server.locate(&cur_path);
                uri_rewritten = false;
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

    // `ngx_http_index_handler`: a directory whose `index` matches becomes an
    // internal redirect, so `$uri` changes to the index file and location
    // matching runs again. A redirect that lands back on a directory repeats
    // until nginx's limit, which is a 500 (`index.t`, `/loop/`).
    let mut index_hops = 0usize;
    loop {
        let expanded_index: Option<Vec<String>> = if cur_loc.index.iter().any(|i| i.contains('$')) {
            let ctx = RwVars {
                req,
                path: &cur_path,
                query: &cur_query,
                vars: &vars,
                server_port,
                server_name: server.name_display(),
                loc: Some(cur_loc),
            };
            Some(cur_loc.index.iter().map(|i| expand_vars(i, &ctx)).collect())
        } else {
            None
        };
        let Some(target) = static_file::index_redirect(
            &cur_path,
            cur_loc,
            expanded_index.as_deref(),
        ) else {
            break;
        };
        index_hops += 1;
        if index_hops > 10 {
            return Target::Done(error_response(500, server.server_tokens));
        }
        cur_path = target;
        cur_loc = server.locate(&cur_path);
    }

    // A matching `if` installed the proxy handler but left it without a target:
    // nginx answers 500 (the proxy module runs with an empty conf).
    if proxy_override_missing {
        return Target::Done(error_response(500, server.server_tokens));
    }

    // An `if` or `limit_except` `proxy_pass` replaces the location's target.
    // Cloning the config is only done when an override actually applies.
    if let Some((pp, name)) = proxy_override.take() {
        let mut overridden = cur_loc.clone();
        if name.is_some() {
            overridden.proxy_upstream_name = name;
        }
        overridden.proxy_pass = Some(pp);
        return Target::Loc(
            cur_path,
            cur_query,
            std::borrow::Cow::Owned(overridden),
            skip_return,
            uri_rewritten,
            vars,
        );
    }

    Target::Loc(
        cur_path,
        cur_query,
        std::borrow::Cow::Borrowed(cur_loc),
        skip_return,
        uri_rewritten,
        vars,
    )
}

/// Run a bare error status through the normal pipeline, so `error_page` applies.
///
/// The HTTP/1 path gets this through `finalize_response` on a synthetic request;
/// HTTP/2 answered an invalid `:authority` before routing and skipped
/// `error_page` entirely, so a config that maps 400 to a page got a bare 400
/// instead (`h2_absolute_redirect.t`, "invalid host - using local sockaddr").
#[allow(clippy::too_many_arguments)]
pub async fn error_page_response(
    req: &Request,
    status: u16,
    server: &Server,
    http: &Http,
    peer_ip: &str,
    peer_port: u16,
    server_port: u16,
    local_addr: &str,
) -> Response {
    let mut custom: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut resp = error_response(status, server.server_tokens);
    finalize_response(
        req,
        &mut resp,
        "/",
        "",
        server,
        http,
        peer_ip,
        peer_port,
        server_port,
        &[],
        &mut custom,
        ConnState {
            requests: 0,
            started: std::time::Instant::now(),
        },
        local_addr,
    )
    .await
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

    // FastCGI without a socket: `auth_request` may point at a `fastcgi_pass`
    // location, and nginx runs that subrequest through the ordinary content
    // phase. The exchange itself has no connection in it, so the same code
    // serves both paths. The subrequest carries no body (`fastcgi_pass_request_
    // body off` is what the auth case uses), which is why `&[]` is passed.
    if loc.fastcgi_pass.is_some() {
        if let Some((resp, _had_length)) =
            crate::fastcgi::fetch(req, path, query, loc, http, &[], peer_ip).await
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

    let mut resp = match resolve_target(req, path, query, server, loc, http, server_port) {
        Target::Done(r) => r,
        Target::Loc(p, q, l, skip, _rw, set_vars) => {
            return render_resolved_state(
                req,
                &p,
                &q,
                &l,
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

    let mut resp = match resolve_target(req, path, query, server, loc, http, server_port) {
        Target::Done(r) => r,
        Target::Loc(p, q, l, skip, _rw, set_vars) => {
            return render_resolved_state(
                req,
                &p,
                &q,
                &l,
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
) -> (Option<Response>, Vec<(&'static str, &'static str)>) {
    // nginx's `$limit_req_status` / `$limit_conn_status`. Empty when no limit
    // applied, which is why `add_header X-Status $limit_req_status` emits
    // nothing for an unlimited location.
    let mut statuses: Vec<(&'static str, &'static str)> = Vec::new();
    for lr in &loc.limit_reqs {
        let Some(zone) = http.limit_req_zones.iter().find(|z| z.name == lr.zone) else {
            continue;
        };
        let key = limit_key(&zone.key, vars);
        // An empty key disables the limit for this request (`key.len == 0`
        // is skipped in `ngx_http_limit_req_handler`). Without this the empty
        // string becomes a shared bucket, so every request without the key --
        // `limit_req2.t`'s `$arg_a` with no `a=` argument -- shares one bucket
        // and the second one is rejected.
        if key.is_empty() {
            continue;
        }
        let dry = loc.limit_req_dry_run;
        let log_at = |msg: &str| {
            // nginx writes this once per configured `error_log` of the
            // location, at `limit_req_log_level`. Two `error_log` directives
            // pointing at the same file therefore produce two identical lines
            // (error_log.t checks exactly that).
            for spec in &loc.error_logs {
                if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                    crate::log::log_to(&[sink], loc.limit_req_log_level, msg);
                }
            }
            if loc.error_logs.is_empty() {
                crate::log::error_log(loc.limit_req_log_level.name(), msg);
            }
        };
        match zone.state.account(&key, lr.burst, lr.nodelay, lr.delay) {
            None => {
                if dry {
                    // `limit_req_dry_run on`: the excess is counted and logged,
                    // the request goes through, and the variable says so.
                    log_at(&format!(
                        "limiting requests, dry run, excess: zone=\"{}\" key=\"{key}\"",
                        lr.zone
                    ));
                    statuses.push(("limit_req_status", "REJECTED_DRY_RUN"));
                    continue;
                }
                log_at(&format!(
                    "limiting requests, excess: zone=\"{}\" key=\"{key}\"",
                    lr.zone
                ));
                statuses.push(("limit_req_status", "REJECTED"));
                return (Some(error_response(loc.limit_req_status, true)), statuses);
            }
            Some(delay) if !delay.is_zero() => {
                if dry {
                    log_at(&format!(
                        "delaying request, dry run, excess: zone=\"{}\" key=\"{key}\"",
                        lr.zone
                    ));
                    statuses.push(("limit_req_status", "DELAYED_DRY_RUN"));
                    continue;
                }
                statuses.push(("limit_req_status", "DELAYED"));
                // nginx holds the request for the computed delay, without
                // blocking its worker. Sleeping the thread here stalls every
                // other connection multiplexed on that runtime thread; with a
                // single worker it serialises the whole server.
                tokio::time::sleep(delay.min(std::time::Duration::from_secs(10))).await;
            }
            _ => statuses.push(("limit_req_status", "PASSED")),
        }
    }

    for lc in &loc.limit_conns {
        let Some(zone) = http.limit_conn_zones.iter().find(|z| z.name == lc.zone) else {
            continue;
        };
        let key = limit_key(&zone.key, vars);
        // Same rule as `limit_req`: no key, no limit.
        if key.is_empty() {
            continue;
        }
        let too_many = match zone.state.acquire(&key, lc.limit, client_fd) {
            Some(guard) => {
                guards.push(guard);
                false
            }
            None => true,
        };
        if !too_many {
            statuses.push(("limit_conn_status", "PASSED"));
            continue;
        }
        let msg = format!("limiting connections by zone \"{}\"", lc.zone);
        if loc.limit_conn_dry_run {
            // nginx: "limiting connections%s by zone ..." with `, dry run`
            // substituted after the word "connections".
            let dry = format!("limiting connections, dry run by zone \"{}\"", lc.zone);
            for spec in &loc.error_logs {
                if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                    crate::log::log_to(&[sink], loc.limit_conn_log_level, &dry);
                }
            }
            if loc.error_logs.is_empty() {
                crate::log::error_log(loc.limit_conn_log_level.name(), &dry);
            }
            statuses.push(("limit_conn_status", "REJECTED_DRY_RUN"));
            continue;
        }
        for spec in &loc.error_logs {
            if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                crate::log::log_to(&[sink], loc.limit_conn_log_level, &msg);
            }
        }
        // The main-context log still sees it, as in nginx.
        if loc.error_logs.is_empty() {
            crate::log::error_log(loc.limit_conn_log_level.name(), &msg);
        }
        statuses.push(("limit_conn_status", "REJECTED"));
        return (Some(error_response(loc.limit_conn_status, true)), statuses);
    }

    (None, statuses)
}

/// Apply `error_page`, `add_header` and `gzip` to a response the content phase
/// produced (including ones from `return` / `rewrite`).
#[allow(clippy::too_many_arguments)]
/// A header value from a `Response`'s dynamic or pre-rendered header set.
fn response_header(r: &Response, name: &str) -> Option<String> {
    for (k, v) in &r.headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.clone());
        }
    }
    split_head(&r.raw)
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

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
    // Whether an `error_page` target actually ran: the builtin body fill at
    // the end must not kick in for it (a 204/200 target deliberately answers
    // with an empty body, nginx keeps that instead of the error page).
    let mut ran_error_page = false;

    while depth < 10 && util::is_special_status(resp.status) && resp.status >= 300 {
        let Some(target) = cur_loc.error_pages.get(&resp.status).cloned() else {
            break;
        };
        ran_error_page = true;
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
            let mut redirected = redirected;
            if redirected.status >= 300 && redirected.body.is_empty() {
                // Fill the builtin page, keeping the target's own headers
                // (a `return 302 "text"` target carries its Location here).
                let mut filled = error_response(redirected.status, server.server_tokens);
                filled.headers.extend(redirected.headers.iter().cloned());
                for (k, v) in split_head(&redirected.raw) {
                    if !k.eq_ignore_ascii_case("content-type")
                        && !k.eq_ignore_ascii_case("content-length")
                    {
                        filled.headers.push((k, v));
                    }
                }
                redirected = filled;
            }
            if !use_target_status
                && (300..400).contains(&original_status)
                && response_header(&redirected, "location").is_none()
            {
                if let Some(loc) = response_header(resp, "location") {
                    redirected.headers.push(("Location".to_string(), loc));
                }
            }
            let redirected_status = redirected.status;
            *resp = redirected;
            resp.status = if use_target_status {
                redirected_status
            } else {
                match new_status {
                    Some(code) => code,
                    None if redirected_status >= 300 => redirected_status,
                    None => original_status,
                }
            };
            continue;
        }
        cur_loc = server.locate(&cur_path);

        // The error page target runs the full rewrite phase too, so a
        // `rewrite ^ http://...` inside it produces the redirect.
        let redirected = match resolve_target(
            req,
            &cur_path,
            &cur_query,
            server,
            cur_loc,
            http,
            server_port,
        ) {
            Target::Done(r) => r,
            Target::Loc(p, q, l, _skip, _rw, _set_vars) => {
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
                    &l,
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
        let mut redirected = redirected;
        if redirected.status >= 300 && redirected.body.is_empty() {
            let mut filled = error_response(redirected.status, server.server_tokens);
            filled.headers.extend(redirected.headers.iter().cloned());
            for (k, v) in split_head(&redirected.raw) {
                if !k.eq_ignore_ascii_case("content-type")
                    && !k.eq_ignore_ascii_case("content-length")
                {
                    filled.headers.push((k, v));
                }
            }
            redirected = filled;
        }
        if !use_target_status
            && (300..400).contains(&original_status)
            && !response_header(&redirected, "location").is_some()
        {
            if let Some(loc) = response_header(resp, "location") {
                redirected.headers.push(("Location".to_string(), loc));
            }
        }
        let redirected_status = redirected.status;
        *resp = redirected;
        resp.status = if use_target_status {
            redirected_status
        } else {
            match new_status {
                Some(code) => code,
                None if redirected_status >= 300 => redirected_status,
                None => original_status,
            }
        };
    }

    if !ran_error_page && resp.status >= 400 && resp.body.is_empty() {
        *resp = error_response(resp.status, server.server_tokens);
    }

    let mut out = crate::gzip::maybe_compress(
        req,
        std::mem::replace(resp, Response::empty(200)),
        cur_loc,
        http,
    );

    // `expires` may be a complex value (`expires $arg_e`), so it is expanded
    // here where the request variables are in scope.
    let expires_expanded = cur_loc.expires.as_ref().map(|spec| {
        let ctx = RwVars {
            req,
            path: &cur_path,
            query: &cur_query,
            vars: custom,
            server_port,
            server_name: server.name_display(),
            loc: Some(cur_loc),
        };
        expand_vars(spec, &ctx)
    });
    apply_expires(
        &mut out.raw,
        cur_loc,
        out.status,
        expires_expanded.as_deref(),
    );
    // nginx's header filter turns *any* `Location` that starts with `/` into an
    // absolute URL when `absolute_redirect` is on -- including one an upstream
    // sent and `proxy_redirect` rewrote. Verified with `proxy_redirect.t`, whose
    // expectations are absolute.
    // `Location` may still be an unrendered entry in `headers` (that is where
    // `return 301 /x` and the directory redirect put it) or already rendered into
    // `raw`. The socket path only ever fixed the former, in `write_redirect`, so
    // an HTTP/2 client got a relative `Location` where nginx sends an absolute
    // one (`h2_absolute_redirect.t`). Fix both here, once.
    absolutize_location_field(&mut out, req, cur_loc, server_port, local_addr);
    absolutize_location(&mut out.raw, req, cur_loc, server_port, local_addr);

    if (!cur_loc.headers.is_empty() || !cur_loc.trailers.is_empty()) && !out.headers_finalized {
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
// ---- realip (ngx_http_realip_module) --------------------------------------

fn cidr_contains(net: std::net::IpAddr, bits: u8, ip: std::net::IpAddr) -> bool {
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            let b = u32::from(bits);
            if b == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - b);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            let b = u32::from(bits);
            if b == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - b);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// `1.2.3.4[:56]` / `[::1]:56` / `::1` — the address forms nginx's
/// `ngx_parse_addr_port` accepts in proxy headers.
fn parse_addr_port(s: &str) -> Option<(std::net::IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest.split_once(']')?;
        let port = port.strip_prefix(':')?;
        return Some((host.parse().ok()?, port.parse().ok()?));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if host.parse::<std::net::IpAddr>().is_ok() => {
            Some((host.parse().ok()?, port.parse().ok()?))
        }
        _ => Some((s.parse().ok()?, 0)),
    }
}

/// `ngx_http_get_forwarded_addr`'s per-header step: walk the value from the
/// right while the current address is trusted; `recursive` gates the walk
/// inside one header (nginx: `while (recursive && p > xff)`).
enum FwdStep {
    Ok,
    Done,
    Declined,
}

fn forwarded_step(
    value: &str,
    addr: &mut (std::net::IpAddr, u16),
    loc: &LocCfg,
    recursive: bool,
) -> FwdStep {
    let trusted = |ip| {
        loc.realip_from
            .iter()
            .any(|(n, b)| cidr_contains(*n, *b, ip))
    };
    let mut rest = value;
    let mut found = false;
    loop {
        if !trusted(addr.0) {
            return if found {
                FwdStep::Done
            } else {
                FwdStep::Declined
            };
        }
        let trimmed = rest.trim_end_matches([' ', ',']);
        let token = match trimmed.rsplit([' ', ',']).next() {
            Some(t) if !t.is_empty() => t,
            _ => {
                return if found {
                    FwdStep::Done
                } else {
                    FwdStep::Declined
                }
            }
        };
        let Some(parsed) = parse_addr_port(token) else {
            return if found {
                FwdStep::Done
            } else {
                FwdStep::Declined
            };
        };
        *addr = parsed;
        found = true;
        if !recursive {
            break;
        }
        let consumed = trimmed.len() - token.len();
        if consumed == 0 {
            break;
        }
        rest = &rest[..consumed];
    }
    FwdStep::Ok
}

/// The address `real_ip_*` rewrites `$remote_addr` to, if any
/// (`ngx_http_realip_handler` + `ngx_http_get_forwarded_addr`).
///
/// `peer` is `None` for a unix-socket connection, which has no address to
/// match against; `set_real_ip_from unix:` is what trusts those peers.
fn realip_effective(
    loc: &LocCfg,
    req: &Request,
    peer: Option<std::net::IpAddr>,
    pp: Option<&crate::proxyproto::Pp>,
) -> Option<(std::net::IpAddr, u16)> {
    if loc.realip_from.is_empty() && !loc.realip_from_unix {
        return None;
    }
    // The peer must be trusted before its header is believed. Skipping this
    // lets any client set `$remote_addr` — and with it `allow`/`deny`,
    // the `limit_req`/`limit_conn` keys and `access_log` — by sending
    // `X-Real-IP`. nginx checks the peer first (`ngx_http_realip_handler`:
    // `ngx_cidr_match(c->sockaddr, ...)` before the header is used).
    let peer_trusted = match peer {
        Some(ip) => loc.realip_from.iter().any(|(n, b)| cidr_contains(*n, *b, ip)),
        None => loc.realip_from_unix,
    };
    if !peer_trusted {
        return None;
    }
    let mut addr = (
        peer.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        0u16,
    );
    if loc.real_ip_header.eq_ignore_ascii_case("X-Forwarded-For") {
        let values: Vec<&str> = req.headers.get_all("x-forwarded-for").collect();
        // nginx reverts the header list and walks it last-received first.
        let mut found = false;
        for v in values.iter().rev() {
            match forwarded_step(v, &mut addr, loc, loc.real_ip_recursive) {
                FwdStep::Ok => {
                    found = true;
                    if !loc.real_ip_recursive {
                        break;
                    }
                }
                FwdStep::Done => {
                    found = true;
                    break;
                }
                FwdStep::Declined => {
                    if !loc.real_ip_recursive {
                        break;
                    }
                    if found {
                        break;
                    }
                }
            }
        }
        if !found {
            return None;
        }
        Some(addr)
    } else if loc.real_ip_header.eq_ignore_ascii_case("proxy_protocol") {
        // `real_ip_header proxy_protocol`: the address comes from the header
        // consumed at connection setup, not from an HTTP header. nginx resolves
        // the value through `$proxy_protocol_addr`, so an empty one declines.
        let pp = pp?;
        if pp.src_addr.is_empty() {
            return None;
        }
        let ip: std::net::IpAddr = pp.src_addr.parse().ok()?;
        Some((ip, pp.src_port))
    } else {
        // Header names are stored lowercased; the directive keeps its case.
        let name = loc.real_ip_header.to_ascii_lowercase();
        let value = req.headers.get(name.as_str())?;
        let parsed = parse_addr_port(value)?;
        Some(parsed)
    }
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
    captures: &[(String, String)],
    state: ConnState,
    local_addr: &str,
    peer_port: u16,
    client_ip: &str,
    guards: &mut Vec<crate::limit::ConnGuard>,
    // The client address as `real_ip_*` left it. The access log is written
    // outside `dispatch`, and `$remote_addr` there must be the rewritten one
    // (`proxy_protocol.t` asserts the client address in the log).
    remote: &mut (String, String),
) -> io::Result<Outcome> {
    // Measurement endpoint for `NGXRS_PROF=1`: per-request thread-CPU time by
    // phase, so the cost of a path can be attributed instead of guessed.
    if crate::prof::enabled() && (path == "/_prof" || path == "/_prof_reset") {
        let body = crate::prof::dump(path == "/_prof_reset").into_bytes();
        let mut resp = Response::bytes(200, "text/plain", body);
        let sent = if sent_headers_needed(server) {
            split_head(&resp.raw)
        } else {
            Vec::new()
        };
        let written = write_response(conn, resp, true, server.server_tokens, false).await?;
        // The dump itself must not be charged to any phase.
        return Ok(Outcome {
            status: 200,
            bytes: written,
            close: false,
            sent,
        });
    }

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
    // `resolve_target` may hand back a location that carries an `if`/`limit_except`
    // `proxy_pass` override, so `loc` is a Cow rather than a plain reference.
    let resolved_path;
    let resolved_query;
    let resolved_loc: std::borrow::Cow<'_, LocCfg>;
    let skip_return;
    let uri_rewritten;
    let pre;
    let mut set_vars;
    match resolve_target(req, path, query, server, loc, http, listen_port) {
        Target::Done(r) => {
            resolved_path = path.to_string();
            resolved_query = query.to_string();
            resolved_loc = std::borrow::Cow::Borrowed(loc);
            skip_return = false;
            uri_rewritten = false;
            pre = Some(r);
            set_vars = Default::default();
        }
        Target::Loc(p, q, l, skip, rewritten, sv) => {
            resolved_path = p;
            resolved_query = q;
            resolved_loc = l;
            skip_return = skip;
            uri_rewritten = rewritten;
            pre = None;
            set_vars = sv;
        }
    }
    let (path, query, loc) = (
        resolved_path.as_str(),
        resolved_query.as_str(),
        &*resolved_loc,
    );

    // `real_ip_*`: a trusted proxy's header rewrites $remote_addr. The
    // rewritten and original values are per-request variables, so every
    // later ServerVars sees them through the custom map.
    // A unix-socket peer has no address (`$remote_addr` reads `unix:`), so it
    // is passed as `None` and trusted only via `set_real_ip_from unix:`.
    let peer_str = conn.peer_ip_str();
    let peer_addr = peer_str.parse::<std::net::IpAddr>().ok();
    let pp = conn.proxy_protocol.clone();
    if peer_addr.is_some() || peer_str == "unix:" {
        if let Some((ip, port)) = realip_effective(loc, req, peer_addr, pp.as_deref()) {
            *remote = (ip.to_string(), port.to_string());
            set_vars.insert("remote_addr".to_string(), ip.to_string());
            set_vars.insert("remote_port".to_string(), port.to_string());
            set_vars.insert("realip_remote_addr".to_string(), peer_str.to_string());
            set_vars.insert("realip_remote_port".to_string(), peer_port.to_string());
        }
        let _ = &set_vars;
    }

    // `limit_rate` is a per-response write rate. `$limit_rate` is also settable
    // (`set $limit_rate 5k`), so the variable wins when it has a value.
    {
        let root_str = loc.root.to_string_lossy().to_string();
        let vars = ServerVars {
            req,
            path,
            query,
            server_name: server.names.first().map(|s| s.as_str()).unwrap_or(""),
            server_port: listen_port,
            peer_ip: &conn.peer_ip_str(),
            peer_port,
            scheme: if req.tls.is_some() { "https" } else { "http" },
            document_root: &root_str,
            upstream_cache_status: "",
            custom: &set_vars,
            connection_requests: state.requests,
            connection_time: state.elapsed_secs(),
            sent: &[],
        };
        let rate = match loc.limit_rate.as_deref() {
            Some(spec) => parse_rate(&vars.expand(spec)),
            None => match set_vars.get("limit_rate") {
                Some(v) => parse_rate(v),
                None => 0,
            },
        };
        conn.begin_response(rate, loc.limit_rate_after);
    }

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

    // ---- WebDAV ----
    // nginx's `ngx_http_dav_module` sits between the static handler (which
    // declines every method but GET/HEAD/POST) and the upstream modules, so a
    // location with both `dav_methods` and `proxy_pass` answers a PUT here.
    if loc.dav_methods != 0 {
        let max = http.client_max_body_size as usize;
        if let Some(mut resp) = crate::dav::handle(conn, req, path, loc, max).await? {
            let mut dav_vars = set_vars.clone();
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
                &mut dav_vars,
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
            crate::fastcgi::handle(conn, req, path, query, loc, http, server.server_tokens).await?
        {
            return Ok(o);
        }
    }

    // ---- uwsgi / scgi ----
    if loc.uwsgi_pass.is_some() {
        // `*_ssl_certificate` and friends are complex values, so the uwsgi
        // handler needs the same variable view the other upstreams get.
        let uwsgi_vars = ServerVars {
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
        if let Some(o) = crate::uwsgi_scgi::handle_uwsgi(
            conn,
            req,
            path,
            query,
            loc,
            server.server_tokens,
            &uwsgi_vars,
        )
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
        let (reject, limit_status) =
            check_limits(loc, http, &limit_vars, guards, conn.raw_fd()).await;
        for (name, value) in limit_status {
            set_vars.insert(name.to_string(), value.to_string());
        }
        if let Some(mut reject) = reject {
            // `add_header` is a header filter, so nginx emits its headers on
            // the 503 the limit modules produce (`limit_req_dry_run.t` checks
            // `X-Status: REJECTED` on that very response). This path writes
            // before `finalize_response`, so apply them here.
            let root = loc.root.to_string_lossy().to_string();
            let header_vars = ServerVars {
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
            crate::http::apply_add_headers_ctx(
                &mut reject.raw,
                &loc.headers,
                reject.status,
                "",
                "",
                &[],
                Some(&header_vars),
                "",
            );
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
    // A body filter that needs the whole entity forces the buffered fetcher.
    // Without this, `sub_filter` on a proxied location was silently skipped:
    // the streaming path writes the upstream body straight to the socket.
    // WebSocket upgrades stay on the streaming path (the filter has no
    // meaning for a 101 tunnel).
    let has_sub_filter = !loc.sub_filters.is_empty() || !loc.sub_filter_inherited.is_empty();
    let upgrade = req.headers.get("upgrade").is_some();
    // `charset` is a header *and* body filter. The header half can run on a
    // streamed reply, but the body half cannot, so a location that converts
    // takes the buffered path -- nginx likewise cannot recode while streaming.
    let charset_active = !matches!(loc.charset, crate::config::CharsetSpec::Off);
    let wants_buffered = loc.ssi
        || (has_sub_filter && !upgrade)
        || (charset_active && !upgrade)
        || (loc.gzip && crate::gzip::accepts_gzip(req) && loc.proxy_cache.is_none());
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
            uri_rewritten,
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
    let resp = if loc.ssi && resp.status == 200 && req.method != Method::Head {
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
    // `sub_filter` is a body filter like SSI, so it sees what SSI produced.
    // nginx skips it for non-200 replies and for HEAD (no body to rewrite).
    let resp = if (!loc.sub_filters.is_empty() || !loc.sub_filter_inherited.is_empty())
        && resp.status == 200
        && req.method != Method::Head
    {
        apply_sub_filter(resp, loc, &vars)
    } else {
        resp
    };
    // `charset` runs last in the header-filter chain: nginx installs it as the
    // top header filter, so it sees whatever SSI/sub_filter produced.
    let resp = if !matches!(loc.charset, crate::config::CharsetSpec::Off)
        || !matches!(loc.source_charset, crate::config::CharsetSpec::Off)
    {
        apply_charset(resp, loc, http, &vars)
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
///
/// Public because `ngx_http_header_filter` applies it to *any* `Location`
/// starting with `/` -- the DAV module's 201 included, which is what `dav.t`
/// checks with `absolute_redirect off`.
pub fn absolute_location(
    req: &Request,
    loc: &LocCfg,
    raw_location: &str,
    listen_port: u16,
    local_addr: &str,
) -> String {
    redirect_location(req, loc, raw_location, listen_port, local_addr)
}

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

        headers_finalized: false,
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
        // `disable_symlinks` refuses the open, and try_files moves on to the
        // next candidate -- `/try_on/try` is such a case: the symlink is
        // rejected and `$uri.html` answers.
        if static_file::symlinks_disallowed(&fs_path, loc, &loc.root) {
            continue;
        }
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

        headers_finalized: false,
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
    let prof_write = crate::prof::start();
    let r = write_response_inner(conn, resp, keepalive, tokens, head_only, keepalive_header).await;
    crate::prof::record(3, prof_write);
    r
}

async fn write_response_inner(
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
        headers_finalized: _,
        body,
    } = resp;

    // nginx's `return 444`: close the connection without sending anything.
    // Surfaced as an error so the connection loop drops the socket, exactly
    // like `ngx_http_special_response_handler(NGX_HTTP_REQUEST_TIMEOUT/444)`.
    if status == 444 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "444 close",
        ));
    }

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

    // `$bytes_sent` counts the whole response; the body length that this
    // function returns feeds `$body_bytes_sent` instead.
    let mut total_sent: u64 = 0;
    let result = match body {
        Body::Empty => {
            if chunked {
                out.extend_from_slice(b"0\r\n");
                push_trailers(&mut out, &trailers);
            }
            let n = out.len() as u64;
            let r = conn.write_all(&out).await.map(|_| 0);
            if r.is_ok() {
                total_sent = n;
            }
            r
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
                let n = out.len() as u64;
                let r = conn.write_all(&out).await.map(|_| b.len() as u64);
                if r.is_ok() {
                    total_sent = n;
                }
                r
            } else {
                out.extend_from_slice(&b);
                let n = out.len() as u64;
                let r = conn.write_all(&out).await.map(|_| b.len() as u64);
                if r.is_ok() {
                    total_sent = n;
                }
                r
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
            let head_len = out.len() as u64;
            if conn.tcp_nopush {
                conn.set_cork(true);
                let w = conn.write_all(&out).await;
                if w.is_err() {
                    conn.set_cork(false);
                    w.map(|_| 0)
                } else {
                    let sent = conn.send_file(&file, offset, len).await;
                    conn.set_cork(false);
                    if sent.is_ok() {
                        total_sent = head_len + len;
                    }
                    sent
                }
            } else if let Err(e) = conn.write_all(&out).await {
                Err(e)
            } else {
                let sent = conn.send_file(&file, offset, len).await;
                if sent.is_ok() {
                    total_sent = head_len + len;
                }
                sent
            }
        }
    };

    out.clear();
    conn.out = out;
    if result.is_ok() {
        conn.last_bytes_sent = total_sent;
    }
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

/// Apply `sub_filter` to a buffered response.
///
/// The filter needs the whole body, so a streamed body is collected first; that
/// is also what nginx's buffering does by default (`sub_filter_buffering on`).
fn apply_sub_filter(mut resp: Response, loc: &LocCfg, vars: &ServerVars<'_>) -> Response {
    let ctype = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| {
            // Static responses carry their headers pre-rendered in `raw`.
            split_head(&resp.raw)
                .into_iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v)
                .unwrap_or_default()
        });
    // Both operands are complex values: `sub_filter X$arg_a _replaced`.
    let filters = crate::http::small::SubFilters {
        once: loc.sub_filter_once,
        types: loc.sub_filter_types.clone(),
        // Own rules first, inherited ones after — nginx's merge order.
        pairs: loc
            .sub_filters
            .iter()
            .chain(loc.sub_filter_inherited.iter())
            .map(|(a, b)| (vars.expand(a), vars.expand(b)))
            .collect(),
    };
    if filters.pairs.is_empty() {
        return resp;
    }
    // A file-backed body has to be read in: the filter needs the whole entity.
    let body = match std::mem::replace(&mut resp.body, Body::Empty) {
        Body::Bytes(b) => b,
        Body::Empty => Vec::new(),
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
    if !filters.eligible(&ctype, body.len()) {
        resp.body = Body::Bytes(body);
        return resp;
    }
    // The filter is installed, so its header effects apply even when no pattern
    // matched (`ngx_http_sub_header_filter` runs before any body is seen):
    // nginx clears `Content-Length` and `Accept-Ranges` for a main request and
    // either drops both validators or -- with `sub_filter_last_modified on` --
    // keeps `Last-Modified` and weakens the ETag, because the entity is no
    // longer byte-identical to the origin's.
    if loc.sub_filter_last_modified {
        weaken_etag(&mut resp);
    } else {
        strip_header(&mut resp, "ETag");
        strip_header(&mut resp, "Last-Modified");
    }
    strip_header(&mut resp, "Accept-Ranges");
    // nginx clears the length and streams the reply, so its wire form is
    // chunked. We have the whole body here and re-emit an exact Content-Length
    // instead -- but the upstream's own copy must go, or the client sees the
    // header twice.
    strip_header(&mut resp, "Content-Length");
    resp.explicit_len = false;
    resp.body = Body::Bytes(filters.apply(&body, &ctype).unwrap_or(body));
    resp
}

/// `ngx_http_charset_header_filter` + body filter.
fn apply_charset(
    mut resp: Response,
    loc: &LocCfg,
    http: &Http,
    vars: &ServerVars<'_>,
) -> Response {
    let ctype = header_value(&resp, "content-type").unwrap_or_default();
    let has_encoding = header_value(&resp, "content-encoding")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let decision = crate::charset::decide(
        &http.charsets,
        &ctype,
        has_encoding,
        &loc.charset,
        &loc.source_charset,
        loc.charset_types.as_deref(),
        loc.override_charset,
        // `charset $arg_c`: the escape hatch is the same expander every other
        // complex value in this location uses.
        |name| Some(vars.expand(&format!("${name}"))),
    );
    match decision {
        crate::charset::Decision::Skip => resp,
        crate::charset::Decision::Declare(name) => {
            set_charset_param(&mut resp, &name);
            resp
        }
        crate::charset::Decision::Recode(name, map, reverse) => {
            // The declared direction is (map.src -> map.dst); a reverse request
            // swaps which side is utf-8 as well.
            let (src_utf8, dst_utf8) = if reverse {
                (
                    http.charsets.names[map.dst].utf8,
                    http.charsets.names[map.src].utf8,
                )
            } else {
                (
                    http.charsets.names[map.src].utf8,
                    http.charsets.names[map.dst].utf8,
                )
            };
            // The entity is no longer byte-identical to the origin's.
            let body = take_body(&mut resp);
            let recoded = crate::charset::recode(&body, &map, src_utf8, dst_utf8, reverse);
            set_charset_param(&mut resp, &name);
            if recoded.len() != body.len() || src_utf8 || dst_utf8 {
                // nginx clears the length for a main request whenever a utf-8
                // side is involved, and re-emits an exact length here either
                // way; the upstream's copy has to go regardless.
                strip_header(&mut resp, "Content-Length");
                resp.explicit_len = false;
            } else {
                strip_header(&mut resp, "Content-Length");
                resp.explicit_len = false;
            }
            resp.body = Body::Bytes(recoded);
            resp
        }
    }
}

/// Read a header from `resp`, whether it is dynamic or pre-rendered.
fn header_value(resp: &Response, name: &str) -> Option<String> {
    if let Some((_, v)) = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        return Some(v.clone());
    }
    split_head(&resp.raw)
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// Append `; charset=<name>` to the response's Content-Type.
///
/// The header may live in `headers` (built dynamically) or be pre-rendered in
/// `raw` (the static fast path). Both are handled, and never both at once: a
/// second `Content-Type` line would be emitted otherwise.
fn set_charset_param(resp: &mut Response, name: &str) {
    let Some(ct) = header_value(resp, "content-type") else {
        return;
    };
    // nginx rewrites the parameter list, so an existing `charset=` is replaced
    // rather than duplicated.
    let media = crate::charset::split_content_type(&ct).0.to_string();
    let updated = format!("{media}; charset={name}");

    for (k, v) in resp.headers.iter_mut() {
        if k.eq_ignore_ascii_case("content-type") {
            *v = updated.clone();
            return;
        }
    }

    // Pre-rendered head: replace that one line, keep every other byte.
    let mut out = Vec::with_capacity(resp.raw.len() + updated.len());
    let mut replaced = false;
    for line in split_head(&resp.raw) {
        let (k, v) = line;
        if !replaced && k.eq_ignore_ascii_case("content-type") {
            out.extend_from_slice(format!("Content-Type: {updated}\r\n").as_bytes());
            replaced = true;
        } else {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
    }
    if replaced {
        // `split_head` yields only headers; re-attach the body untouched.
        let tail = find_crlfcrlf(&resp.raw)
            .map(|p| resp.raw[p + 4..].to_vec())
            .unwrap_or_default();
        out.extend_from_slice(&tail);
        resp.raw = out;
    } else {
        resp.headers.push(("Content-Type".to_string(), updated));
    }
}

fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Take the response body out, materialising a file into memory.
fn take_body(resp: &mut Response) -> Vec<u8> {
    match std::mem::replace(&mut resp.body, Body::Empty) {
        Body::Empty => Vec::new(),
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
    }
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
/// `ETag: "x"` -> `ETag: W/"x"`, in whichever representation holds it.
fn weaken_etag(resp: &mut Response) {
    for (k, v) in resp.headers.iter_mut() {
        if k.eq_ignore_ascii_case("etag") && !v.starts_with("W/") {
            *v = format!("W/{v}");
        }
    }
    let raw = std::mem::take(&mut resp.raw);
    let mut out = Vec::with_capacity(raw.len() + 4);
    let mut start = 0usize;
    while start < raw.len() {
        let end = match memchr::memchr(b'\n', &raw[start..]) {
            Some(p) => start + p + 1,
            None => raw.len(),
        };
        let line = &raw[start..end];
        let is_etag = line.len() > 5 && line[..5].eq_ignore_ascii_case(b"ETag:") && line[5] == b' ';
        if is_etag && !line[6..].starts_with(b"W/") {
            out.extend_from_slice(b"ETag: W/");
            out.extend_from_slice(&line[6..]);
        } else {
            out.extend_from_slice(line);
        }
        start = end;
    }
    resp.raw = out;
}

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
    elapsed: Duration,
    // `$request_length`: the head bytes as received plus the body.
    request_length: u64,
    // `$bytes_sent`: the whole response, head included.
    bytes_sent: u64,
    // `$pipe`: `p` when this request was already buffered behind another on the
    // same connection, `.` otherwise.
    pipelined: bool,
    // `open_log_file_cache` from this request's location, resolved at write
    // time because directive order in the block must not matter.
    file_cache: crate::config::OpenFileCache,
    // `$remote_addr` / `$remote_port` as `real_ip_*` left them; the raw socket
    // address is only the starting point.
    remote: (&str, &str),
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
    // nginx's log writer prints `-` when a variable is *not found*, which is the
    // case for `$http_referer` / `$http_user_agent` when the header is absent —
    // a header that is present but empty prints as "". Keeping `None` here and
    // leaving such names out of the table is what produces `"-" "-"` in the
    // combined format (`access_log.t`, "default log format").
    let referer_opt = req.headers.get("referer");
    let ua_opt = req.headers.get("user-agent");
    let server_name = server.names.first().map(|s| s.as_str()).unwrap_or("");
    let peer = remote.0.to_string();
    let peer_port = remote.1.to_string();
    // `$server_addr` is the socket's local address; nginx falls back to the
    // configured listen address when the socket has none.
    let server_addr = group.addr.ip().to_string();
    let request_length_s = request_length.to_string();
    let bytes_sent_s = bytes_sent.to_string();
    // `$request_time` is seconds with millisecond precision.
    let request_time_s = format!("{:.3}", elapsed.as_secs_f64());
    // `$msec`: the current time with milliseconds (`now` is whole seconds, so
    // the sub-second part comes from the wall clock here).
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let msec_s = format!("{}.{:03}", wall.as_secs(), wall.subsec_millis());
    // `$time_iso8601`: local time with the numeric offset.
    let iso8601_s = util::iso8601_time(now);
    // `$binary_remote_addr`: the packed address bytes, escaped by the writer.
    let binary_remote_addr = match remote.0.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.octets().iter().map(|b| *b as char).collect(),
        Ok(std::net::IpAddr::V6(v6)) => v6.octets().iter().map(|b| *b as char).collect(),
        Err(_) => String::new(),
    };

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
    let t_addr = crate::timing::variable("upstream_addr").unwrap_or_default();
    let t_upstatus = crate::timing::variable("upstream_status").unwrap_or_default();
    let scheme = if req.tls.is_some() { "https" } else { "http" };
    let xff = req.headers.get("x-forwarded-for").unwrap_or("").to_string();

    let mut vars: Vec<(&str, &str)> = vec![
        ("remote_addr", &peer),
        ("remote_port", &peer_port),
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

        ("host", host),
        ("server_name", server_name),
        ("server_port", &port_s),
        ("scheme", scheme),
        ("upstream_connect_time", &t_connect),
        ("upstream_header_time", &t_header),
        ("upstream_response_time", &t_response),
        ("upstream_addr", &t_addr),
        ("upstream_status", &t_upstatus),
        ("request_id", &req.request_id),
        ("server_addr", &server_addr),
        ("bytes_sent", &bytes_sent_s),
        ("request_length", &request_length_s),
        ("request_time", &request_time_s),
        ("msec", &msec_s),
        ("time_iso8601", &iso8601_s),
        ("pipe", if pipelined { "p" } else { "." }),
        ("binary_remote_addr", &binary_remote_addr),
        // `$http_*` arrive from the request's own view so a header that is
        // absent renders as `-` (nginx's not-found rule) while one that is
        // present but empty renders as "".
        ("http_x_forwarded_for", &xff),
    ];
    // Absent headers become not-found, which the expander renders as `-`.
    if let Some(v) = referer_opt {
        vars.push(("http_referer", v));
    }
    if let Some(v) = ua_opt {
        vars.push(("http_user_agent", v));
    }
    vars.extend(sent_refs);

    // `$arg_*` and every `$http_*` are ordinary variables in a `log_format` (and
    // in an `access_log ... if=` condition), so they have to be in the table.
    let mut extra: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        extra.push((format!("arg_{}", k.to_ascii_lowercase()), v.to_string()));
    }
    for (k, v) in req.headers.iter() {
        extra.push((
            format!("http_{}", k.to_ascii_lowercase().replace('-', "_")),
            v.to_string(),
        ));
    }
    for (k, v) in &extra {
        if !vars.iter().any(|(n, _)| n == k) {
            vars.push((k.as_str(), v.as_str()));
        }
    }

    let vars = &vars[..];

    for log in logs {
        // `if=<value>`: write only when the expanded value is neither empty nor
        // "0" (`ngx_http_log_module`). The value is a complex value, so
        // `if=$arg_logme$arg_logmetoo` concatenates two variables.
        if let Some(cond) = &log.if_cond {
            // A complex value: absent variables are empty, not `-`.
            let expanded = if cond.contains('$') {
                expand_log_full(cond, vars, now, crate::config::Escape::None, "")
            } else {
                cond.clone()
            };
            // The expander renders unresolved names as "-", but nginx compares
            // the *value*; an absent variable therefore means "do not log".
            if expanded.is_empty() || expanded == "0" {
                continue;
            }
        }
        let line = expand_log_escaped(
            &log.format,
            vars,
            now,
            log.escape.unwrap_or_default(),
        );
        // A path with `$` is a complex value: `varlog_${arg_logname}` names a
        // file per request.
        let path = match &log.path_template {
            Some(tmpl) => {
                let name = expand_log(tmpl, vars, now);
                match path_prefix_of(&log.path, tmpl) {
                    Some(dir) => dir.join(name.rsplit('/').next().unwrap_or(&name)),
                    None => log.path.clone(),
                }
            }
            None => log.path.clone(),
        };
        ctx.logger.access_cached(&path, line, file_cache);
    }
}

/// The directory part of a template path, so a raw `$` value cannot escape it.
fn path_prefix_of(resolved: &std::path::Path, tmpl: &str) -> Option<std::path::PathBuf> {
    let slash = tmpl.rfind('/')?;
    let _ = resolved;
    Some(std::path::PathBuf::from(&tmpl[..slash]))
}

/// `access_log ... escape=`: nginx escapes `"`, `\` and every byte below 0x20.
fn escape_log_value(line: &str, mode: crate::config::Escape) -> String {
    use crate::config::Escape;
    if mode == Escape::None {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len() + 8);
    for b in line.bytes() {
        match mode {
            Escape::Json => match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                0x08 => out.push_str("\\b"),
                0x0c => out.push_str("\\f"),
                b if b < 0x20 => out.push_str(&format!("\\u{:04X}", b)),
                b => out.push(b as char),
            },
            // nginx's default table escapes 0x00-0x1F, `"` (0x22), `\` (0x5C)
            // and 0x7F as `\xXX` -- it does **not** use `\"` or `\\`
            // (`access_log.t`, "escape - default").
            _ => match b {
                b if b < 0x20 || b == 0x7f || b == b'"' || b == b'\\' => {
                    out.push_str(&format!("\\x{:02X}", b))
                }
                b => out.push(b as char),
            },
        }
    }
    out
}

/// nginx's built-in `combined` format, used whenever `access_log` names no
/// format. Without it the literal word `combined` was written to the log.
pub const COMBINED: &str = "$remote_addr - $remote_user [$time_local] \"$request\" \
$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

pub(crate) fn expand_log(fmt: &str, vars: &[(&str, &str)], now: i64) -> String {
    expand_log_full(fmt, vars, now, crate::config::Escape::None, "-")
}

/// `expand_log` with `access_log ... escape=` applied to each **substituted
/// value**.
///
/// nginx escapes the value, not the format: the quotes a `log_format` writes
/// literally stay quotes, which is exactly what the first `access_log.t`
/// assertion checks.
pub(crate) fn expand_log_escaped(
    fmt: &str,
    vars: &[(&str, &str)],
    now: i64,
    escape: crate::config::Escape,
) -> String {
    // The default mode prints `-` for a variable it cannot resolve; `none` and
    // `json` use nginx's unescaped ops, which write nothing at all
    // (`access_log.t`, "escape - none" vs "escape - default").
    let missing = match escape {
        crate::config::Escape::Default => "-",
        _ => "",
    };
    expand_log_full(fmt, vars, now, escape, missing)
}

/// The shared expander.
///
/// `missing` is what an unresolved name renders as: `-` in a log line, but the
/// empty string when the text is a **complex value** being evaluated -- an
/// `access_log ... if=$a$b` with both absent concatenates two empties, it does
/// not produce `--`.
pub(crate) fn expand_log_full(
    fmt: &str,
    vars: &[(&str, &str)],
    now: i64,
    escape: crate::config::Escape,
    missing: &str,
) -> String {
    let fmt = if fmt == "combined" { COMBINED } else { fmt };
    let mut out = String::with_capacity(fmt.len() + 64);
    let bytes = fmt.as_bytes();
    let mut i = 0;
    let time_local = util::log_time(now);
    while i < bytes.len() {
        if bytes[i] == b'$' {
            // `${name}`: the braced spelling, needed when the name is followed
            // by more identifier characters (`varlog_${arg_logname}`, and
            // `index ${server_name}.html` in the rewrite module).
            if bytes.get(i + 1) == Some(&b'{') {
                if let Some(close) = fmt[i + 2..].find('}') {
                    let name = &fmt[i + 2..i + 2 + close];
                    let val = vars.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
                    match val {
                        Some(v) if name == "time_local" => {
                            out.push_str(&escape_log_value(&time_local, escape))
                        }
                        Some(v) => out.push_str(&escape_log_value(v, escape)),
                        None => out.push_str(missing),
                    }
                    i += 1 + 1 + close + 1;
                    continue;
                }
            }
            // Longest match that ends on a name boundary. Matching a prefix in
            // list order silently split `$request_id` into `$request` + "_id",
            // which is exactly what `request_id.t` caught: the log line read
            // `GET /log HTTP/1.0_id`.
            let mut best: Option<(&str, &str)> = None;
            for (name, val) in vars {
                if !bytes[i + 1..].starts_with(name.as_bytes()) {
                    continue;
                }
                let end = i + 1 + name.len();
                // A name may not be followed by more identifier characters.
                if let Some(next) = bytes.get(end) {
                    if next.is_ascii_alphanumeric() || *next == b'_' {
                        continue;
                    }
                }
                if best.map_or(true, |(b, _)| name.len() > b.len()) {
                    best = Some((name, val));
                }
            }
            if let Some((name, val)) = best {
                if name == "time_local" {
                    out.push_str(&escape_log_value(&time_local, escape));
                } else {
                    out.push_str(&escape_log_value(val, escape));
                }
                i += 1 + name.len();
                continue;
            }
            // nginx logs "-" for a variable it cannot resolve.
            let rest = &fmt[i + 1..];
            let n = rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            if n > 0 {
                out.push_str(missing);
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

/// Absolutise a relative `Location` that is still an unrendered header entry.
///
/// `ngx_http_header_filter` rewrites the value whatever its protocol, so a
/// location that has not been rendered yet must be fixed up too; otherwise the
/// HTTP/2 path -- which never goes through `write_redirect` -- sends it relative.
pub fn absolutize_location_field(
    resp: &mut Response,
    req: &Request,
    loc: &LocCfg,
    listen_port: u16,
    local_addr: &str,
) {
    if !loc.absolute_redirect {
        return;
    }
    for (k, v) in resp.headers.iter_mut() {
        if !k.eq_ignore_ascii_case("location") || !v.starts_with('/') {
            continue;
        }
        *v = redirect_location(req, loc, v, listen_port, local_addr);
    }
}

/// Absolutise a relative `Location` in a rendered header block, matching
/// nginx's `ngx_http_header_filter`. `Refresh` is left alone: nginx only
/// rewrites the `Location` header this way.
fn absolutize_location(
    raw: &mut Vec<u8>,
    req: &Request,
    loc: &LocCfg,
    listen_port: u16,
    local_addr: &str,
) {
    if !loc.absolute_redirect {
        return;
    }
    let head_end = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i + 2,
        None => return,
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    if !head.to_ascii_lowercase().contains("\r\nlocation:") {
        return;
    }
    let mut out = String::with_capacity(head.len() + 64);
    for line in head.split_inclusive("\r\n") {
        let trimmed = line.trim_end_matches("\r\n");
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("location:") {
            let value = trimmed[9..].trim();
            if let Some(rest) = value.strip_prefix('/') {
                let abs = redirect_location(req, loc, &format!("/{rest}"), listen_port, local_addr);
                out.push_str("Location: ");
                out.push_str(&abs);
                out.push_str("\r\n");
                continue;
            }
        }
        out.push_str(line);
    }
    out.push_str(&String::from_utf8_lossy(&raw[head_end..]));
    *raw = out.into_bytes();
}
