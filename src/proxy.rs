//! Reverse proxy: upstream selection, connection reuse, WebSocket upgrade.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Http, LocCfg, LbMethod, ProxyTarget, Upstream};
use crate::http::request::{Method, Request};
use crate::http::{write_head, Body, Outcome, Response};
use crate::util::reason;

const MAX_PROXY_BODY: usize = 32 * 1024 * 1024;

// ---- per-upstream bookkeeping -------------------------------------------

static RR_COUNTERS: OnceLock<Vec<AtomicUsize>> = OnceLock::new();
static ACTIVE: OnceLock<Vec<Vec<AtomicUsize>>> = OnceLock::new();
static POOL: OnceLock<Mutex<HashMap<(usize, u32), Vec<PooledConn>>>> = OnceLock::new();

pub struct PooledConn {
    stream: TcpStream,
    last_used: Instant,
}

/// Called once after the config is built.
pub fn init(http: &Http) {
    let n = http.upstreams.len();
    let _ = RR_COUNTERS.set((0..n).map(|_| AtomicUsize::new(0)).collect());
    let _ = ACTIVE.set(
        http.upstreams
            .iter()
            .map(|u| (0..u.servers.len()).map(|_| AtomicUsize::new(0)).collect())
            .collect(),
    );
    let _ = POOL.set(Mutex::new(HashMap::new()));
}

fn rr(idx: usize) -> usize {
    RR_COUNTERS
        .get()
        .and_then(|v| v.get(idx))
        .map(|a| a.fetch_add(1, Ordering::Relaxed))
        .unwrap_or(0)
}

fn active_add(idx: usize, sidx: usize, delta: isize) {
    if let Some(v) = ACTIVE.get() {
        if let Some(list) = v.get(idx) {
            if let Some(a) = list.get(sidx) {
                if delta > 0 {
                    a.fetch_add(delta as usize, Ordering::Relaxed);
                } else {
                    a.fetch_sub((-delta) as usize, Ordering::Relaxed);
                }
            }
        }
    }
}

fn pool_key_of(c: &Chosen) -> (usize, u32) {
    match c {
        Chosen::Direct(_, a) => (usize::MAX, a.port() as u32),
        Chosen::Upstream { up, sidx, .. } => (*up, *sidx as u32),
    }
}

fn checkout(key: (usize, u32)) -> Option<TcpStream> {
    let pool = POOL.get()?;
    let mut guard = pool.lock().ok()?;
    let list = guard.get_mut(&key)?;
    while let Some(c) = list.pop() {
        if c.last_used.elapsed() < Duration::from_secs(50) {
            return Some(c.stream);
        }
    }
    None
}

fn checkin(key: (usize, u32), stream: TcpStream, cap: usize) {
    if cap == 0 {
        return;
    }
    if let Some(pool) = POOL.get() {
        if let Ok(mut guard) = pool.lock() {
            let list = guard.entry(key).or_default();
            if list.len() < cap {
                list.push(PooledConn {
                    stream,
                    last_used: Instant::now(),
                });
            }
        }
    }
}

// ---- selection -----------------------------------------------------------

enum Chosen {
    Direct(usize, SocketAddr),
    Upstream {
        up: usize,
        sidx: usize,
        addr: SocketAddr,
        name: String,
    },
}

fn choose(http: &Http, loc: &LocCfg, client_ip: &std::net::IpAddr) -> Option<Vec<Chosen>> {
    let pp = loc.proxy_pass.as_ref()?;
    match &pp.target {
        ProxyTarget::Addr(addr) => Some(vec![Chosen::Direct(0, *addr)]),
        ProxyTarget::Upstream(idx) => {
            let up = http.upstreams.get(*idx)?;
            let order = select_order(up, *idx, client_ip)?;
            Some(
                order
                    .into_iter()
                    .map(|sidx| {
                        let s = &up.servers[sidx];
                        Chosen::Upstream {
                            up: *idx,
                            sidx,
                            addr: s.addr,
                            name: s.name.clone(),
                        }
                    })
                    .collect(),
            )
        }
    }
}

fn select_order(up: &Upstream, idx: usize, client_ip: &std::net::IpAddr) -> Option<Vec<usize>> {
    let live: Vec<usize> = up
        .servers
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.down && !s.backup)
        .map(|(i, _)| i)
        .collect();
    let mut pool = if live.is_empty() {
        up.servers
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.down)
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    } else {
        live
    };
    if pool.is_empty() {
        return None;
    }

    match up.method {
        LbMethod::RoundRobin => {
            let start = rr(idx) % pool.len();
            pool.rotate_left(start);
        }
        LbMethod::LeastConn => {
            let act = ACTIVE.get();
            pool.sort_by_key(|&i| {
                act.and_then(|v| v.get(idx))
                    .and_then(|l| l.get(i))
                    .map(|a| a.load(Ordering::Relaxed))
                    .unwrap_or(0)
            });
        }
        LbMethod::IpHash => {
            // nginx hashes the first three octets of IPv4.
            let h = match client_ip {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    (o[0] as u64) << 16 | (o[1] as u64) << 8 | o[2] as u64
                }
                std::net::IpAddr::V6(v6) => {
                    let o = v6.octets();
                    (0..16).fold(0u64, |acc, i| acc.wrapping_mul(31).wrapping_add(o[i] as u64))
                }
            };
            let start = (h as usize) % pool.len();
            pool.rotate_left(start);
        }
    }
    Some(pool)
}

// ---- request building ----------------------------------------------------

/// Subset of nginx variables usable in `proxy_set_header`.
struct Vars<'a> {
    req: &'a Request,
    peer_ip: &'a str,
    scheme: &'a str,
    host: &'a str,
    uri: &'a str,
    args: &'a str,
    server_port: u16,
}

fn expand(spec: &str, v: &Vars<'_>) -> String {
    let mut out = String::with_capacity(spec.len() + 32);
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        let rest = &spec[i + 1..];
        // longest variable name made of [a-z0-9_]
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
        let value: Option<String> = match name {
            "remote_addr" => Some(v.peer_ip.to_string()),
            "scheme" => Some(v.scheme.to_string()),
            "host" | "http_host" | "server_name" => Some(v.host.to_string()),
            "uri" | "document_uri" => Some(v.uri.to_string()),
            "args" | "query_string" => Some(v.args.to_string()),
            "request_uri" => Some(v.req.raw_target.clone()),
            "request_method" => Some(v.req.method.as_str().to_string()),
            "server_port" => Some(v.server_port.to_string()),
            "proxy_add_x_forwarded_for" => {
                let prior = v.req.headers.get("x-forwarded-for").unwrap_or("");
                Some(if prior.is_empty() {
                    v.peer_ip.to_string()
                } else {
                    format!("{prior}, {}", v.peer_ip)
                })
            }
            "proxy_host" => Some(v.host.to_string()),
            "is_args" => Some(if v.args.is_empty() { "" } else { "?" }.to_string()),
            _ => {
                if let Some(h) = name.strip_prefix("http_") {
                    let key = h.replace('_', "-");
                    Some(v.req.headers.get(&key).unwrap_or("").to_string())
                } else {
                    None
                }
            }
        };
        match value {
            Some(val) => {
                out.push_str(&val);
                i += 1 + name_len;
            }
            None => {
                // unknown variable: keep it verbatim (nginx would refuse to start)
                out.push('$');
                i += 1;
            }
        }
    }
    out
}

fn upstream_target(path: &str, query: &str, loc: &LocCfg, pp: &crate::config::ProxyPass) -> String {
    let mut target = match &pp.uri {
        Some(prefix) => {
            let cut = loc.prefix_len.min(path.len());
            let rest = &path[cut..];
            if prefix.ends_with('/') && rest.starts_with('/') {
                format!("{}{}", prefix, &rest[1..])
            } else {
                format!("{prefix}{rest}")
            }
        }
        None => path.to_string(),
    };
    if !query.is_empty() {
        target.push('?');
        target.push_str(query);
    }
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    target
}

struct Head {
    status: u16,
    /// Header lines exactly as received (CRLF terminated, hop-by-hop removed).
    raw: Vec<u8>,
    chunked: bool,
    content_length: Option<u64>,
    keepalive: bool,
    upgrade: Option<(String, String)>,
}

fn parse_upstream_head(buf: &[u8]) -> Option<Head> {
    let end = memchr::memmem::find(buf, b"\r\n\r\n")?;
    let head = &buf[..end];
    let mut lines = head.split(|b| *b == b'\n');
    let status_line = lines.next()?;
    let mut parts = status_line.split(|b| *b == b' ');
    let _ver = parts.next()?;
    let code = parts.next()?;
    let status: u16 = std::str::from_utf8(code).ok()?.trim().parse().ok()?;

    let mut raw = Vec::with_capacity(head.len());
    let mut chunked = false;
    let mut content_length = None;
    let mut conn_close = false;
    let mut conn_keepalive = false;
    let mut upgrade = None;
    let mut have_upgrade_conn = false;

    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = match memchr::memchr(b':', line) {
            Some(c) => c,
            None => continue,
        };
        let name = &line[..colon];
        let value = String::from_utf8_lossy(&line[colon + 1..]).trim().to_string();
        let lname = String::from_utf8_lossy(name).to_ascii_lowercase();

        match lname.as_str() {
            "connection" => {
                for tok in value.split(',') {
                    let t = tok.trim();
                    if t.eq_ignore_ascii_case("close") {
                        conn_close = true;
                    } else if t.eq_ignore_ascii_case("keep-alive") {
                        conn_keepalive = true;
                    } else if t.eq_ignore_ascii_case("upgrade") {
                        have_upgrade_conn = true;
                    }
                }
            }
            "transfer-encoding" => {
                if value.to_ascii_lowercase().contains("chunked") {
                    // Re-emit the header: the body is forwarded still chunked,
                    // so the client needs it to delimit the message.
                    chunked = true;
                    raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                }
            }
            "content-length" => {
                content_length = value.parse::<u64>().ok();
            }
            "server" | "date" | "x-pad" | "keep-alive" => {}
            "upgrade" => {
                upgrade = Some((value.clone(), String::new()));
            }
            _ => {
                raw.extend_from_slice(name);
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(value.as_bytes());
                raw.extend_from_slice(b"\r\n");
            }
        }
    }

    if let Some((v, _)) = upgrade.take() {
        if have_upgrade_conn {
            upgrade = Some((v, String::new()));
        }
    }

    Some(Head {
        status,
        raw,
        chunked,
        content_length,
        keepalive: !conn_close || conn_keepalive,
        upgrade,
    })
}

// ---- main entry ----------------------------------------------------------

/// Returns `None` when this location does not proxy.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    conn: &mut crate::conn::Conn,
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    http: &Http,
    tokens: bool,
) -> io::Result<Option<Outcome>> {
    let pp = match &loc.proxy_pass {
        Some(p) => p.clone(),
        None => return Ok(None),
    };
    let _ = http;

    let peer_ip = conn.peer.ip();
    let Some(candidates) = choose(http, loc, &peer_ip) else {
        return Ok(Some(respond_error(conn, 502, tokens, req.keepalive).await?));
    };

    // Request body (buffered; the static path never needs it).
    let body = if req.chunked {
        conn.take_chunked_body(MAX_PROXY_BODY).await?
    } else if req.body_len > 0 {
        conn.take_body(req.body_len as usize).await?
    } else {
        Vec::new()
    };

    let target_uri = upstream_target(path, query, loc, &pp);
    let is_upgrade = req
        .headers
        .get("upgrade")
        .map(|u| !u.is_empty())
        .unwrap_or(false);

    // ---- proxy_cache: serve a fresh hit without touching the upstream ----
    let zone = loc
        .proxy_cache
        .as_ref()
        .and_then(|name| http.cache_zones.iter().find(|z| &z.name == name));
    let cache_key = zone.map(|_| {
        let key_spec = loc.proxy_cache_key.as_deref();
        let scheme = "http";
        let proxy_host = &pp.host_header;
        let (uri_only, args_only) = match path.split_once('?') {
            Some((u, a)) => (u.to_string(), a.to_string()),
            None => (path.to_string(), query.to_string()),
        };
        let host = req.host.as_ref().map(|h| h.as_str()).unwrap_or("");
        let remote = conn.peer.ip().to_string();
        match key_spec {
            Some(spec) => crate::cache::expand_key(
                spec,
                scheme,
                proxy_host,
                host,
                &req.raw_target,
                &uri_only,
                &args_only,
                &remote,
                req.method.as_str(),
            ),
            None => crate::cache::default_key(scheme, proxy_host, &req.raw_target),
        }
    });

    let bypass = !loc.proxy_cache_bypass.is_empty()
        && loc
            .proxy_cache_bypass
            .iter()
            .any(|v| !v.is_empty() && !v.starts_with('$'));

    if let (Some(zone), Some(key)) = (zone, cache_key.as_ref()) {
        if !bypass {
            if let Some(entry) = crate::cache::load(zone, key) {
                if entry.is_fresh(crate::cache::now()) {
                    let mut raw = Vec::with_capacity(entry.body.len() + 256);
                    for (k, v) in &entry.headers {
                        raw.extend_from_slice(k.as_bytes());
                        raw.extend_from_slice(b": ");
                        raw.extend_from_slice(v.as_bytes());
                        raw.extend_from_slice(b"\r\n");
                    }
                    crate::http::apply_add_headers(
                        &mut raw,
                        &loc.headers,
                        entry.status,
                        &crate::http::AddHeaderVars {
                            upstream_cache_status: "HIT",
                            scheme: "http",
                            host: req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
                        },
                    );
                    raw.extend_from_slice(b"Content-Length: ");
                    raw.extend_from_slice(entry.body.len().to_string().as_bytes());
                    raw.extend_from_slice(b"\r\n");
                    let resp = Response {
                        status: entry.status,
                        headers: Vec::new(),
                        raw,
                        explicit_len: true,
                        no_error_page: false,
                        body: crate::http::Body::Bytes(entry.body.clone()),
                    };
                    let bytes = crate::http::write_response(
                        conn,
                        resp,
                        req.keepalive,
                        tokens,
                        req.method == Method::Head,
                    )
                    .await?;
                    return Ok(Some(Outcome {
                        status: entry.status,
                        bytes,
                        close: false,
                    }));
                }
            }
        }
    }
    let cache_status = if zone.is_some() {
        if bypass {
            "BYPASS"
        } else {
            "MISS"
        }
    } else {
        ""
    };

    let mut used_pooled = false;
    let mut last_err = None;

    'candidates: for cand in candidates {
        let key = pool_key_of(&cand);
        // First attempt may reuse a pooled socket; if that socket turns out to
        // be dead, retry the same backend once on a fresh connection.
        for attempt in 0..2 {
            let want_pool = attempt == 0;
            let (stream, from_pool, up_idx, sidx) = match &cand {
                Chosen::Direct(_, addr) => {
                    let pooled = if want_pool { checkout(key) } else { None };
                    match pooled {
                        Some(s) => (s, true, usize::MAX, 0),
                        None => match connect_timeout(*addr, loc.proxy_connect_timeout).await {
                            Ok(s) => (s, false, usize::MAX, 0),
                            Err(e) => {
                                last_err = Some(e);
                                continue 'candidates;
                            }
                        },
                    }
                }
                Chosen::Upstream { up, sidx, addr, .. } => {
                    let pooled = if want_pool && http.upstreams[*up].keepalive > 0 {
                        checkout(key)
                    } else {
                        None
                    };
                    match pooled {
                        Some(s) => (s, true, *up, *sidx),
                        None => match connect_timeout(*addr, loc.proxy_connect_timeout).await {
                            Ok(s) => (s, false, *up, *sidx),
                            Err(e) => {
                                last_err = Some(e);
                                continue 'candidates;
                            }
                        },
                    }
                }
            };
            if up_idx != usize::MAX {
                active_add(up_idx, sidx, 1);
            }

            let result = exchange(
                conn,
                req,
                &target_uri,
                &body,
                loc,
                &pp,
                stream,
                from_pool,
                tokens,
                is_upgrade,
                &peer_ip.to_string(),
                key,
                CacheCtx {
                    zone,
                    key: cache_key.as_deref(),
                    status: cache_status,
                },
            )
            .await;

            if up_idx != usize::MAX {
                active_add(up_idx, sidx, -1);
            }

            match result {
                Ok(o) => return Ok(Some(o)),
                Err(e) => {
                    last_err = Some(e);
                    if from_pool {
                        // Stale pooled socket: a request may have partially
                        // reached the upstream, so retry only against the same
                        // backend to stay safe for idempotent requests.
                        if req.method.is_read() {
                            continue;
                        }
                    }
                    continue 'candidates;
                }
            }
        }
    }

    if let Some(e) = &last_err {
        eprintln!("ngxrs: [error] upstream failure for {}: {e}", req.raw_target);
    }
    Ok(Some(respond_error(conn, 502, tokens, req.keepalive).await?))
}

async fn connect_timeout(addr: SocketAddr, dur: Duration) -> io::Result<TcpStream> {
    match tokio::time::timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

async fn respond_error(
    conn: &mut crate::conn::Conn,
    status: u16,
    tokens: bool,
    keepalive: bool,
) -> io::Result<Outcome> {
    let resp = Response::bytes(status, "text/html", crate::http::error_body(status, tokens));
    let bytes = crate::http::write_response(conn, resp, keepalive, tokens, false).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn split_head(raw: &[u8]) -> Vec<(String, String)> {
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

struct CacheCtx<'a> {
    zone: Option<&'a crate::config::CacheZone>,
    key: Option<&'a str>,
    status: &'a str,
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    conn: &mut crate::conn::Conn,
    req: &Request,
    target_uri: &str,
    body: &[u8],
    loc: &LocCfg,
    pp: &crate::config::ProxyPass,
    mut up: TcpStream,
    from_pool: bool,
    tokens: bool,
    is_upgrade: bool,
    peer_ip: &str,
    pool_key: (usize, u32),
    cache: CacheCtx<'_>,
) -> io::Result<Outcome> {
    // ---- request head ----
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(req.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target_uri.as_bytes());
    out.extend_from_slice(if loc.proxy_http_version == 1 {
        b" HTTP/1.1\r\n"
    } else {
        b" HTTP/1.0\r\n"
    });

    let mut set: HashMap<String, String> = HashMap::new();
    for (k, v) in &loc.proxy_set_headers {
        set.insert(k.to_ascii_lowercase(), v.clone());
    }

    let default_host = pp.host_header.clone();
    let (uri_only, args_only) = match target_uri.split_once('?') {
        Some((u, a)) => (u.to_string(), a.to_string()),
        None => (target_uri.to_string(), String::new()),
    };
    let vars = Vars {
        req,
        peer_ip,
        scheme: "http",
        host: &default_host,
        uri: &uri_only,
        args: &args_only,
        server_port: 80,
    };
    let host = set
        .get("host")
        .map(|v| expand(v, &vars))
        .unwrap_or_else(|| default_host.clone());

    let mut wrote: Vec<String> = Vec::new();
    // Host first, like nginx.
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\n");
    wrote.push("host".to_string());

    for (k, v) in req.headers.iter() {
        let lk = k.to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "host" | "connection" | "keep-alive" | "transfer-encoding" | "te" | "trailer"
                | "upgrade" | "proxy-connection" | "content-length" | "expect"
        ) {
            continue;
        }
        if set.contains_key(&lk) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
        wrote.push(lk);
    }

    for (k, v) in &loc.proxy_set_headers {
        let lk = k.to_ascii_lowercase();
        if lk == "host" {
            continue;
        }
        let val = expand(v, &vars);
        if val.is_empty() {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    let user_set_upgrade = loc
        .proxy_set_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("upgrade"));
    if is_upgrade && loc.proxy_http_version == 1 && !user_set_upgrade {
        if let Some(u) = req.headers.get("upgrade") {
            out.extend_from_slice(b"Connection: upgrade\r\nUpgrade: ");
            out.extend_from_slice(u.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    } else if is_upgrade && loc.proxy_http_version == 1 {
        // headers already emitted from proxy_set_header
    } else if loc.proxy_http_version == 1 {
        out.extend_from_slice(b"Connection: ");
        if loc.proxy_set_headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("connection") && v.is_empty()
        }) {
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(b"close\r\n");
        }
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }

    if !body.is_empty() || req.body_len > 0 || req.chunked {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    if std::env::var_os("NGXRS_DEBUG_PROXY").is_some() {
        eprintln!("ngxrs: [debug] upstream request:\n{}", String::from_utf8_lossy(&out));
    }

    if from_pool {
        // A stale pooled socket fails here; caller retries with a fresh one.
        let w = tokio::time::timeout(loc.proxy_send_timeout, up.write_all(&out)).await;
        match w {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "send timeout")),
        }
    } else {
        up.write_all(&out).await?;
    }
    if !body.is_empty() {
        up.write_all(body).await?;
    }
    up.flush().await?;

    // ---- response head ----
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut deadline = Instant::now() + loc.proxy_read_timeout;
    let head = loop {
        if let Some(pos) = memchr::memmem::find(&buf, b"\r\n\r\n") {
            let h = parse_upstream_head(&buf[..pos + 4])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream response"))?;
            let rest = buf.split_off(pos + 4);
            buf = rest;
            break h;
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "upstream head too large"));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
        }
        let mut chunk = [0u8; 8192];
        let n = match tokio::time::timeout(remaining, up.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "upstream closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if deadline.elapsed() > Duration::ZERO {
            deadline = Instant::now() + loc.proxy_read_timeout;
        }
    };

    // 1xx informational responses are forwarded then the real head follows.
    let mut head = head;
    while (100..200).contains(&head.status) && head.status != 101 {
        // nginx forwards 100 Continue to the client; keep it simple and drop it.
        let mut next = Vec::new();
        let rest = buf.clone();
        let pos = memchr::memmem::find(&rest, b"\r\n\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream response"))?;
        next.extend_from_slice(&rest[..pos + 4]);
        buf = rest[pos + 4..].to_vec();
        head = parse_upstream_head(&next)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream response"))?;
    }

    // ---- 101 Switching Protocols: hand the sockets to a bidirectional pipe ----
    if head.status == 101 {
        let mut client_head = Vec::with_capacity(head.raw.len() + 96);
        client_head.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
        client_head.extend_from_slice(&head.raw);
        client_head.extend_from_slice(b"\r\n");
        conn.write_all(&client_head).await?;
        if !buf.is_empty() {
            conn.write_all(&buf).await?;
        }
        conn.pipe_with(up).await?;
        return Ok(Outcome {
            status: 101,
            bytes: 0,
            close: true,
        });
    }

    // ---- body ----
    let total_len = if head.chunked {
        None
    } else {
        head.content_length
    };
    let mut raw = head.raw;
    if let Some(len) = total_len {
        if !raw
            .windows(14)
            .any(|w| w.eq_ignore_ascii_case(b"Content-Length"))
        {
            raw.extend_from_slice(b"Content-Length: ");
            raw.extend_from_slice(len.to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
    }

    // ---- cacheable (length-delimited) responses are buffered first ----
    let cacheable = cache.zone.is_some()
        && cache.key.is_some()
        && !head.chunked
        && total_len.is_some()
        && !is_upgrade
        && matches!(head.status, 200 | 301 | 302 | 304 | 404);
    if cacheable {
        let len = total_len.unwrap_or(0);
        let mut payload = buf;
        while (payload.len() as u64) < len {
            let mut chunk = vec![0u8; (len - payload.len() as u64).min(64 * 1024) as usize];
            let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            payload.extend_from_slice(&chunk[..n]);
        }

        if let (Some(zone), Some(key)) = (cache.zone, cache.key) {
            let stored_headers: Vec<(String, String)> = split_head(&raw)
                .into_iter()
                .filter(|(k, _)| {
                    !k.eq_ignore_ascii_case("connection")
                        && !k.eq_ignore_ascii_case("keep-alive")
                        && !k.eq_ignore_ascii_case("transfer-encoding")
                        && !k.eq_ignore_ascii_case("x-cache-status")
                })
                .collect();
            if let Some(valid) = crate::cache::validity(loc, head.status) {
                let entry = crate::cache::Cached {
                    status: head.status,
                    headers: stored_headers,
                    body: payload.clone(),
                    stored_at: crate::cache::now(),
                    valid_for: valid.as_secs(),
                };
                let _ = crate::cache::store(zone, key, &entry);
            }
        }

        let mut out_raw = raw;
        crate::http::apply_add_headers(
            &mut out_raw,
            &loc.headers,
            head.status,
            &crate::http::AddHeaderVars {
                upstream_cache_status: cache.status,
                scheme: "http",
                host: req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
            },
        );
        write_head(conn, head.status, &out_raw, req.keepalive, tokens).await?;
        conn.write_all(&payload).await?;
        return Ok(Outcome {
            status: head.status,
            bytes: payload.len() as u64,
            close: false,
        });
    }

    let mut raw = raw;
    crate::http::apply_add_headers(
        &mut raw,
        &loc.headers,
        head.status,
        &crate::http::AddHeaderVars {
            upstream_cache_status: cache.status,
            scheme: "http",
            host: req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
        },
    );
    write_head(conn, head.status, &raw, req.keepalive, tokens).await?;

    let mut sent = 0u64;
    if head.chunked {
        sent = stream_chunked(conn, &mut up, buf, loc.proxy_read_timeout).await?;
        if loc.proxy_buffering {
            let _ = reason(200);
        }
    } else if let Some(len) = total_len {
        let mut remaining = len;
        let mut pending = buf;
        loop {
            if remaining == 0 {
                break;
            }
            if !pending.is_empty() {
                let take = (pending.len() as u64).min(remaining) as usize;
                conn.write_all(&pending[..take]).await?;
                sent += take as u64;
                remaining -= take as u64;
                pending.drain(..take);
                continue;
            }
            let mut chunk = vec![0u8; (remaining.min(64 * 1024)) as usize];
            let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            if n == 0 {
                break;
            }
            conn.write_all(&chunk[..n]).await?;
            sent += n as u64;
            remaining -= n as u64;
        }
    } else {
        // no length: read until EOF
        if !buf.is_empty() {
            conn.write_all(&buf).await?;
            sent += buf.len() as u64;
        }
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            conn.write_all(&chunk[..n]).await?;
            sent += n as u64;
        }
    }

    // ---- connection reuse ----
    let reuse = head.keepalive
        && total_len.is_some()
        && !is_upgrade
        && loc.proxy_http_version == 1
        && !req.chunked;
    if reuse {
        // nginx only keeps upstream connections alive; a bare proxy_pass
        // always opens a fresh socket.
        let cap = match pp.target {
            crate::config::ProxyTarget::Upstream(i) => loc_upstream_cap(i, pp).unwrap_or(0),
            _ => 0,
        };
        checkin(pool_key, up, cap);
    }

    Ok(Outcome {
        status: head.status,
        bytes: sent,
        close: false,
    })
}

fn loc_upstream_cap(idx: usize, _pp: &crate::config::ProxyPass) -> Option<usize> {
    // keepalive is per-upstream; 0 means the directive was absent.
    UPSTREAM_KEEPALIVE
        .get()
        .and_then(|v| v.get(idx).copied())
        .filter(|c| *c > 0)
}

static UPSTREAM_KEEPALIVE: OnceLock<Vec<usize>> = OnceLock::new();

pub fn init_keepalive(http: &Http) {
    let _ = UPSTREAM_KEEPALIVE.set(http.upstreams.iter().map(|u| u.keepalive).collect());
}

async fn stream_chunked(
    conn: &mut crate::conn::Conn,
    up: &mut TcpStream,
    mut pending: Vec<u8>,
    read_timeout: Duration,
) -> io::Result<u64> {
    let mut sent = 0u64;
    loop {
        // ensure a full chunk-size line is buffered
        let line_end = loop {
            if let Some(i) = memchr::memchr(b'\n', &pending) {
                break i;
            }
            let mut chunk = [0u8; 8192];
            let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            if n == 0 {
                return Ok(sent);
            }
            pending.extend_from_slice(&chunk[..n]);
        };
        let line = String::from_utf8_lossy(&pending[..line_end]).trim().to_string();
        let size_hex = line.split(';').next().unwrap_or("").trim().to_string();
        let mut size = u64::from_str_radix(&size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk"))?;

        // need line + payload + CRLF
        let need = line_end + 1 + size as usize + 2;
        while pending.len() < need {
            let mut chunk = [0u8; 8192];
            let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            if n == 0 {
                return Ok(sent);
            }
            pending.extend_from_slice(&chunk[..n]);
        }

        let header_len = line_end + 1;
        if size == 0 {
            // trailers: pass through the terminating CRLF block
            let end = need.min(pending.len());
            conn.write_all(&pending[..end]).await?;
            sent += end as u64;
            return Ok(sent);
        }
        conn.write_all(&pending[..need]).await?;
        sent += need as u64;
        size = 0;
        pending.drain(..need);
    }
}

impl crate::conn::Conn {
    /// Take a Content-Length body into memory (bounded).
    pub async fn take_body(&mut self, len: usize) -> io::Result<Vec<u8>> {
        if len > MAX_PROXY_BODY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        let mut out = Vec::with_capacity(len);
        self.take_into(&mut out, len).await?;
        Ok(out)
    }

    /// Read and de-chunk a chunked body into memory (bounded).
    pub async fn take_chunked_body(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line_pub().await?;
            let size_str = String::from_utf8_lossy(&line)
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let size = u64::from_str_radix(&size_str, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                loop {
                    let l = self.read_line_pub().await?;
                    if l.is_empty() {
                        break;
                    }
                }
                break;
            }
            if out.len() + size as usize > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            self.take_into(&mut out, size as usize).await?;
            let _crlf = self.read_line_pub().await?;
        }
        Ok(out)
    }
}
