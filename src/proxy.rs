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

/// Locate the end of an upstream response head, tolerating LF-only line
/// endings (nginx accepts them, and simple backends emit them).
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut line_start = 0usize;
    while i < buf.len() {
        if buf[i] != b'\n' {
            i += 1;
            continue;
        }
        let mut line_end = i;
        if line_end > line_start && buf[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        let empty = line_end == line_start;
        i += 1;
        if empty && line_start > 0 {
            return Some(i);
        }
        line_start = i;
    }
    None
}

fn parse_upstream_head(buf: &[u8]) -> Option<Head> {
    let end = find_head_end(buf)?;
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
    // nginx's upstream header validation: duplicates and CL/TE conflicts make
    // the whole response invalid (502), not just the offending line.
    let mut seen_cl = false;
    let mut seen_te = false;
    let mut seen_expires = false;
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
                // Duplicate, conflicting with Content-Length, or any coding
                // other than `chunked` invalidates the response.
                if seen_te || seen_cl || !value.eq_ignore_ascii_case("chunked") {
                    return None;
                }
                seen_te = true;
                chunked = true;
                // Re-emit the header: the body is forwarded still chunked,
                // so the client needs it to delimit the message.
                raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            "content-length" => {
                if seen_cl || seen_te {
                    return None;
                }
                seen_cl = true;
                match value.parse::<u64>() {
                    Ok(n) => content_length = Some(n),
                    // `Content-Length: foo` is invalid, not "unknown length".
                    Err(_) => return None,
                }
            }

            "expires" => {
                // A duplicate is logged and ignored: only the first is kept.
                if seen_expires {
                    continue;
                }
                seen_expires = true;
                raw.extend_from_slice(name);
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(value.as_bytes());
                raw.extend_from_slice(b"\r\n");
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
    vars: &crate::http::ServerVars<'_>,
) -> io::Result<Option<Outcome>> {
    let pp = match &loc.proxy_pass {
        Some(p) => p.clone(),
        None => return Ok(None),
    };
    let _ = http;

    let peer_ip = conn.peer.ip();
    let peer_ip_owned = peer_ip.to_string();
    let peer_port = conn.peer.port();
    let Some(candidates) = choose(http, loc, &peer_ip) else {
        return Ok(Some(respond_error(conn, 502, tokens, req.keepalive).await?));
    };

    // `proxy_bind` applies to every candidate connection below.
    let bind = match resolve_bind(
        loc,
        &BindVars {
            peer_ip: &peer_ip_owned,
            peer_port,
            query,
        },
    ) {
        Ok(b) => b,
        Err(()) => {
            crate::log::error_log("error", "invalid proxy_bind value");
            return Ok(Some(respond_error(conn, 500, tokens, req.keepalive).await?));
        }
    };

    // nginx answers `Expect: 100-continue` before reading the body.
    // RFC 7231: never send 100 Continue to an HTTP/1.0 client.
    if req.expect_continue && req.version_minor == 1 {
        conn.send_100_continue().await?;
    }

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
    // `proxy_cache` takes a complex value: `proxy_cache $arg_c;` picks the zone
    // per request. An empty result disables caching, an unknown name is a 500
    // (nginx logs "cache \"%V\" is not found" and fails the request).
    let zone_name = loc.proxy_cache.as_ref().map(|spec| vars.expand(spec));
    if let Some(name) = zone_name.as_deref() {
        if !name.is_empty() && !http.cache_zones.iter().any(|z| z.name == name) {
            crate::log::error_log(
                "error",
                &format!("cache \"{name}\" is not found"),
            );
            let resp = crate::http::error_response(500, http.server_tokens);
            let bytes = crate::http::write_response(
                conn,
                resp,
                req.keepalive,
                tokens,
                req.method == Method::Head,
            )
            .await?;
            return Ok(Some(Outcome {
                status: 500,
                bytes,
                close: false,
                sent: Vec::new(),
            }));
        }
    }
    let zone = zone_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .and_then(|name| http.cache_zones.iter().find(|z| z.name == name));
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

    // Cacheable HEAD requests go upstream as GET (nginx's default).
    let convert_head = req.method == Method::Head
        && loc.proxy_cache_convert_head
        && zone.is_some();

    // nginx: bypass when any value expands to something that is neither empty
    // nor "0".
    let bypass = loc.proxy_cache_bypass.iter().any(|v| {
        let e = vars.expand(v);
        let e = e.trim();
        !e.is_empty() && e != "0"
    });

    // A stored-but-stale entry is reported as EXPIRED (nginx does the same)
    // rather than MISS.
    let mut stale_hit = false;
    if let (Some(zone), Some(key)) = (zone, cache_key.as_ref()) {
        if !bypass {
            if let Some(entry) = crate::cache::load(zone, key) {
                let fresh = entry.is_fresh(crate::cache::now());
                // With `proxy_cache_background_update` nginx serves the stale
                // copy and refreshes it behind the client's back.
                // nginx serves a stale copy only when a background update is
                // allowed *and* `stale-while-revalidate` still covers now.
                let serve_stale = !fresh
                    && loc.proxy_cache_background_update
                    && entry.may_serve_stale(crate::cache::now());
                if !fresh && !serve_stale {
                    stale_hit = true;
                }
                if fresh || serve_stale {
                    let hit_status = if fresh { "HIT" } else { "STALE" };
                    if serve_stale {
                        spawn_background_update(
                            loc,
                            http,
                            req,
                            key.clone(),
                            &conn.peer.ip().to_string(),
                        );
                    }
                    let mut raw = Vec::with_capacity(entry.body.len() + 256);
                    for (k, v) in &entry.headers {
                        raw.extend_from_slice(k.as_bytes());
                        raw.extend_from_slice(b": ");
                        raw.extend_from_slice(v.as_bytes());
                        raw.extend_from_slice(b"\r\n");
                    }
                    crate::http::apply_add_headers_upstream(
                        &mut raw,
                        &loc.headers,
                        entry.status,
                        hit_status,
                        "",
                    );
                    raw.extend_from_slice(b"Content-Length: ");
                    raw.extend_from_slice(entry.body.len().to_string().as_bytes());
                    raw.extend_from_slice(b"\r\n");
                    // A range is served out of the cached body.
                    let mut status = entry.status;
                    let mut body = entry.body.clone();
                    if loc.proxy_force_ranges {
                        let (s2, raw2, body2) =
                            apply_force_ranges(req, loc, status, &mut raw, body);
                        status = s2;
                        raw = raw2;
                        body = body2;
                    }
                    let resp = Response {
                        status,
                        headers: Vec::new(),
                        raw,
                        explicit_len: true,
                        no_error_page: false,
                        trailers: Vec::new(),
                        expect_trailers: false,
                        body: crate::http::Body::Bytes(body),
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
                        status,
                        bytes,
                        close: false,
                        sent: Vec::new(),
                    }));
                }
            }
        }
    }
    // `proxy_cache_lock`: only the first request for a key may populate the
    // cache. Latecomers wait for it to land, then serve the fresh entry.
    // RAII: releases the lock on every exit path.
    struct CacheLock(std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>, String);
    impl Drop for CacheLock {
        fn drop(&mut self) {
            let mut set = self.0.lock().unwrap_or_else(|e| e.into_inner());
            set.remove(&self.1);
        }
    }

    let mut _cache_lock_held: Option<CacheLock> = None;
    if let (Some(z), Some(key), true) = (zone, cache_key.as_ref(), loc.proxy_cache_lock) {
        let deadline = Instant::now() + loc.proxy_cache_lock_timeout;
        loop {
            // Someone else may have filled the entry while we waited.
            if let Some(entry) = crate::cache::load(z, key) {
                if entry.is_fresh(crate::cache::now()) {
                    let mut raw = Vec::with_capacity(entry.body.len() + 256);
                    for (k, v) in &entry.headers {
                        raw.extend_from_slice(k.as_bytes());
                        raw.extend_from_slice(b": ");
                        raw.extend_from_slice(v.as_bytes());
                        raw.extend_from_slice(b"\r\n");
                    }
                    crate::http::apply_add_headers_upstream(
                        &mut raw,
                        &loc.headers,
                        entry.status,
                        "HIT",
                        "",
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
                        trailers: Vec::new(),
                        expect_trailers: false,
                        body: Body::Bytes(entry.body),
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
                        sent: Vec::new(),
                    }));
                }
            }

            let taken = {
                let mut set = z.lock.lock().unwrap_or_else(|e| e.into_inner());
                if set.contains(key) {
                    false
                } else {
                    set.insert(key.clone());
                    true
                }
            };
            if taken {
                _cache_lock_held = Some(CacheLock(z.lock.clone(), key.clone()));
                break;
            }
            if Instant::now() >= deadline {
                // nginx stops waiting and goes to the upstream itself.
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let cache_status = if zone.is_some() {
        if bypass {
            "BYPASS"
        } else if stale_hit {
            "EXPIRED"
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
        let upstream_addr = match &cand {
            Chosen::Direct(_, a) => a.to_string(),
            Chosen::Upstream { addr, .. } => addr.to_string(),
        };
        // First attempt may reuse a pooled socket; if that socket turns out to
        // be dead, retry the same backend once on a fresh connection.
        for attempt in 0..2 {
            let want_pool = attempt == 0;
            let (stream, from_pool, up_idx, sidx) = match &cand {
                Chosen::Direct(_, addr) => {
                    let pooled = if want_pool { checkout(key) } else { None };
                    match pooled {
                        Some(s) => (s, true, usize::MAX, 0),
                        None => match connect_bound(*addr, bind, loc.proxy_connect_timeout).await {
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
                        None => match connect_bound(*addr, bind, loc.proxy_connect_timeout).await {
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
                &peer_ip_owned,
                key,
                CacheCtx {
                    zone,
                    key: cache_key.as_deref(),
                    status: cache_status,
                },
                &upstream_addr,
                vars,
                convert_head,
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
    connect_bound(addr, None, dur).await
}

/// Connect, optionally binding the local (source) address first — nginx's
/// `proxy_bind`.
async fn connect_bound(
    addr: SocketAddr,
    source: Option<SocketAddr>,
    dur: Duration,
) -> io::Result<TcpStream> {
    let Some(src) = source else {
        return match tokio::time::timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                Ok(s)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
        };
    };

    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    sock.bind(&src.into())?;

    // socket2 reports an in-progress connect as WouldBlock/EINPROGRESS.
    let connect = async {
        loop {
            match sock.connect(&addr.into()) {
                Ok(()) => return Ok(()),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::EINPROGRESS) =>
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    };
    match tokio::time::timeout(dur, connect).await {
        Ok(Ok(())) => {
            sock.set_nonblocking(false)?;
            let std_stream: std::net::TcpStream = sock.into();
            let s = TcpStream::from_std(std_stream)?;
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

/// Variables `proxy_bind` may reference.
pub struct BindVars<'a> {
    pub peer_ip: &'a str,
    pub peer_port: u16,
    pub query: &'a str,
}

/// Resolve `proxy_bind` for one request into an address to bind.
pub fn resolve_bind(loc: &LocCfg, vars: &BindVars<'_>) -> Result<Option<SocketAddr>, ()> {
    let Some(spec) = &loc.proxy_bind else {
        return Ok(None);
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let expanded = expand_bind(spec, vars);
    if expanded.is_empty() || expanded.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    parse_bind_addr(&expanded).map(Some).ok_or(())
}

fn expand_bind(spec: &str, vars: &BindVars<'_>) -> String {
    let mut out = String::with_capacity(spec.len() + 16);
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
        match &rest[..n] {
            "remote_addr" => out.push_str(vars.peer_ip),
            "remote_port" => out.push_str(&vars.peer_port.to_string()),
            name => {
                if let Some(want) = name.strip_prefix("arg_") {
                    if let Some((_, v)) = vars
                        .query
                        .split('&')
                        .filter_map(|p| p.split_once('='))
                        .find(|(k, _)| k.eq_ignore_ascii_case(want))
                    {
                        out.push_str(v);
                    }
                }
            }
        }
        i += 1 + n;
    }
    out
}

/// `127.0.0.2`, `127.0.0.2:80`, `[::1]:8080`, `[::1]`.
fn parse_bind_addr(spec: &str) -> Option<SocketAddr> {
    if let Some(rest) = spec.strip_prefix('[') {
        let close = rest.find(']')?;
        let ip: std::net::IpAddr = rest[..close].parse().ok()?;
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            0
        } else {
            after.strip_prefix(':')?.parse().ok()?
        };
        return Some(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, 0));
    }
    let (host, port) = spec.rsplit_once(':')?;
    let ip: std::net::IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, port.parse().ok()?))
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
        sent: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
struct CacheCtx<'a> {
    zone: Option<&'a crate::config::CacheZone>,
    key: Option<&'a str>,
    status: &'a str,
}

/// Serialize the upstream request head exactly as nginx does.
#[allow(clippy::too_many_arguments)]
/// Apply `proxy_cookie_domain` / `proxy_cookie_path` to a response head.
fn apply_cookie_rules(raw: &mut Vec<u8>, loc: &LocCfg, vars: &crate::http::ServerVars<'_>) {
    let domains = loc.proxy_cookie_domains.as_deref().unwrap_or(&[]);
    let paths = loc.proxy_cookie_paths.as_deref().unwrap_or(&[]);
    let flags = loc.proxy_cookie_flags.as_deref().unwrap_or(&[]);
    if domains.is_empty() && paths.is_empty() && flags.is_empty() {
        return;
    }
    let expand = |s: &str| vars.expand(s);
    *raw = crate::cookie::rewrite_set_cookie(raw, domains, paths, flags, &expand);
}

fn build_upstream_head(
    req: &Request,
    target_uri: &str,
    body_of_request: &[u8],
    loc: &LocCfg,
    pp: &crate::config::ProxyPass,
    peer_ip: &str,
    is_upgrade: bool,
    convert_head: bool,
) -> Vec<u8> {
    // ---- request head ----
    let mut out = Vec::with_capacity(512);
    // `proxy_cache_convert_head`: a HEAD is sent as GET so the response can be
    // cached and reused for later GETs.
    if convert_head {
        out.extend_from_slice(b"GET");
    } else {
        out.extend_from_slice(req.method.as_str().as_bytes());
    }
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

    if !body_of_request.is_empty() || req.body_len > 0 || req.chunked {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body_of_request.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
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
    upstream_addr: &str,
    vars: &crate::http::ServerVars<'_>,
    convert_head: bool,
) -> io::Result<Outcome> {
    // ---- request head ----
    let out = build_upstream_head(req, target_uri, body, loc, pp, peer_ip, is_upgrade, convert_head);

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
        if let Some(pos) = find_head_end(&buf) {
            let h = parse_upstream_head(&buf[..pos])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream response"))?;
            buf = buf.split_off(pos);
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
            sent: Vec::new(),
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

    // ---- cacheable responses are buffered first ----
    // nginx buffers close-delimited *and* chunked upstream responses so they can
    // be cached and re-sent with a Content-Length. Any status is cacheable when
    // the headers decide a validity (verified against nginx 1.28).
    // `proxy_force_ranges` needs the whole body in memory to slice it, so a
    // ranged request is buffered even when the response is not cacheable.
    let wants_ranges = loc.proxy_force_ranges
        && req.headers.get("range").is_some()
        && !is_upgrade;
    let cacheable = cache.zone.is_some() && cache.key.is_some() && !is_upgrade;
    if cacheable || wants_ranges {
        let mut payload = buf;
        match (head.chunked, total_len) {
            // Chunked: read to the terminator, then decode.
            (true, _) => loop {
                if dechunk(&payload).is_some() {
                    break;
                }
                let mut chunk = vec![0u8; 64 * 1024];
                match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => payload.extend_from_slice(&chunk[..n]),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"))
                    }
                }
            },
            (false, Some(len)) => {
                while (payload.len() as u64) < len {
                    let mut chunk =
                        vec![0u8; (len - payload.len() as u64).min(64 * 1024) as usize];
                    let n =
                        match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => return Err(e),
                            Err(_) => {
                                return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"))
                            }
                        };
                    payload.extend_from_slice(&chunk[..n]);
                }
            }
            (false, None) => loop {
                let mut chunk = vec![0u8; 64 * 1024];
                match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => payload.extend_from_slice(&chunk[..n]),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"))
                    }
                }
            },
        }
        if head.chunked {
            match dechunk(&payload) {
                Some(decoded) => payload = decoded,
                None => payload.clear(),
            }
        }

        if cacheable {
            if let (Some(zone), Some(key)) = (cache.zone, cache.key) {
            let stored_headers: Vec<(String, String)> = crate::http::split_head(&raw)
                .into_iter()
                .filter(|(k, _)| {
                    !k.eq_ignore_ascii_case("connection")
                        && !k.eq_ignore_ascii_case("keep-alive")
                        && !k.eq_ignore_ascii_case("transfer-encoding")
                        && !k.eq_ignore_ascii_case("x-cache-status")
                })
                .collect();
            if let Some(valid) =
                crate::cache::ttl(loc, head.status, &stored_headers, loc.proxy_cache_ignore)
            {
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
        }

        let mut out_raw = raw;
        apply_cookie_rules(&mut out_raw, loc, vars);
        crate::http::apply_expires(&mut out_raw, loc);
        crate::http::apply_add_headers_upstream(
            &mut out_raw,
            &loc.headers,
            head.status,
            cache.status,
            upstream_addr,
        );
        // A close-delimited upstream response has no length; since we buffered
        // it we can now send one.
        if !crate::http::split_head(&out_raw)
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            && !crate::http::split_head(&out_raw)
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        {
            out_raw.extend_from_slice(b"Content-Length: ");
            out_raw.extend_from_slice(payload.len().to_string().as_bytes());
            out_raw.extend_from_slice(b"\r\n");
        }
        let mut status = head.status;
        if wants_ranges {
            let (s2, raw2, body2) = apply_force_ranges(req, loc, status, &mut out_raw, payload);
            status = s2;
            out_raw = raw2;
            payload = body2;
        }
        // `add_trailer` switches the response to chunked encoding, so the
        // buffered reply must go through the normal response writer.
        if !loc.trailers.is_empty() {
            let (expect, list) = crate::http::eval_trailers(&loc.trailers, status, vars);
            if expect {
                out_raw = strip_length_headers(&mut out_raw);
                let resp = Response {
                    status,
                    headers: Vec::new(),
                    raw: out_raw,
                    explicit_len: false,
                    no_error_page: false,
                    trailers: list,
                    expect_trailers: true,
                    body: if req.method == Method::Head {
                        crate::http::Body::Empty
                    } else {
                        crate::http::Body::Bytes(payload)
                    },
                };
                let bytes = crate::http::write_response(
                    conn,
                    resp,
                    req.keepalive,
                    tokens,
                    req.method == Method::Head,
                )
                .await?;
                return Ok(Outcome {
                    status,
                    bytes,
                    close: false,
                    sent: Vec::new(),
                });
            }
        }
        write_head(conn, status, &out_raw, req.keepalive, tokens).await?;
        // A converted HEAD gets no body even though the upstream sent one.
        if req.method != Method::Head {
            conn.write_all(&payload).await?;
        }
        return Ok(Outcome {
            status,
            bytes: payload.len() as u64,
            close: false,
            sent: Vec::new(),
        });
    }

    let mut raw = raw;
    crate::http::apply_expires(&mut raw, loc);
    let upstream_headers = crate::http::split_head(&raw);
    crate::http::apply_add_headers_ctx(
        &mut raw,
        &loc.headers,
        head.status,
        cache.status,
        upstream_addr,
        &upstream_headers,
        Some(vars),
    );
    apply_cookie_rules(&mut raw, loc, vars);
    let sent_headers = crate::http::split_head(&raw);
    write_head(conn, head.status, &raw, req.keepalive, tokens).await?;

    let mut sent = 0u64;
    if req.method == Method::Head {
        // Converted HEAD: drain (and discard) the body we asked for.
        return Ok(Outcome {
            status: head.status,
            bytes: 0,
            close: false,
            sent: sent_headers,
        });
    }
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
        // The upstream signals the end by closing (no Content-Length). The
        // client cannot know where the body ends unless we re-frame it, so
        // emit chunked — which is what nginx does here.
        conn.write_all(b"Transfer-Encoding: chunked\r\n").await?;

        if !buf.is_empty() {
            let mut framed = Vec::with_capacity(buf.len() + 16);
            framed.extend_from_slice(format!("{:x}\r\n", buf.len()).as_bytes());
            framed.extend_from_slice(&buf);
            framed.extend_from_slice(b"\r\n");
            sent += buf.len() as u64;
            conn.write_all(&framed).await?;
        }
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            let mut framed = Vec::with_capacity(n + 16);
            framed.extend_from_slice(format!("{n:x}\r\n").as_bytes());
            framed.extend_from_slice(&chunk[..n]);
            framed.extend_from_slice(b"\r\n");
            sent += n as u64;
            conn.write_all(&framed).await?;
        }
        conn.write_all(b"0\r\n\r\n").await?;
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
        sent: sent_headers,
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
    /// Send the interim `100 Continue` nginx emits for `Expect: 100-continue`.
    pub async fn send_100_continue(&mut self) -> io::Result<()> {
        self.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await
    }

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


/// Buffered variant used by HTTP/2, where there is no socket to stream to.
///
/// Returns `None` when the location does not proxy. The whole upstream reply is
/// read into memory, which is what nginx does for proxy_buffering on.
pub async fn fetch(
    req: &Request,
    path: &str,
    query: &str,
    loc: &LocCfg,
    http: &Http,
    peer_ip: &str,
) -> Option<Response> {
    let pp = loc.proxy_pass.clone()?;
    let candidates = choose(http, loc, &peer_ip.parse().ok()?)?;
    let target_uri = upstream_target(path, query, loc, &pp);

    let mut last_err: Option<io::Error> = None;
    for cand in candidates {
        let addr = match &cand {
            Chosen::Direct(_, a) => *a,
            Chosen::Upstream { addr, .. } => *addr,
        };
        let mut up = match connect_bound(addr, resolve_bind(loc, &BindVars {
            peer_ip,
            peer_port: 0,
            query,
        }).ok().flatten(), loc.proxy_connect_timeout).await {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let out = build_upstream_head(req, &target_uri, &[], loc, &pp, peer_ip, false, false);
        if up.write_all(&out).await.is_err() {
            continue;
        }

        // Read until the head is complete, then to Content-Length or EOF.
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut chunk = vec![0u8; 16 * 1024];
        let mut head_end: Option<usize> = None;
        loop {
            let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    last_err = Some(e);
                    break;
                }
                Err(_) => {
                    last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
                    break;
                }
            };
            buf.extend_from_slice(&chunk[..n]);
            if head_end.is_none() {
                head_end = find_head_end(&buf);
            }
            if let Some(h) = head_end {
                if let Some(head) = parse_upstream_head(&buf[..h]) {
                    let have = buf.len() - h;
                    if let Some(len) = head.content_length {
                        if have as u64 >= len {
                            break;
                        }
                    } else if !head.chunked {
                        // No framing information: the upstream closes to signal
                        // the end, so keep reading until EOF.
                    }
                }
            }
        }

        let Some(h) = head_end else {
            last_err = Some(io::Error::new(io::ErrorKind::InvalidData, "no response head"));
            continue;
        };
        let head = match parse_upstream_head(&buf[..h]) {
            Some(x) => x,
            None => continue,
        };
        let payload = buf[h..].to_vec();
        let body = if head.chunked {
            match dechunk(&payload) {
                Some(b) => b,
                None => payload,
            }
        } else {
            match head.content_length {
                Some(len) if payload.len() as u64 > len => payload[..len as usize].to_vec(),
                _ => payload,
            }
        };

        let mut raw = head.raw.clone();
        if !crate::http::split_head(&raw)
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            raw.extend_from_slice(b"Content-Length: ");
            raw.extend_from_slice(body.len().to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        let upstream_headers = crate::http::split_head(&head.raw);
        crate::http::apply_expires(&mut raw, loc);
        crate::http::apply_add_headers_full(
            &mut raw,
            &loc.headers,
            head.status,
            "BYPASS",
            &addr.to_string(),
            &upstream_headers,
        );

        return Some(Response {
            status: head.status,
            headers: Vec::new(),
            raw,
            explicit_len: true,
            no_error_page: false,
            trailers: Vec::new(),
            expect_trailers: false,
            body: Body::Bytes(body),
        });
    }

    if let Some(e) = &last_err {
        eprintln!("ngxrs: [error] h2 upstream failure for {}: {e}", req.raw_target);
    }
    Some(Response::bytes(502, "text/html", crate::http::error_body(502, true)))
}

/// Strip chunked framing.
fn dechunk(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    loop {
        let line_end = memchr::memmem::find(&input[i..], b"\r\n")? + i;
        let size_str = std::str::from_utf8(&input[i..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if i + size > input.len() {
            return None;
        }
        out.extend_from_slice(&input[i..i + size]);
        i += size + 2; // skip trailing CRLF
    }
}

/// Recompute the cache key exactly as the request path does.
///
/// Used by the background refresh, which has no connection context.
pub fn cache_key_for(
    loc: &LocCfg,
    req: &Request,
    peer_ip: &str,
) -> Option<String> {
    let pp = loc.proxy_pass.as_ref()?;
    let scheme = "http";
    let proxy_host = &pp.host_header;
    let (uri_only, args_only) = match req.raw_target.split_once('?') {
        Some((u, a)) => (u.to_string(), a.to_string()),
        None => (req.raw_target.clone(), String::new()),
    };
    let host = req.host.as_ref().map(|h| h.as_str()).unwrap_or("");
    Some(match &loc.proxy_cache_key {
        Some(spec) => crate::cache::expand_key(
            spec, scheme, proxy_host, host, &req.raw_target, &uri_only, &args_only, peer_ip,
            req.method.as_str(),
        ),
        None => crate::cache::default_key(scheme, proxy_host, &req.raw_target),
    })
}


/// Refresh a stale cache entry behind the client's back.
///
/// Everything the task needs is materialised before spawning: neither `Request`
/// nor `Http` is `Clone`, and both are borrowed from the live request.
pub fn spawn_background_update(
    loc: &LocCfg,
    http: &Http,
    req: &Request,
    key: String,
    peer_ip: &str,
) {
    let Some(zone) = loc
        .proxy_cache
        .as_ref()
        .and_then(|name| http.cache_zones.iter().find(|z| &z.name == name))
        .cloned()
    else {
        return;
    };
    let Some(pp) = loc.proxy_pass.clone() else {
        return;
    };
    let Some(candidates) = choose(http, loc, &match peer_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    }) else {
        return;
    };
    let addrs: Vec<SocketAddr> = candidates
        .into_iter()
        .map(|c| match c {
            Chosen::Direct(_, a) => a,
            Chosen::Upstream { addr, .. } => addr,
        })
        .collect();

    // The refresh always asks for the whole body, even for a HEAD request.
    let target_uri = upstream_target(req_uri(req), req_query(req), loc, &pp);
    let head = build_upstream_head(req, &target_uri, &[], loc, &pp, peer_ip, false, true);

    let connect_timeout = loc.proxy_connect_timeout;
    let read_timeout = loc.proxy_read_timeout;
    let loc_owned = loc.clone();

    tokio::spawn(async move {
        let Some((status, headers, body)) =
            refetch(&head, &addrs, connect_timeout, read_timeout).await
        else {
            return;
        };
        if let Some(valid) = crate::cache::ttl(
            &loc_owned,
            status,
            &headers,
            loc_owned.proxy_cache_ignore,
        ) {
            let entry = crate::cache::Cached {
                status,
                headers,
                body,
                stored_at: crate::cache::now(),
                valid_for: valid.as_secs(),
            };
            let _ = crate::cache::store(&zone, &key, &entry);
        }
    });
}

fn req_uri(req: &Request) -> &str {
    match req.raw_target.split_once('?') {
        Some((u, _)) => u,
        None => &req.raw_target,
    }
}

fn req_query(req: &Request) -> &str {
    match req.raw_target.split_once('?') {
        Some((_, q)) => q,
        None => "",
    }
}

/// Read one upstream response, decoding its body.
async fn refetch(
    head: &[u8],
    addrs: &[SocketAddr],
    connect_timeout: std::time::Duration,
    read_timeout: std::time::Duration,
) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut up = None;
    for addr in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
            up = Some(s);
            break;
        }
    }
    let mut up = up?;
    up.write_all(head).await.ok()?;

    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    loop {
        if let Some(pos) = find_head_end(&buf) {
            let h = parse_upstream_head(&buf[..pos])?;
            let mut body = buf.split_off(pos);
            if h.chunked {
                loop {
                    if dechunk(&body).is_some() {
                        break;
                    }
                    let mut chunk = vec![0u8; 16 * 1024];
                    let n = tokio::time::timeout(read_timeout, up.read(&mut chunk))
                        .await
                        .ok()?
                        .ok()?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                body = dechunk(&body).unwrap_or_default();
            } else if let Some(len) = h.content_length {
                while (body.len() as u64) < len {
                    let mut chunk = vec![0u8; 16 * 1024];
                    let n = tokio::time::timeout(read_timeout, up.read(&mut chunk))
                        .await
                        .ok()?
                        .ok()?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                body.truncate(len as usize);
            } else {
                loop {
                    let mut chunk = vec![0u8; 16 * 1024];
                    let n = tokio::time::timeout(read_timeout, up.read(&mut chunk))
                        .await
                        .ok()?
                        .ok()?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
            }
            let headers: Vec<(String, String)> = crate::http::split_head(&h.raw)
                .into_iter()
                .filter(|(k, _)| {
                    !k.eq_ignore_ascii_case("connection")
                        && !k.eq_ignore_ascii_case("keep-alive")
                        && !k.eq_ignore_ascii_case("transfer-encoding")
                })
                .collect();
            return Some((h.status, headers, body));
        }
        let mut chunk = vec![0u8; 16 * 1024];
        let n = tokio::time::timeout(read_timeout, up.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `proxy_force_ranges`: slice a buffered upstream body for a `Range` request.
///
/// nginx serves ranges from a proxied response even when the upstream never
/// sent `Accept-Ranges` (verified against 1.28 with `max_ranges 0` upstream).
/// Returns the (possibly rewritten) status, head and body.
fn apply_force_ranges(
    req: &Request,
    loc: &LocCfg,
    status: u16,
    raw: &mut Vec<u8>,
    body: Vec<u8>,
) -> (u16, Vec<u8>, Vec<u8>) {
    if !loc.proxy_force_ranges || status != 200 {
        return (status, std::mem::take(raw), body);
    }
    let Some(range) = req.headers.get("range") else {
        return (status, std::mem::take(raw), body);
    };

    // `If-Range` must still match, exactly like the static-file path.
    if let Some(cond) = req.headers.get("if-range") {
        let headers = crate::http::split_head(raw);
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let ok = if cond.trim().starts_with('"') || cond.trim().starts_with("W/") {
            get("etag").map(|e| e.trim() == cond.trim()).unwrap_or(false)
        } else {
            match (
                crate::util::parse_http_date(cond),
                get("last-modified").and_then(|v| crate::util::parse_http_date(&v)),
            ) {
                (Some(want), Some(have)) => have <= want,
                _ => false,
            }
        };
        if !ok {
            return (status, std::mem::take(raw), body);
        }
    }

    let size = body.len() as u64;
    let content_type = crate::http::split_head(raw)
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v)
        .unwrap_or_else(|| "text/html".to_string());

    match crate::http::static_file::parse_multi_range(range, size) {
        crate::http::static_file::MultiRange::Ignore => (status, std::mem::take(raw), body),
        crate::http::static_file::MultiRange::Unsatisfiable => {
            let mut out = Vec::new();
            out.extend_from_slice(b"Content-Type: text/html\r\nContent-Range: bytes */");
            out.extend_from_slice(size.to_string().as_bytes());
            out.extend_from_slice(b"\r\nContent-Length: 0\r\n");
            (416, out, Vec::new())
        }
        crate::http::static_file::MultiRange::Ranges(spans) => {
            let mut head = strip_length_headers(raw);
            if spans.len() == 1 {
                let (start, end) = spans[0];
                head.extend_from_slice(b"Content-Range: bytes ");
                head.extend_from_slice(start.to_string().as_bytes());
                head.push(b'-');
                head.extend_from_slice(end.to_string().as_bytes());
                head.push(b'/');
                head.extend_from_slice(size.to_string().as_bytes());
                head.extend_from_slice(b"\r\nContent-Length: ");
                head.extend_from_slice((end - start + 1).to_string().as_bytes());
                head.extend_from_slice(b"\r\n");
                let lo = (start as usize).min(body.len());
                let hi = (end as usize + 1).min(body.len());
                (206, head, body[lo..hi].to_vec())
            } else {
                // nginx picks the boundary from the request's address/size.
                let boundary = format!("{:016X}", span_hash(req, size));
                let mbody =
                    crate::http::static_file::multipart_body(&boundary, &content_type, size, &spans, &body);
                head.extend_from_slice(b"Content-Type: multipart/byteranges; boundary=");
                head.extend_from_slice(boundary.as_bytes());
                head.extend_from_slice(b"\r\nContent-Length: ");
                head.extend_from_slice(mbody.len().to_string().as_bytes());
                head.extend_from_slice(b"\r\n");
                (206, head, mbody)
            }
        }
    }
}

/// Drop `Content-Length`, `Content-Range` and `Content-Type` before re-adding.
fn strip_length_headers(raw: &mut Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while pos < raw.len() {
        let end = memchr::memmem::find(&raw[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(raw.len());
        let line = &raw[pos..end];
        let keep = ![
            "content-length",
            "content-range",
            "content-type",
            "accept-ranges",
        ]
        .iter()
        .any(|n| {
            line.len() > n.len() && line[..n.len()].eq_ignore_ascii_case(n.as_bytes())
        });
        if keep {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        pos = end + 2;
    }
    out
}

fn span_hash(req: &Request, size: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.raw_target.hash(&mut h);
    size.hash(&mut h);
    h.finish()
}
