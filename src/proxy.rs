//! Reverse proxy: upstream selection, connection reuse, WebSocket upgrade.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Http, LbMethod, LocCfg, ProxyTarget, Upstream};
use crate::http::request::{Method, Request};
use crate::http::{write_head, Body, Outcome, Response};
use crate::util::reason;

pub const MAX_PROXY_BODY: usize = 32 * 1024 * 1024;

// ---- per-upstream bookkeeping -------------------------------------------

static RR_COUNTERS: OnceLock<Vec<AtomicUsize>> = OnceLock::new();
static ACTIVE: OnceLock<Vec<Vec<AtomicUsize>>> = OnceLock::new();
static POOL: OnceLock<Mutex<HashMap<(usize, u32), Vec<PooledConn>>>> = OnceLock::new();

/// An established upstream connection. `proxy_pass http://unix:...` reaches a
/// unix socket, everything else a TCP socket; the rest of the proxy code only
/// needs the byte stream, so the two share one type.
pub enum UpStream {
    Tcp(TcpStream),
    Unix(tokio::net::UnixStream),
    /// `proxy_pass https://`: the connection is a TLS session over TCP.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for UpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            UpStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            UpStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            UpStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            UpStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct PooledConn {
    stream: UpStream,
    /// When the TCP connection was established -- nginx's `keepalive_time`
    /// bounds the *total* age of a pooled connection, not its idle period.
    created: Instant,
    last_used: Instant,
    /// Requests already served over this connection.
    requests: u64,
}

/// Per-upstream keepalive limits, filled from the config once.
static UPSTREAM_KA: OnceLock<Vec<(u64, Duration, Duration)>> = OnceLock::new();

fn ka_limits(idx: usize) -> (u64, Duration, Duration) {
    UPSTREAM_KA
        .get()
        .and_then(|v| v.get(idx).copied())
        // nginx defaults: 1000 requests, 1h maximum age, 60s idle.
        .unwrap_or((1000, Duration::from_secs(3600), Duration::from_secs(60)))
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

/// Cache keys with a background refresh in flight.
///
/// nginx keeps this in the shared cache zone (`c->node->updating`), so it must
/// be visible from every worker thread — a `thread_local!` here made the
/// `UPDATING` status invisible whenever the follow-up request landed on a
/// different worker.
fn updating_set() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static SET: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn updating_mark(key: &str) -> bool {
    updating_set()
        .lock()
        .map(|mut s| s.insert(key.to_string()))
        .unwrap_or(false)
}

fn updating_clear(key: &str) {
    if let Ok(mut s) = updating_set().lock() {
        s.remove(key);
    }
}

fn updating_test(key: &str) -> bool {
    updating_set()
        .lock()
        .map(|s| s.contains(key))
        .unwrap_or(false)
}

// ---- peer failure accounting (server ... max_fails fail_timeout) ----------

/// Which retry triggers count as an "unsuccessful attempt" against
/// `max_fails`. Probed against nginx 1.28: retries triggered by 5xx and 429
/// count, 403 and 404 do not; I/O errors and timeouts count; a *successful*
/// attempt never resets the counter — only the `fail_timeout` window expiring
/// brings a peer back.
struct PeerFail {
    fails: u32,
    checked: std::time::Instant,
}

fn peer_fail_cell() -> &'static std::sync::Mutex<std::collections::HashMap<(usize, usize), PeerFail>>
{
    static CELLS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(usize, usize), PeerFail>>,
    > = std::sync::OnceLock::new();
    CELLS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// nginx `ngx_http_upstream_get_rr_peer`: a peer is unavailable while
/// `fails >= max_fails` and the last attempt is inside `fail_timeout`.
fn peer_available(up: usize, sidx: usize, max_fails: u32, fail_timeout: Duration) -> bool {
    if max_fails == 0 {
        return true;
    }
    let guard = peer_fail_cell().lock().unwrap_or_else(|e| e.into_inner());
    match guard.get(&(up, sidx)) {
        Some(p) => !(p.fails >= max_fails && p.checked.elapsed() < fail_timeout),
        None => true,
    }
}

/// Every completed attempt refreshes `checked`; an unsuccessful one also
/// bumps `fails`.
fn peer_mark(up: usize, sidx: usize, failed: bool) {
    let mut guard = peer_fail_cell().lock().unwrap_or_else(|e| e.into_inner());
    let p = guard.entry((up, sidx)).or_insert(PeerFail {
        fails: 0,
        checked: std::time::Instant::now(),
    });
    p.checked = std::time::Instant::now();
    if failed {
        p.fails = p.fails.saturating_add(1);
    }
}

/// `exchange` returns this when the upstream status matches a
/// `proxy_next_upstream http_XXX` flag and another peer may still be tried:
/// nothing has reached the client at that point, so the attempt is discarded.
#[derive(Debug)]
struct RetryNextUpstream(u16);
impl std::fmt::Display for RetryNextUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proxy_next_upstream retry (status {})", self.0)
    }
}
impl std::error::Error for RetryNextUpstream {}

fn as_retry(e: &io::Error) -> Option<u16> {
    e.get_ref()
        .and_then(|x| x.downcast_ref::<RetryNextUpstream>())
        .map(|r| r.0)
}

/// The `proxy_next_upstream` flag covering this upstream status (0: none).
fn status_flag(status: u16) -> u32 {
    use crate::config::next_upstream as nu;
    match status {
        500 => nu::HTTP_500,
        502 => nu::HTTP_502,
        503 => nu::HTTP_503,
        504 => nu::HTTP_504,
        403 => nu::HTTP_403,
        404 => nu::HTTP_404,
        429 => nu::HTTP_429,
        _ => 0,
    }
}

/// May a failure while *establishing* the connection move to the next peer?
/// Nothing has been sent at that point, so nginx applies no method
/// restriction, only the `error` / `timeout` flags.
fn connect_retry(e: &io::Error, nu_flags: u32) -> bool {
    use crate::config::next_upstream as nu;
    if nu_flags & nu::OFF != 0 {
        return false;
    }
    let want = if e.kind() == io::ErrorKind::TimedOut {
        nu::TIMEOUT
    } else {
        nu::ERROR
    };
    nu_flags & want != 0
}

fn pool_key_of(c: &Chosen) -> PoolKey {
    let (up, sidx) = match c {
        Chosen::Direct(_, a) => (usize::MAX, a.port() as u32),
        Chosen::Unix(_) => (usize::MAX, 0),
        Chosen::Upstream { up, sidx, .. } => (*up, *sidx as u32),
    };
    // A fresh connection; `checkout` replaces these when reusing a pooled one.
    PoolKey {
        up,
        sidx,
        created: Instant::now(),
        requests: 0,
    }
}

/// `ka_limits` for a direct (non-`upstream`) target: no pooling at all.
const _: fn(usize) -> (u64, Duration, Duration) = ka_limits;

/// Take a pooled connection, dropping any that outlived their limits.
///
/// `keepalive_timeout` is checked here because it is an *idle* limit; a
/// connection that sat unused for longer is closed and a fresh one opened, which
/// is what `upstream_keepalive.t` observes as a new `$connection`.
fn checkout(key: PoolKey) -> Option<(UpStream, Instant, u64)> {
    // Only the **idle** limit is enforced here. `keepalive_requests` and
    // `keepalive_time` decide whether a connection is put back into the pool
    // (`checkin`), not whether it may be taken out: nginx happily serves one
    // more request on a connection that has reached `keepalive_time` and only
    // then closes it -- which is what `upstream_keepalive.t` asserts with
    // "keepalive time last" followed by "keepalive time new".
    let (_, _, idle_timeout) = ka_limits(key.up);
    let pool = POOL.get()?;
    let mut guard = pool.lock().ok()?;
    let list = guard.get_mut(&(key.up, key.sidx))?;
    while let Some(c) = list.pop() {
        if c.last_used.elapsed() >= idle_timeout {
            continue;
        }
        return Some((c.stream, c.created, c.requests));
    }
    None
}

fn checkin(key: PoolKey, stream: UpStream, cap: usize) {
    if cap == 0 {
        return;
    }
    let (max_req, max_age, _) = ka_limits(key.up);
    let requests = key.requests + 1;
    // nginx stops keeping a connection once it has carried `keepalive_requests`
    // or reached `keepalive_time`; the socket is simply closed, which the
    // upstream sees as EOF.
    if requests >= max_req || key.created.elapsed() >= max_age {
        return;
    }
    if let Some(pool) = POOL.get() {
        if let Ok(mut guard) = pool.lock() {
            let list = guard.entry((key.up, key.sidx)).or_default();
            if list.len() < cap {
                list.push(PooledConn {
                    stream,
                    created: key.created,
                    last_used: Instant::now(),
                    requests,
                });
            }
        }
    }
}

/// Identifies a pooled connection and carries its lifetime counters.
#[derive(Clone, Copy)]
struct PoolKey {
    up: usize,
    sidx: u32,
    created: Instant,
    requests: u64,
}

// ---- selection -----------------------------------------------------------

enum Chosen {
    Direct(usize, SocketAddr),
    /// `proxy_pass http://unix:/path:`. Never pooled: a unix connect is local
    /// and cheap, and the pool is keyed by address.
    Unix(std::sync::Arc<std::path::PathBuf>),
    Upstream {
        up: usize,
        sidx: usize,
        addr: SocketAddr,
        name: String,
    },
}

/// Resolve a `proxy_pass` authority that only exists at request time.
///
/// An `upstream {}` name wins; otherwise the value is `host[:port][/uri]` and
/// needs `resolver` (nginx refuses to start without one in that case).
async fn dynamic_addr(
    http: &Http,
    loc: &LocCfg,
    authority: &str,
    https: bool,
    vars: &crate::http::ServerVars<'_>,
) -> Option<Vec<std::net::SocketAddr>> {
    let authority = authority.split('/').next().unwrap_or(authority);
    if let Some(up) = http.upstreams.iter().find(|u| u.name == authority) {
        return up.servers.first().map(|s| vec![s.addr]);
    }
    let default_port = if https { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse::<u16>().ok()?)
        }
        _ => (authority, default_port),
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(vec![std::net::SocketAddr::new(ip, port)]);
    }
    // nginx allows `resolver` in http, server and location; the innermost one
    // wins, and `resolver_timeout` applies to whichever is in force.
    let resolver = loc.resolver.as_ref().or(http.resolver.as_ref())?;
    let resolver = resolver.with_timeout(loc.resolver_timeout.or(http.resolver_timeout));
    let _ = vars;
    let ips = crate::resolver::resolve(&resolver, host).await?;
    if ips.is_empty() {
        return None;
    }
    // Every address the name resolved to becomes a peer, in order, so
    // `proxy_next_upstream` walks them (`many.example.net` in the resolver
    // tests expects both to appear in `$upstream_addr`).
    Some(
        ips.into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, port))
            .collect(),
    )
}

fn choose(
    http: &Http,
    loc: &LocCfg,
    client_ip: &std::net::IpAddr,
    hash_vars: Option<&crate::http::ServerVars<'_>>,
) -> Option<Vec<Chosen>> {
    let pp = loc.proxy_pass.as_ref()?;
    match &pp.target {
        ProxyTarget::Addr(addr) => Some(vec![Chosen::Direct(0, *addr)]),
        ProxyTarget::Unix(path) => Some(vec![Chosen::Unix(path.clone())]),
        ProxyTarget::Upstream(idx) => {
            let up = http.upstreams.get(*idx)?;
            let hash_key = match (&up.method, hash_vars) {
                (LbMethod::Hash { key, .. }, Some(v)) => Some(v.expand(key)),
                _ => None,
            };
            let order = select_order(up, *idx, client_ip, hash_key.as_deref())?;
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

fn select_order(
    up: &Upstream,
    idx: usize,
    client_ip: &std::net::IpAddr,
    hash_key: Option<&str>,
) -> Option<Vec<usize>> {
    // `max_fails`/`fail_timeout`: a peer whose recent attempts all failed is
    // held out of rotation until its `fail_timeout` expires. Backups are
    // appended after the primaries: a normal request never reaches them, but
    // a `proxy_next_upstream` retry does (nginx's two peer pools). When no
    // primary is available at all, backups serve directly.
    let mut primaries: Vec<usize> = up
        .servers
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            !s.down && !s.backup && peer_available(idx, *i, s.max_fails, s.fail_timeout)
        })
        .map(|(i, _)| i)
        .collect();
    let backups: Vec<usize> = up
        .servers
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            !s.down && s.backup && peer_available(idx, *i, s.max_fails, s.fail_timeout)
        })
        .map(|(i, _)| i)
        .collect();

    // `hash` selects by key; nginx only ever hashes the primary pool.
    if let (LbMethod::Hash { consistent, .. }, Some(key)) = (&up.method, hash_key) {
        let hashed = if *consistent {
            chash_order(up, idx, key, &primaries)
        } else {
            plain_hash_order(up, idx, key, &primaries)
        };
        if let Some(mut order) = hashed {
            order.extend(backups);
            return Some(order);
        }
        // Empty key, a single peer, or every rehash rejected: fall through to
        // plain round-robin (`get_rr_peer` in nginx).
    }

    if !primaries.is_empty() {
        // The rotation (or sort) only ever orders the primaries: backups stay
        // behind them, reachable by a retry but never by rotation.
        match &up.method {
            LbMethod::RoundRobin | LbMethod::Hash { .. } => {
                let start = rr(idx) % primaries.len();
                primaries.rotate_left(start);
            }
            LbMethod::LeastConn => {
                // Ties rotate: nginx round-robins between peers with the same
                // (active) count, so a stable sort over an unrotated list
                // would pin every idle request on the first peer.
                let start = rr(idx) % primaries.len();
                primaries.rotate_left(start);
                let act = ACTIVE.get();
                primaries.sort_by_key(|&i| {
                    act.and_then(|v| v.get(idx))
                        .and_then(|l| l.get(i))
                        .map(|a| a.load(Ordering::Relaxed))
                        .unwrap_or(0)
                });
            }
            LbMethod::Random { two, least_conn } => {
                // `random [two [least_conn]]`: with `two`, two peers are drawn
                // and the better one wins; `least_conn` compares in-flight
                // requests instead of request counts. Without `two` the choice
                // is simply random, so no rotation is applied.
                if *two && primaries.len() > 1 {
                    let n = primaries.len();
                    let pick = |i: usize| -> i64 {
                        if *least_conn {
                            ACTIVE
                                .get()
                                .and_then(|v| v.get(idx))
                                .and_then(|l| l.get(primaries[i]))
                                .map(|a| a.load(Ordering::Relaxed) as i64)
                                .unwrap_or(0)
                        } else {
                            // Default `random two` compares total request counts
                            // (`peer->conns`); we track in-flight requests only,
                            // so that is what the comparison uses.
                            ACTIVE
                                .get()
                                .and_then(|v| v.get(idx))
                                .and_then(|l| l.get(primaries[i]))
                                .map(|a| a.load(Ordering::Relaxed) as i64)
                                .unwrap_or(0)
                        }
                    };
                    let a = (rr(idx) % n) as usize;
                    let b = (rr(idx.wrapping_add(1)) % n) as usize;
                    let first = a.min(b);
                    let second = a.max(b);
                    // Move the better peer to the front; the rest keeps order.
                    if pick(second) < pick(first) {
                        primaries.swap(0, second);
                    } else {
                        primaries.swap(0, first);
                    }
                } else {
                    let start = rr(idx) % primaries.len();
                    primaries.rotate_left(start);
                }
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
                        (0..16).fold(0u64, |acc, i| {
                            acc.wrapping_mul(31).wrapping_add(o[i] as u64)
                        })
                    }
                };
                let start = (h as usize) % primaries.len();
                primaries.rotate_left(start);
            }
        }
        primaries.extend(backups);
        Some(primaries)
    } else if !backups.is_empty() {
        Some(backups)
    } else {
        None
    }
}

/// `ngx_http_upstream_get_hash_peer`: the Cache::Memcached-compatible
/// expression `((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH`, where
/// REHASH is the *decimal string* of the retry counter (omitted on the first
/// iteration) and PREV_HASH accumulates. The peer is picked by walking the
/// whole list (down peers included) by `hash % total_weight`; a peer that is
/// already tried, down, or failed makes the loop rehash — after 20 tries
/// nginx falls back to round-robin, which is `None` here.
fn plain_hash_order(
    up: &Upstream,
    idx: usize,
    key: &str,
    primaries: &[usize],
) -> Option<Vec<usize>> {
    // nginx: `number < 2 || key.len == 0` selects by round-robin instead.
    // `number` is the configured primary count, down peers included.
    let configured = up.servers.iter().filter(|s| !s.backup).count();
    if configured < 2 || key.is_empty() || primaries.is_empty() {
        return None;
    }
    // Static total over every primary server, down ones included.
    let total_weight: u64 = up
        .servers
        .iter()
        .filter(|s| !s.backup)
        .map(|s| u64::from(s.weight))
        .sum();
    if total_weight == 0 {
        return None;
    }
    let mut hash: u32 = 0;
    let mut rehash: u32 = 0;
    let mut tries: u32 = 0;
    let mut order: Vec<usize> = Vec::new();
    loop {
        if !order.is_empty() && order.len() >= primaries.len() {
            break;
        }
        // nginx rehashes without bound *within* one get; its per-request cap
        // of 20 counts full peer attempts, not these steps. The list is
        // consumed lazily by the request loop, so generate it with a cap
        // generous enough to cover every primary.
        if tries > 100 {
            return None;
        }
        let mut crc = 0u32;
        if rehash > 0 {
            crc = crate::config::typed::crc32_update(crc, rehash.to_string().as_bytes());
        }
        crc = crate::config::typed::crc32_update(crc, key.as_bytes());
        let folded = (crc >> 16) & 0x7fff;
        hash = hash.wrapping_add(folded);
        rehash += 1;
        tries += 1;

        // Walk every primary server in config order — down ones included, as
        // nginx only rejects a peer *after* the walk selected it.
        let primaries_all: Vec<usize> = up
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.backup)
            .map(|(i, _)| i)
            .collect();
        let mut w = u64::from(hash % (total_weight as u32));
        let mut picked = primaries_all[0];
        for &i in &primaries_all {
            let wt = u64::from(up.servers[i].weight);
            if w < wt {
                picked = i;
                break;
            }
            w -= wt;
        }
        if !order.contains(&picked) && primaries.contains(&picked) {
            order.push(picked);
        }
    }
    if order.is_empty() {
        None
    } else {
        Some(order)
    }
}

/// `ngx_http_upstream_get_chash_peer`: look the key's crc32 up in the ring
/// (`find_chash_point`: first point with `hash >= key hash`), and on every
/// further attempt continue from the *next* point (`hash++`), skipping points
/// whose server is down, failed, or already tried. `None` falls back to
/// round-robin (empty key / empty ring / more than 20 tries).
fn chash_order(up: &Upstream, idx: usize, key: &str, primaries: &[usize]) -> Option<Vec<usize>> {
    if key.is_empty() || up.chash_points.is_empty() || primaries.is_empty() {
        return None;
    }
    let key_hash = crate::config::typed::crc32_update(0, key.as_bytes());
    // First index with point.hash >= key_hash (binary search over sorted ring).
    let start = up.chash_points.partition_point(|&(h, _)| h < key_hash);
    let mut hidx = start;
    let mut steps: u32 = 0;
    let mut order: Vec<usize> = Vec::new();
    loop {
        if order.len() >= primaries.len() {
            break;
        }
        // One full circle over the ring is enough to reach every server's
        // points; nginx only caps *peer attempts* per request, not the
        // in-get walk.
        let n = up.chash_points.len();
        if steps as usize >= n {
            return None;
        }
        steps += 1;
        let sidx = up.chash_points[hidx % up.chash_points.len()].1;
        let s = &up.servers[sidx];
        if !order.contains(&sidx)
            && !s.down
            && !s.backup
            && peer_available(idx, sidx, s.max_fails, s.fail_timeout)
        {
            order.push(sidx);
        }
        hidx += 1;
    }
    if order.is_empty() {
        None
    } else {
        Some(order)
    }
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
                } else if let Some(want) = name.strip_prefix("arg_") {
                    // Query arguments were missing here, which silently broke
                    // `proxy_pass http://$arg_b`: the name stayed literal and
                    // the target failed to parse (502). nginx does not
                    // percent-decode `$arg_*`, and the key match ignores case.
                    Some(
                        v.args
                            .split('&')
                            .filter_map(|p| p.split_once('='))
                            .find(|(k, _)| k.eq_ignore_ascii_case(want))
                            .map(|(_, val)| val.to_string())
                            .unwrap_or_default(),
                    )
                } else if let Some(want) = name.strip_prefix("cookie_") {
                    Some(crate::http::cookie_value(v.req, want))
                } else {
                    None
                }
            }
        };
        let value = value.or_else(|| {
            crate::http::resolve_var_for_proxy(
                name,
                v.req,
                v.peer_ip,
                v.scheme,
                v.host,
                v.uri,
                v.args,
                v.server_port,
            )
        });
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

fn upstream_target(
    path: &str,
    query: &str,
    loc: &LocCfg,
    pp: &crate::config::ProxyPass,
    vars: &crate::http::ServerVars<'_>,
    uri_rewritten: bool,
) -> String {
    let mut target = if uri_rewritten {
        // `rewrite ... break` changed the request URI inside this location:
        // nginx then ignores the URI part of `proxy_pass` entirely and sends
        // the rewritten URI as-is.
        path.to_string()
    } else {
        match &pp.uri {
            // `proxy_pass http://u/$1$name.html`: the URI part is a complex value,
            // expanded per request with the location's regex captures.
            Some(prefix) if prefix.contains('$') => vars.expand(prefix),
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
        }
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
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
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
    uri_rewritten: bool,
) -> io::Result<Option<Proxied>> {
    let pp = match &loc.proxy_pass {
        Some(p) => p.clone(),
        None => return Ok(None),
    };
    let _ = http;

    //  may have been rewritten by realip; ip_hash and the
    // upstream selection must hash the rewritten address like nginx.
    let peer_ip: std::net::IpAddr = vars
        .get("remote_addr")
        .parse()
        .unwrap_or_else(|_| conn.peer.ip());
    let peer_ip_owned = peer_ip.to_string();
    let peer_port = conn.peer.port();
    // A `proxy_pass` whose authority contains variables is resolved per
    // request (`proxy_pass http://$arg_b`). nginx looks the expanded value up
    // as an `upstream` name first and otherwise needs `resolver`.
    let dynamic = if pp.host_header.contains('$') {
        Some(vars.expand(&pp.host_header))
    } else {
        None
    };
    // A variable target may carry its own URI (`proxy_pass http://$b` with
    // `$b = host/`): that part replaces the request URI, as nginx does.
    let dyn_uri: Option<String> = dynamic.as_deref().and_then(|e| {
        // The expanded value carries its own URI; the request's arguments are
        // not re-attached (nginx parses the value as a full URL).
        e.find('/').map(|i| e[i..].to_string())
    });
    let dyn_target = match dynamic.as_deref() {
        Some(expanded) if !expanded.is_empty() => {
            match dynamic_addr(http, loc, expanded, pp.https, vars).await {
                Some(a) => Some(a),
                None => {
                    crate::log::error_log(
                        "error",
                        &format!("no resolver defined to resolve {expanded}"),
                    );
                    return Ok(Some(written(
                        respond_error(conn, 502, tokens, req.keepalive).await?,
                    )));
                }
            }
        }
        Some(_) => {
            return Ok(Some(written(
                respond_error(conn, 502, tokens, req.keepalive).await?,
            )));
        }
        None => None,
    };
    let Some(candidates) = dyn_target
        .map(|addrs| {
            addrs
                .into_iter()
                .enumerate()
                .map(|(i, a)| Chosen::Direct(i, a))
                .collect()
        })
        .or_else(|| choose(http, loc, &peer_ip, Some(vars)))
    else {
        // Peer selection found nothing live: nginx records the upstream group
        // name as the only `$upstream_addr` entry.
        note_group_name(http, &pp);
        return Ok(Some(written(
            respond_error_upstream(conn, 502, tokens, req.keepalive, loc, &pp).await?,
        )));
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
            return Ok(Some(written(
                respond_error(conn, 500, tokens, req.keepalive).await?,
            )));
        }
    };

    // nginx answers `Expect: 100-continue` before reading the body.
    // RFC 7231: never send 100 Continue to an HTTP/1.0 client.
    if req.expect_continue && req.version_minor == 1 {
        conn.send_100_continue().await?;
    }

    // Request body (buffered; the static path never needs it).
    // `client_max_body_size` applies here too, and nginx enforces it while
    // reading the body -- a chunked request over the limit is a 413, not a
    // completed upstream call (`body_chunked.t`, "body too large").
    let body_limit = if loc.client_max_body_size == u64::MAX {
        MAX_PROXY_BODY
    } else {
        (loc.client_max_body_size as usize).min(MAX_PROXY_BODY)
    };
    let body = match take_request_body(conn, req, body_limit).await {
        Ok(b) => b,
        Err(e) if e.to_string() == "body too large" => {
            let resp = crate::http::error_response(413, tokens);
            let bytes = crate::http::write_response(
                conn,
                resp,
                req.keepalive,
                tokens,
                req.method == Method::Head,
            )
            .await?;
            return Ok(Some(written(Outcome {
                status: 413,
                bytes,
                close: false,
                sent: Vec::new(),
            })));
        }
        Err(e) => return Err(e),
    };

    let target_uri =
        dyn_uri.unwrap_or_else(|| upstream_target(path, query, loc, &pp, vars, uri_rewritten));
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
            crate::log::error_log("error", &format!("cache \"{name}\" is not found"));
            let resp = crate::http::error_response(500, http.server_tokens);
            let bytes = crate::http::write_response(
                conn,
                resp,
                req.keepalive,
                tokens,
                req.method == Method::Head,
            )
            .await?;
            return Ok(Some(written(Outcome {
                status: 500,
                bytes,
                close: false,
                sent: Vec::new(),
            })));
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

    // `proxy_cache_min_uses`: count this request against the key (nginx bumps
    // `fcn->uses` on every cache lookup) and refuse to store until it is met.
    let min_uses_ok = match (zone, cache_key.as_ref()) {
        (Some(z), Some(key)) => {
            let mut map = z.uses.lock().unwrap_or_else(|e| e.into_inner());
            let uses = map.entry(key.clone()).or_insert(0);
            *uses += 1;
            *uses >= u64::from(loc.proxy_cache_min_uses.max(1))
        }
        _ => true,
    };

    // nginx: bypass when any value expands to something that is neither empty
    // nor "0".
    let bypass = loc.proxy_cache_bypass.iter().any(|v| {
        let e = vars.expand(v);
        let e = e.trim();
        !e.is_empty() && e != "0"
    }) || !cache_range_allowed(loc, req, min_uses_ok);

    // Cacheable HEAD requests go upstream as GET (nginx's default). A non-cacheable
    // one -- `proxy_no_cache` matched, or a bypassed range -- is forwarded as HEAD:
    // converting it would pull the whole entity at the backend's own pace for
    // nothing. nginx decides this inside `ngx_http_upstream_cache`, after
    // `u->cacheable` is known.
    let convert_head =
        req.method == Method::Head && loc.proxy_cache_convert_head && zone.is_some() && !bypass;

    // A stored-but-stale entry is reported as EXPIRED (nginx does the same)
    // rather than MISS.
    let mut stale_entry: Option<crate::cache::Cached> = None;
    let mut stale_sig: Option<String> = None;
    let key_is_updating = cache_key.as_deref().map(updating_test).unwrap_or(false);
    if let (Some(zone), Some(key)) = (zone, cache_key.as_ref()) {
        if !bypass {
            let get = |name: &str| req.headers.get_joined(name).unwrap_or_default();
            let hit = crate::cache::lookup(zone, key, get);
            if let Some((entry, sig)) = hit {
                let now = crate::cache::now();
                let fresh = entry.is_fresh(now);
                // nginx's decision table (ngx_http_upstream_cache):
                //   STALE (expired, nobody refreshing)
                //     -> serve stale + start a background refresh when
                //        `proxy_cache_background_update` and
                //        `valid_sec + updating_sec >= now`
                //   UPDATING (a refresh is already running)
                //     -> serve stale as UPDATING when `use_stale updating`
                //        or the stale-while-revalidate window still covers now;
                //        otherwise fall through to EXPIRED and refetch in the
                //        foreground.
                let in_flight = key_is_updating;
                let within_swr = entry.may_serve_stale(now);
                let serve_stale = if fresh {
                    true
                } else if in_flight {
                    loc.proxy_cache_use_stale_updating || within_swr
                } else {
                    // `proxy_cache_use_stale updating` also covers an expired
                    // entry nobody is refreshing yet: nginx answers with the
                    // stale copy and starts the update itself, rather than
                    // refetching in the foreground (this is what makes
                    // `use_stale updating` a way to keep a 5xx out of the
                    // client's face, see ticket with 1.19.3 behaviour).
                    (loc.proxy_cache_background_update && within_swr)
                        || loc.proxy_cache_use_stale_updating
                };
                if !fresh && !serve_stale {
                    stale_entry = Some(entry.clone());
                    stale_sig = sig.clone();
                }
                if (fresh || serve_stale) && entry.error.is_some() {
                    // A cached error replays through `error_page` instead of
                    // producing a body (nginx's `c->error`).
                    return Ok(Some(Proxied::Intercept {
                        status: entry.error.unwrap_or(entry.status),
                        headers: Vec::new(),
                    }));
                }
                // A conditional request on a HIT gets 304, exactly like an
                // upstream 200 would (nginx's `not_modified` header filter).
                if fresh {
                    if let Some(nm) = cached_not_modified(&entry, req) {
                        let n = crate::http::write_response(
                            conn,
                            nm,
                            true,
                            tokens,
                            req.method.as_str() == "HEAD",
                        )
                        .await?;
                        return Ok(Some(written(Outcome {
                            status: 304,
                            bytes: n,
                            close: false,
                            sent: Vec::new(),
                        })));
                    }
                }
                if fresh || serve_stale {
                    let hit_status = if fresh {
                        "HIT"
                    } else if in_flight {
                        "UPDATING"
                    } else {
                        "STALE"
                    };
                    let pending_update = if serve_stale && !fresh && !in_flight {
                        spawn_background_update(
                            loc,
                            http,
                            req,
                            key.clone(),
                            &conn.peer.ip().to_string(),
                            &target_uri,
                            &entry,
                        )
                    } else {
                        None
                    };
                    let written_out =
                        serve_cached(conn, req, loc, http, tokens, &entry, hit_status).await?;
                    // nginx finalizes the client request only after the
                    // background subrequest finishes
                    // (`ngx_http_upstream_finalize_request` waits on
                    // `u->cache`), so the next request for the same key sees
                    // the refreshed entry. Dropping the handle instead left the
                    // refresh racing the client and `$upstream_cache_status`
                    // answering STALE a second time.
                    if let Some(h) = pending_update {
                        let _ = h.await;
                    }
                    return Ok(Some(written_out));
                }
            }
        }
    }
    // `proxy_cache_lock`: only the first request for a key may populate the
    // cache. Latecomers wait for it to land, then serve the fresh entry.
    // RAII: releases the lock on every exit path.
    /// Owns a cache key until `lock_age` runs out or we finish. `Drop` only
    /// clears the entry if it is still ours: after a takeover the key belongs to
    /// another request and the original holder must not release it.
    struct CacheLock(
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Instant>>>,
        String,
        Instant,
    );
    impl Drop for CacheLock {
        fn drop(&mut self) {
            let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if map.get(&self.1) == Some(&self.2) {
                map.remove(&self.1);
            }
        }
    }

    let mut _cache_lock_held: Option<CacheLock> = None;
    // Set when the lock could not be taken before its timeout. nginx marks the
    // response uncacheable in that case (`ngx_http_file_cache_lock_wait` zeroes
    // `lock_timeout`, `ngx_http_file_cache_lock` then reports CACHE_SCARCE).
    let mut lock_timed_out = false;
    if let (Some(z), Some(key), true) = (zone, cache_key.as_ref(), loc.proxy_cache_lock) {
        let deadline = Instant::now() + loc.proxy_cache_lock_timeout;
        loop {
            // Someone else may have filled the entry while we waited.
            let get = |name: &str| req.headers.get_joined(name).unwrap_or_default();
            if let Some((entry, _sig)) = crate::cache::lookup(z, key, get) {
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
                        server_tokens: None,

                        headers_finalized: false,
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
                    return Ok(Some(written(Outcome {
                        status: entry.status,
                        bytes,
                        close: false,
                        sent: Vec::new(),
                    })));
                }
            }

            // nginx's ngx_http_file_cache_lock: a key is held until
            // `node->lock_time` (= now + lock_age) passes. Past that a waiter
            // takes over instead of waiting forever, so a stalled or very slow
            // upstream cannot serialise every later request behind one lock.
            let mine = {
                let mut map = z.lock.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                match map.get(key) {
                    Some(&held) if held > now => None,
                    _ => {
                        let until = now + loc.proxy_cache_lock_age;
                        map.insert(key.clone(), until);
                        Some(until)
                    }
                }
            };
            if let Some(until) = mine {
                _cache_lock_held = Some(CacheLock(z.lock.clone(), key.clone(), until));
                break;
            }
            if Instant::now() >= deadline {
                // nginx stops waiting and goes to the upstream itself, but the
                // reply it gets this way is not stored.
                lock_timed_out = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let mut cache_status: &str = if zone.is_some() {
        if bypass {
            "BYPASS"
        } else if stale_entry.is_some() {
            "EXPIRED"
        } else {
            "MISS"
        }
    } else {
        ""
    };

    // `proxy_cache_revalidate` only applies to an expired (not bypassed) entry.
    let reval_entry = if loc.proxy_cache_revalidate && !bypass {
        stale_entry.as_ref()
    } else {
        None
    };
    // The key the expired entry was stored under. A revalidated variant has to
    // go back to its own variant key; writing it to the base key would replace
    // whichever representation happened to be there (proxy_cache_vary.t).
    let reval_sig: Option<String> = if reval_entry.is_some() {
        stale_sig.clone()
    } else {
        None
    };

    let mut used_pooled = false;
    let mut last_err = None;
    // Set when a failed attempt would have moved to another peer: exhausting
    // the candidate list that way is nginx's "no live upstreams", which
    // appends the group name to `$upstream_addr`.
    let mut wanted_more = false;

    // `proxy_next_upstream` gating. The directive *replaces* the default
    // `error timeout`, so a config that only lists `http_500` does not retry
    // on connect errors. `_tries` / `_timeout` bound the whole sequence.
    use crate::config::next_upstream as nu;
    let nu_flags = loc.proxy_next_upstream;
    let nu_off = nu_flags & nu::OFF != 0;
    let nu_start = std::time::Instant::now();
    let nu_tries = loc.proxy_next_upstream_tries;
    let nu_timeout = loc.proxy_next_upstream_timeout;
    // nginx passes non-idempotent methods (POST/LOCK/PATCH) to the next server
    // only with the `non_idempotent` flag — and only once the request has
    // already been sent; a connect error happens before that and always may
    // retry.
    let method_retryable = match &req.method {
        Method::Post => false,
        Method::Other(s) => {
            let m = s.as_str();
            !m.eq_ignore_ascii_case("LOCK") && !m.eq_ignore_ascii_case("PATCH")
        }
        _ => true,
    } || nu_flags & nu::NON_IDEMPOTENT != 0;
    let mut attempts = 0u32;

    'candidates: for (cand_idx, cand) in candidates.iter().enumerate() {
        // Respect `proxy_next_upstream_tries` / `_timeout` before every new
        // attempt (nginx checks both in `ngx_http_upstream_next`).
        attempts += 1;
        if nu_tries > 0 && attempts > nu_tries {
            break;
        }
        if !nu_timeout.is_zero() && nu_start.elapsed() >= nu_timeout {
            break;
        }
        // One entry in `$upstream_*` per backend tried.
        let tidx = crate::timing::begin();
        let t_up = std::time::Instant::now();
        let mut key = pool_key_of(cand);
        let upstream_addr = match cand {
            Chosen::Direct(_, a) => a.to_string(),
            Chosen::Unix(p) => format!("unix:{}", p.display()),
            Chosen::Upstream { addr, .. } => addr.to_string(),
        };
        crate::timing::set_addr(tidx, &upstream_addr);
        // A status-triggered retry must be decided before anything reaches the
        // client, and is only offered when another peer could still take the
        // request and the method may be replayed.
        let status_retry = (!nu_off
            && cand_idx + 1 < candidates.len()
            && method_retryable
            && nu_flags & nu::ANY_HTTP != 0)
            .then_some(nu_flags);
        // First attempt may reuse a pooled socket; if that socket turns out to
        // be dead, retry the same backend once on a fresh connection.
        for attempt in 0..2 {
            let want_pool = attempt == 0;
            let (stream, from_pool, up_idx, sidx) = match cand {
                Chosen::Direct(_, addr) => {
                    let pooled = if want_pool { checkout(key) } else { None };
                    let pooled = pooled.map(|(s, created, requests)| {
                        key.created = created;
                        key.requests = requests;
                        s
                    });
                    match pooled {
                        Some(s) => (s, true, usize::MAX, 0),
                        None => match connect_bound(*addr, bind, loc.proxy_connect_timeout).await {
                            Ok(s) => {
                                let up = if pp.https {
                                    match tls_wrap(
                                        s,
                                        loc.proxy_ssl_name.as_deref().unwrap_or(&pp.host_header),
                                        loc.proxy_ssl_session_reuse,
                                        loc.proxy_connect_timeout,
                                        client_cert_opt(loc, vars).as_ref(),
                                    )
                                    .await
                                    {
                                        Ok(t) => t,
                                        Err(e) => {
                                            last_err = Some(e);
                                            continue 'candidates;
                                        }
                                    }
                                } else {
                                    UpStream::Tcp(s)
                                };
                                (up, false, usize::MAX, 0)
                            }
                            Err(e) => {
                                let retry = connect_retry(&e, nu_flags);
                                last_err = Some(e);
                                if !retry {
                                    break 'candidates;
                                }
                                continue 'candidates;
                            }
                        },
                    }
                }
                Chosen::Unix(path) => match connect_unix(path, loc.proxy_connect_timeout).await {
                    Ok(s) => (s, false, usize::MAX, 0),
                    Err(e) => {
                        let retry = connect_retry(&e, nu_flags);
                        last_err = Some(e);
                        if !retry {
                            break 'candidates;
                        }
                        continue 'candidates;
                    }
                },
                Chosen::Upstream { up, sidx, addr, .. } => {
                    let pooled = if want_pool && http.upstreams[*up].keepalive > 0 {
                        checkout(key).map(|(st, created, requests)| {
                            key.created = created;
                            key.requests = requests;
                            st
                        })
                    } else {
                        None
                    };
                    match pooled {
                        Some(s) => (s, true, *up, *sidx),
                        None => match connect_bound(*addr, bind, loc.proxy_connect_timeout).await {
                            Ok(s) => {
                                let stream = if pp.https {
                                    match tls_wrap(
                                        s,
                                        loc.proxy_ssl_name.as_deref().unwrap_or(&pp.host_header),
                                        loc.proxy_ssl_session_reuse,
                                        loc.proxy_connect_timeout,
                                        client_cert_opt(loc, vars).as_ref(),
                                    )
                                    .await
                                    {
                                        Ok(t) => t,
                                        Err(e) => {
                                            peer_mark(*up, *sidx, true);
                                            last_err = Some(e);
                                            continue 'candidates;
                                        }
                                    }
                                } else {
                                    UpStream::Tcp(s)
                                };
                                (stream, false, *up, *sidx)
                            }
                            Err(e) => {
                                peer_mark(*up, *sidx, true);
                                let retry = connect_retry(&e, nu_flags);
                                last_err = Some(e);
                                if !retry {
                                    break 'candidates;
                                }
                                continue 'candidates;
                            }
                        },
                    }
                }
            };
            if up_idx != usize::MAX {
                active_add(up_idx, sidx, 1);
            }
            // nginx records 0 for a connection taken from the keepalive pool.
            crate::timing::set_connect(
                tidx,
                if from_pool {
                    std::time::Duration::ZERO
                } else {
                    t_up.elapsed()
                },
            );

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
                    reval: reval_entry,
                    reval_sig: reval_sig.as_deref(),
                    stale: stale_entry.as_ref(),
                    no_store: lock_timed_out,
                    min_uses_ok,
                },
                &upstream_addr,
                vars,
                convert_head,
                http,
                tidx,
                status_retry,
            )
            .await;

            if up_idx != usize::MAX {
                active_add(up_idx, sidx, -1);
            }
            crate::timing::set_response(tidx, t_up.elapsed());

            match result {
                Ok(o) => {
                    if let Chosen::Upstream { up, sidx, .. } = cand {
                        // A completed exchange is a successful attempt: it
                        // refreshes `checked` but does not reset `fails`
                        // (probed against nginx 1.28).
                        peer_mark(*up, *sidx, false);
                    }
                    return Ok(Some(o));
                }
                Err(e) => {
                    // The status matched a `proxy_next_upstream http_XXX`
                    // flag: nothing reached the client, discard the attempt.
                    if let Some(code) = as_retry(&e) {
                        if !matches!(code, 403 | 404) {
                            if let Chosen::Upstream { up, sidx, .. } = cand {
                                peer_mark(*up, *sidx, true);
                            }
                        }
                        wanted_more = true;
                        continue 'candidates;
                    }
                    let retry_conn = connect_retry(&e, nu_flags) && method_retryable;
                    last_err = Some(e);
                    if from_pool {
                        // Stale pooled socket: a request may have partially
                        // reached the upstream, so retry only against the same
                        // backend to stay safe for idempotent requests.
                        if req.method.is_read() {
                            continue;
                        }
                    } else {
                        // The request already reached this peer, so nginx
                        // only moves on for idempotent methods.
                        if let Chosen::Upstream { up, sidx, .. } = cand {
                            peer_mark(*up, *sidx, true);
                        }
                        if !retry_conn {
                            break 'candidates;
                        }
                    }
                    // Falling through to the next candidate means this
                    // request still wants a peer; exhausting the list that
                    // way is nginx's "no live upstreams".
                    wanted_more = true;
                    continue 'candidates;
                }
            }
        }
    }

    if let Some(e) = &last_err {
        eprintln!(
            "ngxrs: [error] upstream failure for {}: {e}",
            req.raw_target
        );
    }
    // nginx answers 504 for a timeout (connect, handshake or read) and 502 for
    // any other upstream failure.
    let status = match &last_err {
        Some(e) if e.kind() == io::ErrorKind::TimedOut => 504,
        _ => 502,
    };
    if last_err.is_some() && wanted_more {
        note_group_name(http, &pp);
    }
    // A connection-level failure never reaches the client directly: nginx
    // passes it through `ngx_http_special_response_handler`, so `error_page 502`
    // / `error_page 504` apply. Nothing has been written at this point, which is
    // what lets `Proxied::Intercept` hand the status to the normal pipeline --
    // without this, `error_page 504 502 /50x` was silently ignored for every
    // connect/read error and the resolver tests only ever saw a bare 502.
    Ok(Some(Proxied::Intercept {
        status,
        headers: Vec::new(),
    }))
}

/// `proxy_ssl_certificate` + `proxy_ssl_certificate_key`, when both are set.
///
/// nginx requires the pair; a certificate without a key is a config error, so
/// returning `None` here only happens when the pair is genuinely absent.
fn client_cert_opt(
    loc: &crate::config::LocCfg,
    vars: &crate::http::ServerVars<'_>,
) -> Option<(std::path::PathBuf, std::path::PathBuf, Vec<String>)> {
    match (&loc.proxy_ssl_certificate, &loc.proxy_ssl_certificate_key) {
        (Some(c), Some(k)) => {
            let pw = loc
                .proxy_ssl_password_file
                .as_ref()
                .and_then(|p| crate::tls::read_passwords(p).ok())
                .unwrap_or_default();
            // nginx evaluates these as complex values. The test harness
            // selects the certificate per request via `$arg_*`, so expanding
            // here is what makes `proxy_ssl_certificate` behave like nginx.
            Some((expand_path(c, vars), expand_path(k, vars), pw))
        }
        _ => None,
    }
}

/// Expand `$var` in a configured path at request time.
fn expand_path(raw: &std::path::Path, vars: &crate::http::ServerVars<'_>) -> std::path::PathBuf {
    let s = raw.to_string_lossy();
    if !s.contains('$') {
        return raw.to_path_buf();
    }
    std::path::PathBuf::from(vars.expand(&s))
}

async fn connect_timeout(addr: SocketAddr, dur: Duration) -> io::Result<UpStream> {
    Ok(UpStream::Tcp(connect_bound(addr, None, dur).await?))
}

/// Wrap an established TCP connection in TLS for `proxy_pass https://`.
///
/// The SNI name is `proxy_ssl_name` when configured, else the authority of the
/// `proxy_pass` URL -- nginx's `u->conf->ssl_name` falls back to `u->host`.
async fn tls_wrap(
    tcp: TcpStream,
    sni: &str,
    reuse: bool,
    dur: Duration,
    client_cert: Option<&(std::path::PathBuf, std::path::PathBuf, Vec<String>)>,
) -> io::Result<UpStream> {
    // `proxy_ssl_certificate` makes us authenticate to the upstream. Cached
    // per (cert, key) so resumption keeps working, same reason as tls_connector.
    let connector = match client_cert {
        Some((cert, key, pw)) => crate::tls::upstream_connector_with_client_cert(
            cert,
            key,
            pw,
            reuse,
            b"http/1.1",
        )?,
        None => tls_connector(reuse)?,
    };
    // `proxy_ssl_name` / `u->host` never carries the port, but the authority we
    // keep as `host_header` does (`127.0.0.1:8082`), so strip it here. A bare IP
    // is a valid `ServerName` but an `IP:port` string is not.
    let host = authority_host(sni);
    let name = match rustls::pki_types::ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS server name",
            ))
        }
    };
    let tls = tokio::time::timeout(dur, connector.connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))??;
    Ok(UpStream::Tls(Box::new(tls)))
}

/// A cached TLS client per resumption setting.
///
/// `proxy_ssl_session_reuse on` is the nginx default, and it only works if the
/// same `ClientConfig` (with its session store) outlives the connection:
/// building one per connection starts from an empty store every time, so the
/// upstream can never answer `$ssl_session_reused` with `r`.
fn tls_connector(reuse: bool) -> io::Result<tokio_rustls::TlsConnector> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<std::collections::HashMap<bool, tokio_rustls::TlsConnector>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    if let Some(c) = cache.lock().unwrap().get(&reuse) {
        return Ok(c.clone());
    }
    let connector = crate::grpc::proxy_tls_connector_with_reuse(reuse)
        .ok_or_else(|| io::Error::other("no TLS client config"))?;
    cache.lock().unwrap().insert(reuse, connector.clone());
    Ok(connector)
}

/// `proxy_pass http://unix:/path:`. A missing socket file is reported like any
/// refused connect, so `proxy_next_upstream` can move on.
async fn connect_unix(path: &std::path::Path, dur: Duration) -> io::Result<UpStream> {
    match tokio::time::timeout(dur, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(s)) => Ok(UpStream::Unix(s)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
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

/// The proxy's own error response (502 "no live upstreams" style): unlike
/// `respond_error` it still runs the location's `add_header` set, so
/// `add_header X-IP $upstream_addr always` shows the attempted peers and the
/// upstream group name — nginx records the group name as a final
/// `$upstream_addr` entry when peer selection reports "no live upstreams".
#[allow(clippy::too_many_arguments)]
async fn respond_error_upstream(
    conn: &mut crate::conn::Conn,
    status: u16,
    tokens: bool,
    keepalive: bool,
    loc: &LocCfg,
    pp: &crate::config::ProxyPass,
) -> io::Result<Outcome> {
    let body = crate::http::error_body(status, tokens);
    let addr = crate::timing::variable("upstream_addr").unwrap_or_default();
    let mut raw = b"Content-Type: text/html\r\n".to_vec();
    crate::http::apply_add_headers_proxy(
        &mut raw,
        &loc.headers,
        status,
        "",
        &addr,
        &[],
        &pp.host_header,
        None,
    );
    raw.extend_from_slice(b"Content-Length: ");
    raw.extend_from_slice(body.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n");
    let resp = Response::raw(status, raw, crate::http::Body::Bytes(body));
    let bytes = crate::http::write_response(conn, resp, keepalive, tokens, false).await?;
    Ok(Outcome {
        status,
        bytes,
        close: false,
        sent: Vec::new(),
    })
}

/// nginx appends the upstream group name to `$upstream_addr` when a peer
/// selection found nothing live: the attempt list gains one entry that has an
/// address (the name) but no timings, which is exactly how it renders.
fn note_group_name(http: &Http, pp: &crate::config::ProxyPass) {
    if let crate::config::ProxyTarget::Upstream(i) = &pp.target {
        if let Some(up) = http.upstreams.get(*i) {
            let tidx = crate::timing::begin();
            crate::timing::set_addr(tidx, &up.name);
        }
    }
}

#[allow(clippy::too_many_arguments)]
struct CacheCtx<'a> {
    zone: Option<&'a crate::config::CacheZone>,
    key: Option<&'a str>,
    status: &'a str,
    /// Expired entry that may be revalidated with `If-None-Match` / `If-Modified-Since`.
    reval: Option<&'a crate::cache::Cached>,
    /// Variant signature of `reval`, when it was stored as a variant.
    reval_sig: Option<&'a str>,
    /// Expired entry kept for `proxy_cache_use_stale`: if the upstream answers
    /// with a status the directive lists, this is served instead.
    stale: Option<&'a crate::cache::Cached>,
    /// Whether `proxy_cache_min_uses` has been reached for this key.
    min_uses_ok: bool,
    /// `proxy_cache_lock` was on but this request gave up waiting. nginx turns
    /// that into `NGX_HTTP_CACHE_SCARCE` and clears `u->cacheable`, so the
    /// response is served but never stored.
    no_store: bool,
}

/// Result of one proxy attempt.
///
/// The proxy normally writes the response itself (it streams to the socket), but
/// `proxy_intercept_errors` needs the error_page machinery in `http`, which runs
/// after the content phase — so that case hands the status back instead.
pub enum Proxied {
    /// The response is already on the wire.
    Written(Outcome),
    /// Nothing was written; the caller must run `error_page` for this status.
    Intercept {
        status: u16,
        /// `WWW-Authenticate` survives the interception (nginx copies it into
        /// `r->headers_out` in `ngx_http_upstream_intercept_errors`).
        headers: Vec<(String, String)>,
    },
}

/// nginx's `ngx_http_upstream_cache_check_range`: may the cache be used for
/// this ranged request?
///
/// `false` means the request bypasses the cache (and keeps its `Range` header),
/// which nginx signals with NGX_DECLINED.
fn cache_range_allowed(loc: &LocCfg, req: &Request, min_uses_ok: bool) -> bool {
    // Below `proxy_cache_min_uses` nothing is stored, so the cache cannot serve
    // a later range request either; let the Range header through to the origin.
    if !min_uses_ok {
        return false;
    }
    let Some(header) = req.headers.get("range") else {
        return true;
    };
    let Some(max) = loc.proxy_cache_max_range_offset else {
        // Unlimited: never bypass.
        return true;
    };
    if max == 0 {
        return false;
    }
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return true;
    };
    let spec = spec.trim_start();
    if spec.starts_with('-') {
        // Suffix range: nginx declines.
        return false;
    }
    let digits: String = spec.chars().take_while(|c| c.is_ascii_digit()).collect();
    match digits.parse::<u64>() {
        Ok(offset) => offset < max,
        Err(_) => true,
    }
}

fn written(o: Outcome) -> Proxied {
    Proxied::Written(o)
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
    reval: Option<&crate::cache::Cached>,
    drop_range: bool,
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
            "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-connection"
                | "content-length"
                | "expect"
        ) {
            continue;
        }
        // When the cache is going to be used, nginx fetches the *whole* entity
        // so later range requests can be served from it.
        if drop_range && (lk == "range" || lk == "if-range") {
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

    // `proxy_cache_revalidate`: nginx's default proxy config sets these two from
    // `$upstream_cache_last_modified` / `$upstream_cache_etag`, which are only
    // defined for an EXPIRED entry with revalidation on. A user
    // `proxy_set_header` for either name wins.
    // nginx strips `Last-Modified` from anything but a 200/206 before storing
    // it, which is what makes conditional requests possible only for those two
    // statuses (`proxy_cache_revalidate.t`: "other status no revalidation").
    if let Some(entry) = reval.filter(|e| e.status == 200 || e.status == 206) {
        for (want, name) in [
            ("last-modified", "If-Modified-Since"),
            ("etag", "If-None-Match"),
        ] {
            if set.contains_key(&want.to_string()) {
                continue;
            }
            if let Some((_, v)) = entry
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(want))
            {
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(v.as_bytes());
                out.extend_from_slice(b"\r\n");
                wrote.push(want.to_string());
            }
        }
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
        // The value must be **expanded** before deciding: `proxy_set_header
        // Connection $args` with empty `$args` means "send no Connection header"
        // (keepalive), which is how `upstream_keepalive.t` enables pooling.
        match set.get("connection") {
            Some(v) => {
                let v = expand(v, &vars);
                if !v.is_empty() {
                    out.extend_from_slice(b"Connection: ");
                    out.extend_from_slice(v.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            // Nothing configured: nginx's own proxy config sets `Connection:
            // close` so a bare `proxy_pass` never pools.
            None => out.extend_from_slice(b"Connection: close\r\n"),
        }
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }

    if !body_of_request.is_empty() || req.body_len > 0 || req.chunked || req.buffered_body.is_some()
    {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body_of_request.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[allow(clippy::too_many_arguments)]
/// Write a stored cache entry to the client, reporting `hit_status` in
/// `$upstream_cache_status`. Shared by the HIT/STALE/UPDATING path and by
/// `proxy_cache_use_stale` when the upstream answers with a listed status.
async fn serve_cached(
    conn: &mut crate::conn::Conn,
    req: &Request,
    loc: &LocCfg,
    http: &crate::config::Http,
    tokens: bool,
    entry: &crate::cache::Cached,
    hit_status: &str,
) -> io::Result<Proxied> {
    let mut raw = Vec::with_capacity(entry.body.len() + 256);
    for (k, v) in &entry.headers {
        raw.extend_from_slice(k.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(v.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    crate::http::apply_add_headers_upstream(&mut raw, &loc.headers, entry.status, hit_status, "");
    // The stored headers may already carry a Content-Length.
    if !entry
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        raw.extend_from_slice(b"Content-Length: ");
        raw.extend_from_slice(entry.body.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    // A range is served out of the cached body when the origin advertised
    // `Accept-Ranges: bytes` (nginx keeps that header in the cache entry);
    // `proxy_force_ranges` overrides it.
    let ranges_from_cache = loc.proxy_force_ranges
        || entry.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("accept-ranges") && v.trim().eq_ignore_ascii_case("bytes")
        });
    let mut status = entry.status;
    let mut body = entry.body.clone();
    if ranges_from_cache {
        let (s2, raw2, body2) = apply_force_ranges(req, status, &mut raw, body, loc.max_ranges.unwrap_or(u32::MAX));
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
        server_tokens: None,

        headers_finalized: false,
        body: crate::http::Body::Bytes(body),
    };
    // gzip is an output filter in nginx, so a served-from-cache body goes
    // through it exactly like a fresh one.
    let resp = crate::gzip::maybe_compress(req, resp, loc, http);
    let bytes = crate::http::write_response(
        conn,
        resp,
        req.keepalive,
        tokens,
        req.method == Method::Head,
    )
    .await?;
    Ok(written(Outcome {
        status,
        bytes,
        close: false,
        sent: Vec::new(),
    }))
}

async fn exchange(
    conn: &mut crate::conn::Conn,
    req: &Request,
    target_uri: &str,
    body: &[u8],
    loc: &LocCfg,
    pp: &crate::config::ProxyPass,
    mut up: UpStream,
    from_pool: bool,
    tokens: bool,
    is_upgrade: bool,
    peer_ip: &str,
    pool_key: PoolKey,
    cache: CacheCtx<'_>,
    upstream_addr: &str,
    vars: &crate::http::ServerVars<'_>,
    convert_head: bool,
    http: &crate::config::Http,
    tidx: usize,
    // `Some(proxy_next_upstream flags)` when a status-triggered retry is
    // allowed for this attempt (another peer can still take the request);
    // the caller only offers it before anything reaches the client.
    status_retry: Option<u32>,
) -> io::Result<Proxied> {
    let t_up = Instant::now();
    // ---- request head ----
    // The cache only helps a ranged request if it can hold the whole entity, so
    // the Range header is withheld from the upstream while the cache is in play
    // (`ngx_http_proxy_create_request` + `ngx_http_upstream_cache_check_range`).
    let drop_range =
        cache.zone.is_some() && cache.key.is_some() && cache.status != "BYPASS" && !is_upgrade;
    let out = build_upstream_head(
        req,
        target_uri,
        body,
        loc,
        pp,
        peer_ip,
        is_upgrade,
        convert_head,
        cache.reval,
        drop_range,
    );

    if std::env::var_os("NGXRS_DEBUG_PROXY").is_some() {
        eprintln!(
            "ngxrs: [debug] upstream request:\n{}",
            String::from_utf8_lossy(&out)
        );
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
            let h = parse_upstream_head(&buf[..pos]).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "bad upstream response")
            })?;
            buf = buf.split_off(pos);
            crate::timing::set_header(tidx, t_up.elapsed());
            break h;
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream head too large",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
        }
        let mut chunk = [0u8; 8192];
        // Race the upstream against a client disconnect. nginx finalizes the
        // request as soon as the client goes away, which is what frees a
        // `limit_conn` slot while the upstream is still thinking.
        // nginx finalizes the upstream request as soon as the client goes
        // away: `$upstream_header_time` stays unset and the `limit_conn` slot
        // is released (`ngx_http_upstream_finalize_request`). Watching costs a
        // timer per poll step, so the step starts at 1 ms and backs off.
        let watch_client = true;
        let read = tokio::select! {
            r = tokio::time::timeout(remaining, up.read(&mut chunk)) => r,
            _ = conn.peer_closed(), if watch_client => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client closed"));
            }
        };
        let n = match read {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed",
            ));
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

    // ---- `proxy_cache_use_stale` on an upstream status ----
    // An expired entry may stand in for the upstream reply when the directive
    // lists that status (`... http_404 http_500`). nginx makes this decision
    // where the upstream headers are parsed, which is here.
    if let Some(entry) = cache.stale {
        if loc.proxy_cache_use_stale_codes.contains(&head.status) {
            return serve_cached(conn, req, loc, http, tokens, entry, "STALE").await;
        }
    }

    // ---- `proxy_next_upstream http_XXX`: try the next peer instead ----
    //
    // nginx decides in `ngx_http_upstream_test_next`, i.e. right after the
    // head is parsed and before anything is relayed or cached. The caller
    // only sets `status_retry` when another peer remains, so the last
    // candidate is always served.
    crate::timing::set_status(tidx, head.status);
    if let Some(nu_flags) = status_retry {
        let flag = status_flag(head.status);
        if flag != 0 && nu_flags & flag != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                RetryNextUpstream(head.status),
            ));
        }
    }

    // ---- 304 on a revalidated entry: serve the cached body as REVALIDATED ----
    //
    // nginx keeps the stored response and only refreshes its validity, so the
    // client sees the cached status (200) and headers, not a 304.
    if head.status == 304 {
        if let (Some(entry), Some(zone), Some(key)) = (cache.reval, cache.zone, cache.key) {
            if loc.proxy_cache_revalidate {
                let now = crate::cache::now();
                // `r->cache->date = now` plus the original valid_sec window.
                let refreshed = crate::cache::Cached {
                    stored_at: now,
                    ..entry.clone()
                };
                let _ = crate::cache::restore(zone, key, cache.reval_sig, &refreshed);

                let mut raw = Vec::with_capacity(entry.body.len() + 256);
                for (k, v) in &entry.headers {
                    raw.extend_from_slice(k.as_bytes());
                    raw.extend_from_slice(b": ");
                    raw.extend_from_slice(v.as_bytes());
                    raw.extend_from_slice(b"\r\n");
                }
                crate::http::apply_expires(&mut raw, loc, entry.status, Some(&vars.expand(loc.expires.as_deref().unwrap_or(""))));
                apply_proxy_redirect(&mut raw, loc, vars);
                crate::http::apply_add_headers_upstream(
                    &mut raw,
                    &loc.headers,
                    entry.status,
                    "REVALIDATED",
                    "",
                );
                if !entry
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                {
                    raw.extend_from_slice(b"Content-Length: ");
                    raw.extend_from_slice(entry.body.len().to_string().as_bytes());
                    raw.extend_from_slice(b"\r\n");
                }
                let ranges_from_cache = loc.proxy_force_ranges
                    || entry.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("accept-ranges")
                            && v.trim().eq_ignore_ascii_case("bytes")
                    });
                let mut status = entry.status;
                let mut body = entry.body.clone();
                if ranges_from_cache {
                    let (s2, raw2, body2) =
                        apply_force_ranges(req, status, &mut raw, body, loc.max_ranges.unwrap_or(u32::MAX));
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
                    server_tokens: None,

                    headers_finalized: false,
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
                // A 304 keeps the upstream usable, exactly like a normal reply.
                let reuse =
                    head.keepalive && !is_upgrade && loc.proxy_http_version == 1 && !req.chunked;
                if reuse {
                    let cap = match pp.target {
                        crate::config::ProxyTarget::Upstream(i) => {
                            loc_upstream_cap(i, pp).unwrap_or(0)
                        }
                        _ => 0,
                    };
                    checkin(pool_key, up, cap);
                }
                return Ok(written(Outcome {
                    status,
                    bytes,
                    close: false,
                    sent: Vec::new(),
                }));
            }
        }
    }

    // ---- `proxy_intercept_errors`: let `error_page` handle this status ----
    //
    // nginx decides this in `ngx_http_upstream_intercept_errors`, called from
    // `ngx_http_upstream_process_headers` — i.e. right after the head is parsed
    // and before the body is relayed or cached. `WWW-Authenticate` is copied
    // into `r->headers_out` first so it survives the internal redirect.
    if loc.proxy_intercept_errors
        && crate::util::is_special_status(head.status)
        && loc.error_pages.contains_key(&head.status)
    {
        let preserved = if head.status == 401 {
            crate::http::split_head(&head.raw)
                .into_iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
                .collect()
        } else {
            Vec::new()
        };
        // Record the error in the cache so later requests replay it, even if
        // the upstream resource shows up in the meantime (nginx ticket #827).
        if let (Some(zone), Some(key)) = (cache.zone, cache.key) {
            // `proxy_cache_bypass` means "do not use the cache at all", so such
            // a request must not seed an error entry either.
            if cache.status != "BYPASS" {
                // The upstream headers decide cacheability here too: a
                //  on the error stores it for N
                // seconds (nginx ticket #1382),  stores nothing.
                let cc_headers = crate::http::split_head(&head.raw);
                if let Some(valid) =
                    crate::cache::ttl(loc, head.status, &cc_headers, loc.proxy_cache_ignore)
                {
                    let entry = crate::cache::Cached {
                        status: head.status,
                        error: Some(head.status),
                        headers: Vec::new(),
                        body: Vec::new(),
                        stored_at: crate::cache::now(),
                        valid_for: valid.as_secs(),
                    };
                    let _ = crate::cache::store(zone, key, &entry);
                }
            }
        }
        return Ok(Proxied::Intercept {
            status: head.status,
            headers: preserved,
        });
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
        match up {
            UpStream::Tcp(tcp) => conn.pipe_with(tcp).await?,
            // `proxy_pass http://unix:` cannot be upgraded; answer like an
            // unusable upstream so the client is not left hanging.
            // A TLS session cannot be spliced either: `pipe_with` needs the raw
            // socket, and an upgrade over TLS would have to re-encrypt both
            // directions.
            UpStream::Unix(_) | UpStream::Tls(_) => {
                return Ok(written(Outcome {
                    status: 502,
                    bytes: 0,
                    close: true,
                    sent: Vec::new(),
                }))
            }
        }
        return Ok(written(Outcome {
            status: 101,
            bytes: 0,
            close: true,
            sent: Vec::new(),
        }));
    }

    // ---- body ----
    //
    // A response with no body never has one, whatever its headers say: `HEAD`
    // (we asked the upstream for headers only), 204, 304 and 1xx. The `304` case
    // is the trap -- `304len` in `proxy_keepalive.t` carries
    // `Content-Length: 100`, which describes the *entity* the client already
    // has, not bytes that follow. Reading it blocked until `proxy_read_timeout`
    // and the client got nothing at all ("buffered 304").
    let bodyless = req.method == Method::Head
        || head.status == 204
        || head.status == 304
        || (100..200).contains(&head.status);
    let total_len = if bodyless {
        Some(0)
    } else if head.chunked {
        None
    } else {
        head.content_length
    };
    let mut raw = head.raw;
    // Synthesise a length only when a body is actually coming: adding
    // `Content-Length: 0` to a 304 would be a lie about the entity.
    if let Some(len) = total_len {
        if !bodyless
            && !raw
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
    // Slicing is needed when `proxy_force_ranges` asks for it *or* when the
    // cache withheld the Range header upstream: then the body in hand is the
    // whole entity and the client still expects its range.
    let wants_ranges =
        (loc.proxy_force_ranges || drop_range) && req.headers.get("range").is_some() && !is_upgrade;
    let cacheable = cache.zone.is_some()
        && cache.key.is_some()
        && !is_upgrade
        && !cache.no_store
        && cache.min_uses_ok;
    // `proxy_buffering on` (the default) makes nginx absorb a chunked upstream
    // reply and re-send it with a Content-Length, so the client never sees the
    // upstream's chunk framing (`proxy_chunked.t` checks the raw bytes).
    //
    // OFF by default: enabling it fixes `proxy_chunked.t` #1 but costs five
    // assertions in `proxy_cache_vary.t` (entries start reporting HIT where
    // nginx says MISS) and the mechanism is not understood yet. Shipping an
    // unexplained behaviour change for a net -4 is worse than the missing
    // assertion. See OPEN-ISSUES in COMPAT.md.
    const BUFFER_CHUNKED_UPSTREAM: bool = true;
    let buffered_chunked = BUFFER_CHUNKED_UPSTREAM
        && loc.proxy_buffering
        && head.chunked
        && !is_upgrade
        && total_len.is_none();
    if cacheable || wants_ranges || buffered_chunked {
        let mut payload = buf;
        match (head.chunked, total_len) {
            // Chunked: read to the terminator, then decode. The terminator is
            // the blank line *after* the `0` size line, which may arrive later
            // than the `0` itself; stopping at the `0` left that byte in a socket
            // that then went back to the pool ("buffered complex chunked 2").
            (true, _) => loop {
                if chunked_body_end(&payload).is_some() {
                    break;
                }
                let mut chunk = vec![0u8; 64 * 1024];
                match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => payload.extend_from_slice(&chunk[..n]),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
                }
            },
            (false, Some(len)) => {
                while (payload.len() as u64) < len {
                    let mut chunk = vec![0u8; (len - payload.len() as u64).min(64 * 1024) as usize];
                    let n = match tokio::time::timeout(loc.proxy_read_timeout, up.read(&mut chunk))
                        .await
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
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
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
                        headers: stored_headers.clone(),
                        body: payload.clone(),
                        stored_at: crate::cache::now(),
                        valid_for: valid.as_secs(),
                        error: None,
                    };
                    // `Vary: *` says the representation may depend on anything
                    // about the request, so nginx does not store it at all.
                    if loc.proxy_cache_ignore.vary || !crate::cache::vary_star(&stored_headers) {
                        let get = |n: &str| req.headers.get_joined(n).unwrap_or_default();
                        let _ = crate::cache::store_repr(
                            zone,
                            key,
                            &stored_headers,
                            get,
                            &entry,
                            loc.proxy_cache_ignore.vary,
                        );
                    }
                }
            }
        }

        let mut out_raw = raw;
        apply_cookie_rules(&mut out_raw, loc, vars);
        apply_proxy_redirect(&mut out_raw, loc, vars);
        crate::http::apply_expires(&mut out_raw, loc, head.status, Some(&vars.expand(loc.expires.as_deref().unwrap_or(""))));
        crate::http::apply_add_headers_upstream(
            &mut out_raw,
            &loc.headers,
            head.status,
            cache.status,
            upstream_addr,
        );
        // We dechunked a buffered upstream reply, so the framing header must go
        // and a Content-Length takes its place.
        if buffered_chunked {
            out_raw = drop_header(&out_raw, "transfer-encoding");
        }
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
            let (s2, raw2, body2) = apply_force_ranges(req, status, &mut out_raw, payload, loc.max_ranges.unwrap_or(u32::MAX));
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
                    server_tokens: None,

                    headers_finalized: false,
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
                return Ok(written(Outcome {
                    status,
                    bytes,
                    close: false,
                    sent: Vec::new(),
                }));
            }
        }
        write_head(conn, status, &out_raw, req.keepalive, tokens).await?;
        // A converted HEAD gets no body even though the upstream sent one.
        if req.method != Method::Head {
            conn.write_all(&payload).await?;
        }
        // The body was read to its end (length, terminator or EOF), so the
        // upstream connection is at a message boundary and can be reused --
        // including after a buffered chunked reply, which is what
        // "buffered chunked 2" / "buffered 0 chunk 2" measure.
        let reuse = head.keepalive && !is_upgrade && loc.proxy_http_version == 1 && !req.chunked;
        if reuse {
            let cap = match pp.target {
                crate::config::ProxyTarget::Upstream(i) => loc_upstream_cap(i, pp).unwrap_or(0),
                _ => 0,
            };
            checkin(pool_key, up, cap);
        }
        return Ok(written(Outcome {
            status,
            bytes: payload.len() as u64,
            close: false,
            sent: Vec::new(),
        }));
    }

    let mut raw = raw;
    apply_proxy_redirect(&mut raw, loc, vars);
    crate::http::apply_expires(&mut raw, loc, head.status, Some(&vars.expand(loc.expires.as_deref().unwrap_or(""))));
    let upstream_headers = crate::http::split_head(&raw);
    crate::http::apply_add_headers_ctx(
        &mut raw,
        &loc.headers,
        head.status,
        cache.status,
        upstream_addr,
        &upstream_headers,
        Some(vars),
        &pp.host_header,
    );
    apply_cookie_rules(&mut raw, loc, vars);
    // `add_trailer` forces chunked framing even when the upstream sent a
    // Content-Length: nginx sets `r->expect_trailers` and the header filter
    // drops the length in favour of `Transfer-Encoding: chunked`.
    // Only the *decision* is made here — nginx sets `expect_trailers` before the
    // values are known. The values themselves are evaluated after the body,
    // which matters for time-dependent ones like `$msec`.
    let (expect_trailers, _) = crate::http::eval_trailers(&loc.trailers, head.status, vars);
    if expect_trailers && !head.chunked {
        raw = strip_length_headers(&mut raw);
        raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    // A chunked upstream reply cannot stay chunked for an HTTP/1.0 client: the
    // body is dechunked below and the close delimits it.
    if head.chunked && req.version_minor != 1 {
        raw = drop_header(&raw, "transfer-encoding");
    }
    let sent_headers = crate::http::split_head(&raw);
    write_head(conn, head.status, &raw, req.keepalive, tokens).await?;

    let mut sent = 0u64;
    let mut pacer = Pacer::new(loc.proxy_limit_rate);
    if req.method == Method::Head {
        // We sent HEAD upstream, so no body follows and nothing needs draining;
        // the connection is at a message boundary and may go back to the pool.
        let reuse = head.keepalive && !is_upgrade && loc.proxy_http_version == 1 && !req.chunked;
        if reuse {
            let cap = match pp.target {
                crate::config::ProxyTarget::Upstream(i) => loc_upstream_cap(i, pp).unwrap_or(0),
                _ => 0,
            };
            checkin(pool_key, up, cap);
        }
        return Ok(written(Outcome {
            status: head.status,
            bytes: 0,
            close: false,
            sent: sent_headers,
        }));
    }
    // A chunked upstream ends at a known boundary too, so its connection is
    // just as reusable as a `Content-Length` one -- as long as the terminator
    // was actually read.
    let mut chunk_complete = false;
    if head.chunked {
        if req.version_minor == 1 {
            let (n, complete) =
                stream_chunked(conn, &mut up, buf, loc.proxy_read_timeout, &mut pacer).await?;
            sent = n;
            chunk_complete = complete;
        } else {
            // An HTTP/1.0 client cannot be sent chunked framing: nginx dechunks
            // and delimits the body by closing the connection instead. Passing
            // the upstream's chunks through gave the client `a\r\n0123456789\r\n`
            // where nginx gives it the digits alone ("unbuffered complex
            // chunked", `proxy_chunked.t`).
            let (n, complete) =
                stream_dechunked(conn, &mut up, buf, loc.proxy_read_timeout, &mut pacer).await?;
            sent = n;
            chunk_complete = complete;
        }
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
                pacer.tick(take as u64).await;
                if expect_trailers {
                    let mut framed = Vec::with_capacity(take + 16);
                    framed.extend_from_slice(format!("{take:x}\r\n").as_bytes());
                    framed.extend_from_slice(&pending[..take]);
                    framed.extend_from_slice(b"\r\n");
                    conn.write_all(&framed).await?;
                } else {
                    conn.write_all(&pending[..take]).await?;
                }
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
            pacer.tick(n as u64).await;
            if expect_trailers {
                let mut framed = Vec::with_capacity(n + 16);
                framed.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                framed.extend_from_slice(&chunk[..n]);
                framed.extend_from_slice(b"\r\n");
                conn.write_all(&framed).await?;
            } else {
                conn.write_all(&chunk[..n]).await?;
            }
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
            pacer.tick(n as u64).await;
            conn.write_all(&framed).await?;
        }
        conn.write_all(b"0\r\n\r\n").await?;
    }

    // ---- connection reuse ----
    let reuse = head.keepalive
        && (bodyless || total_len.is_some() || chunk_complete)
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

    // Close out the chunked framing with the trailer block. Only the
    // Content-Length path re-frames here; a chunked upstream already ends with
    // its own terminator and its trailers are passed through verbatim.
    if expect_trailers && !head.chunked {
        let (_, trailer_list) = crate::http::eval_trailers(&loc.trailers, head.status, vars);
        let mut tail = Vec::with_capacity(64);
        tail.extend_from_slice(b"0\r\n");
        for (k, v) in &trailer_list {
            tail.extend_from_slice(k.as_bytes());
            tail.extend_from_slice(b": ");
            tail.extend_from_slice(v.as_bytes());
            tail.extend_from_slice(b"\r\n");
        }
        tail.extend_from_slice(b"\r\n");
        conn.write_all(&tail).await?;
    }

    Ok(written(Outcome {
        status: head.status,
        bytes: sent,
        close: false,
        sent: sent_headers,
    }))
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
    let _ = UPSTREAM_KA.set(
        http.upstreams
            .iter()
            .map(|u| (u.keepalive_requests, u.keepalive_time, u.keepalive_timeout))
            .collect(),
    );
}

/// Paces the upstream→client copy for `proxy_limit_rate`.
///
/// nginx delays each read from the upstream pipe so the transfer as a whole
/// runs at the configured rate; the client sees the same total elapsed time.
struct Pacer {
    /// Bytes per second; 0 disables pacing.
    rate: u64,
    started: Option<std::time::Instant>,
    copied: u64,
}

impl Pacer {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            started: None,
            copied: 0,
        }
    }

    /// Sleep until the next `n` bytes are allowed out, then count them.
    ///
    /// The delay must happen *before* the write: sleeping afterwards would let
    /// the client see the whole body immediately and only the (already
    /// finished) request would linger.
    async fn tick(&mut self, n: u64) {
        if self.rate == 0 || n == 0 {
            return;
        }
        let start = *self.started.get_or_insert_with(std::time::Instant::now);
        let due = Duration::from_secs_f64((self.copied + n) as f64 / self.rate as f64);
        if let Some(wait) = due.checked_sub(start.elapsed()) {
            tokio::time::sleep(wait).await;
        }
        self.copied += n;
    }
}

/// Stream a chunked upstream body **dechunked**, for clients that cannot be sent
/// chunked framing (HTTP/1.0). Bytes are forwarded as they arrive; the caller
/// closes the connection to mark the end.
async fn stream_dechunked(
    conn: &mut crate::conn::Conn,
    up: &mut UpStream,
    mut pending: Vec<u8>,
    read_timeout: Duration,
    pacer: &mut Pacer,
) -> io::Result<(u64, bool)> {
    let mut sent = 0u64;
    loop {
        let line_end = loop {
            if let Some(i) = memchr::memchr(b'\n', &pending) {
                break i;
            }
            let mut chunk = [0u8; 8192];
            let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => return Ok((sent, false)),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            pending.extend_from_slice(&chunk[..n]);
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&pending[..line_end])
                .trim()
                .split(';')
                .next()
                .unwrap_or("")
                .trim(),
            16,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk"))?;
        let need = line_end + 1 + size + 2;
        while pending.len() < need {
            let mut chunk = [0u8; 8192];
            let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                Ok(Ok(0)) => return Ok((sent, false)),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
            };
            pending.extend_from_slice(&chunk[..n]);
        }
        if size == 0 {
            // Trailers, then the blank line: wait for the real end so the
            // connection is at a message boundary.
            loop {
                if chunked_message_end(&pending, line_end + 1).is_some() {
                    return Ok((sent, true));
                }
                let mut chunk = [0u8; 8192];
                let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                    Ok(Ok(0)) => return Ok((sent, false)),
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
                };
                pending.extend_from_slice(&chunk[..n]);
            }
        }
        let data = pending[line_end + 1..line_end + 1 + size].to_vec();
        pacer.tick(size as u64).await;
        conn.write_all(&data).await?;
        sent += size as u64;
        pending.drain(..need);
    }
}

/// End of a chunked message: the offset just past the blank line that follows
/// the `0` size line and any trailer block. `start` is the byte after the `0`
/// line's CRLF.
fn chunked_message_end(pending: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    loop {
        let nl = pending.get(i..)?.iter().position(|&b| b == b'\n')? + i;
        let line = &pending[i..nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let next = nl + 1;
        if line.is_empty() {
            return Some(next);
        }
        i = next;
    }
}

async fn stream_chunked(
    conn: &mut crate::conn::Conn,
    up: &mut UpStream,
    mut pending: Vec<u8>,
    read_timeout: Duration,
    pacer: &mut Pacer,
) -> io::Result<(u64, bool)> {
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
                return Ok((sent, false));
            }
            pending.extend_from_slice(&chunk[..n]);
        };
        let line = String::from_utf8_lossy(&pending[..line_end])
            .trim()
            .to_string();
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
                return Ok((sent, false));
            }
            pending.extend_from_slice(&chunk[..n]);
        }

        let header_len = line_end + 1;
        if size == 0 {
            // The terminating `0` line is followed by an optional trailer block
            // and then a blank line, and the upstream may pause before that blank
            // line (`proxy_keepalive.t`'s "complex" case sleeps 50ms). Returning
            // as soon as the `0` line arrived sent a truncated chunked body and a
            // broken connection; wait for the real end of the message.
            loop {
                if let Some(end) = chunked_message_end(&pending, line_end + 1) {
                    conn.write_all(&pending[..end]).await?;
                    sent += end as u64;
                    return Ok((sent, true));
                }
                let mut chunk = [0u8; 8192];
                let n = match tokio::time::timeout(read_timeout, up.read(&mut chunk)).await {
                    Ok(Ok(0)) => {
                        conn.write_all(&pending).await?;
                        sent += pending.len() as u64;
                        return Ok((sent, false));
                    }
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
                };
                pending.extend_from_slice(&chunk[..n]);
            }
        }
        pacer.tick(size).await;
        conn.write_all(&pending[..need]).await?;
        sent += need as u64;
        size = 0;
        pending.drain(..need);
    }
}

/// The request body, however this connection carries it.
///
/// HTTP/1.1 has it on the socket; HTTP/2 and HTTP/3 collected it into
/// `Request::buffered_body` before routing. One helper so the upstream modules
/// do not each have to know which.
pub async fn take_request_body(
    conn: &mut crate::conn::Conn,
    req: &Request,
    max: usize,
) -> io::Result<Vec<u8>> {
    if let Some(b) = &req.buffered_body {
        if b.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        return Ok(b.clone());
    }
    if req.chunked {
        conn.take_chunked_body(max).await
    } else if req.body_len > 0 {
        conn.take_body(req.body_len as usize).await
    } else {
        Ok(Vec::new())
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
            return Err(crate::http::body_too_large());
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
                return Err(crate::http::body_too_large());
            }
            self.take_into(&mut out, size as usize).await?;
            // The line after the data must be empty: nginx answers 400 when it
            // is not (`body_chunked.t`, "runaway chunk").
            let tail = self.read_line_pub().await?;
            if !tail.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad chunk terminator",
                ));
            }
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
    custom: &std::collections::HashMap<String, String>,
) -> Option<Response> {
    let pp = loc.proxy_pass.clone()?;
    let fetch_vars = crate::http::ServerVars {
        req,
        path,
        query,
        server_name: "",
        server_port: 80,
        peer_ip,
        peer_port: 0,
        scheme: "http",
        document_root: "",
        upstream_cache_status: "",
        custom,
        connection_requests: 0,
        connection_time: 0,
        sent: &[],
    };
    let candidates = choose(http, loc, &peer_ip.parse().ok()?, Some(&fetch_vars))?;
    let target_uri = upstream_target(path, query, loc, &pp, &fetch_vars, false);

    // The socket-free path serves HTTP/2, HTTP/3, SSI includes and auth
    // subrequests, and it must honour `proxy_cache` exactly like the streaming
    // path: nginx's `auth_request` combined with `proxy_cache` is a documented
    // way to cache an authentication decision, and a hit is what makes the
    // second client request skip the upstream.
    let zone = loc
        .proxy_cache
        .as_deref()
        .and_then(|name| http.cache_zones.iter().find(|z| z.name == name));
    let cache_key = if zone.is_some() {
        cache_key_for(loc, req, peer_ip)
    } else {
        None
    };
    // `proxy_cache_bypass` turns every `$upstream_cache_status` into BYPASS;
    // otherwise the status has to distinguish a hit from an expired entry the
    // way the streaming path does (nginx reports EXPIRED, not MISS).
    let bypass_spec = Vars {
        req,
        peer_ip,
        scheme: "http",
        host: req.host.as_ref().map(|h| h.as_str()).unwrap_or(""),
        uri: path,
        args: query,
        server_port: 0,
    };
    let bypass = loc.proxy_cache_bypass.iter().any(|v| {
        let e = expand(v, &bypass_spec);
        let e = e.trim();
        !e.is_empty() && e != "0"
    });
    let mut cache_status = "MISS";
    let mut stale_entry: Option<crate::cache::Cached> = None;
    if let (Some(z), Some(key)) = (zone, cache_key.as_deref()) {
        if bypass {
            cache_status = "BYPASS";
        } else {
            // Vary-aware, exactly like the streaming path: a stored response
            // with `Vary` is indexed per request-header signature.
            let get = |name: &str| req.headers.get_joined(name).unwrap_or_default();
            match crate::cache::lookup(z, key, get) {
                Some((entry, _)) if entry.is_fresh(crate::cache::now()) => {
                    if entry.error.is_none() {
                        if let Some(nm) = cached_not_modified(&entry, req) {
                            return Some(nm);
                        }
                        return Some(cached_response(entry, loc, "HIT"));
                    }
                    cache_status = "HIT";
                    stale_entry = Some(entry);
                }
                Some((entry, _)) => {
                    // A stale copy is serviceable under the same two rules as
                    // the streaming path. The refresh is fire-and-forget here:
                    // nginx clones a subrequest for it and does *not* hold the
                    // client's response, which is what
                    // "stale response not blocked by background update" checks
                    // for a slow SSI include.
                    let now = crate::cache::now();
                    let stale_ok = (loc.proxy_cache_background_update
                        && entry.may_serve_stale(now))
                        || (loc.proxy_cache_use_stale_updating && updating_test(key));
                    if stale_ok {
                        if let Some(h) = spawn_background_update(
                            loc,
                            http,
                            req,
                            key.to_string(),
                            peer_ip,
                            &target_uri,
                            &entry,
                        ) {
                            drop(h);
                        }
                        if entry.error.is_none() {
                            return Some(cached_response(entry, loc, "STALE"));
                        }
                    }
                    cache_status = "EXPIRED";
                    stale_entry = Some(entry);
                }
                None => cache_status = "MISS",
            }
        }
    }

    let mut last_err: Option<io::Error> = None;
    for cand in candidates {
        // The socket-free path buffers the whole reply, so `proxy_bind` (which
        // needs a TCP socket) only applies to TCP targets.
        //
        // It shares the *same* keepalive pool as the streaming path. nginx's
        // pool is per-peer and used by every request that reaches that peer,
        // subrequests included, so an SSI `#include virtual=` goes out on the
        // already-open upstream connection instead of dialling a second one.
        // Without this, a backend that serves one connection at a time (the
        // daemon in `proxy_keepalive.t`) blocks: it is still reading the pooled
        // connection while the subrequest waits for it to accept a new one, and
        // `inmemory` never gets a reply.
        let mut key = pool_key_of(&cand);
        let pooled = checkout(key).map(|(s, created, requests)| {
            key.created = created;
            key.requests = requests;
            s
        });
        let mut reused = pooled.is_some();
        let mut up: UpStream = if let Some(s) = pooled {
            s
        } else if let Chosen::Unix(path) = &cand {
            match connect_unix(path, loc.proxy_connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        } else {
            let addr = match &cand {
                Chosen::Direct(_, a) => *a,
                Chosen::Upstream { addr, .. } => *addr,
                Chosen::Unix(_) => unreachable!(),
            };
            match connect_bound(
                addr,
                resolve_bind(
                    loc,
                    &BindVars {
                        peer_ip,
                        peer_port: 0,
                        query,
                    },
                )
                .ok()
                .flatten(),
                loc.proxy_connect_timeout,
            )
            .await
            {
                Ok(s) => UpStream::Tcp(s),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        };

        // The socket-free path (HTTP/2, HTTP/3, SSI, auth subrequests) carries
        // the body in memory rather than on a connection it can read.
        let in_memory = req.buffered_body.as_deref().unwrap_or(&[]);
        let out = build_upstream_head(
            req,
            &target_uri,
            in_memory,
            loc,
            &pp,
            peer_ip,
            false,
            false,
            None,
            false,
        );
        let write_failed = up.write_all(&out).await.is_err()
            || (!in_memory.is_empty() && up.write_all(in_memory).await.is_err());
        if write_failed {
            // A pooled socket the peer has since closed fails on the first
            // write; dial once more before giving up on this backend.
            if reused {
                reused = false;
                let fresh = match &cand {
                    Chosen::Unix(path) => connect_unix(path, loc.proxy_connect_timeout).await,
                    _ => {
                        let addr = match &cand {
                            Chosen::Direct(_, a) => *a,
                            Chosen::Upstream { addr, .. } => *addr,
                            Chosen::Unix(_) => unreachable!(),
                        };
                        connect_bound(addr, None, loc.proxy_connect_timeout)
                            .await
                            .map(UpStream::Tcp)
                    }
                };
                match fresh {
                    Ok(mut s) => {
                        if s.write_all(&out).await.is_err()
                            || (!in_memory.is_empty() && s.write_all(in_memory).await.is_err())
                        {
                            continue;
                        }
                        up = s;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            } else {
                continue;
            }
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
                    } else if head.chunked {
                        // A chunked reply ends at its `0`-size line plus the
                        // blank line after any trailers; keep-alive means the
                        // socket stays open, so waiting for EOF never returns
                        // (`inmemory chunked` came back empty).
                        //
                        // `dechunk` alone is not enough: it returns as soon as it
                        // sees the `0` line, while the closing CRLF may still be
                        // in flight (`proxy_keepalive.t`'s "complex" case sleeps
                        // 50ms before it). Pooling then left that byte in the
                        // socket and the next reply on the connection parsed off
                        // by one, which showed up as "read timeout" two requests
                        // later.
                        if chunked_body_end(&buf[h..]).is_some() {
                            break;
                        }
                    } else {
                        // No framing information: the upstream closes to signal
                        // the end, so keep reading until EOF.
                    }
                }
            }
        }

        let Some(h) = head_end else {
            last_err = Some(io::Error::new(
                io::ErrorKind::InvalidData,
                "no response head",
            ));
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
        // `$upstream_addr` for a unix target is `unix:<path>`, as nginx prints it.
        let upstream_addr_display = match &cand {
            Chosen::Unix(p) => format!("unix:{}", p.display()),
            Chosen::Direct(_, a) => a.to_string(),
            Chosen::Upstream { addr, .. } => addr.to_string(),
        };
        apply_proxy_redirect(&mut raw, loc, &fetch_vars);
        crate::http::apply_expires(&mut raw, loc, head.status, None);
        // Applied here, where `$upstream_*` is in scope, and with the full
        // `ServerVars` set (`$request_body`, `$cookie_*`, `set` variables).
        // `headers_finalized` then stops `finalize_response` repeating it.
        crate::http::apply_add_headers_ctx(
            &mut raw,
            &loc.headers,
            head.status,
            cache_status,
            &upstream_addr_display,
            &upstream_headers,
            Some(&fetch_vars),
            &pp.host_header,
        );

        // `proxy_cache_use_stale`: an expired entry may stand in for an
        // upstream status the directive lists.
        if let Some(entry) = stale_entry {
            if loc.proxy_cache_use_stale_codes.contains(&head.status) {
                return Some(cached_response(entry, loc, "STALE"));
            }
        }

        // Store for the next request, following the same rules as the
        // streaming path (status validity, Cache-Control, Vary). A bypassed
        // request must not seed an entry.
        if cache_status != "BYPASS" {
            if let (Some(z), Some(key)) = (zone, cache_key.as_deref()) {
                if let Some(ttl) =
                    crate::cache::ttl(loc, head.status, &upstream_headers, loc.proxy_cache_ignore)
                {
                    if !ttl.is_zero() {
                        let entry = crate::cache::Cached {
                            status: head.status,
                            error: None,
                            headers: upstream_headers.clone(),
                            body: body.clone(),
                            stored_at: crate::cache::now(),
                            valid_for: ttl.as_secs(),
                        };
                        if loc.proxy_cache_ignore.vary
                            || !crate::cache::vary_star(&upstream_headers)
                        {
                            let get = |n: &str| req.headers.get_joined(n).unwrap_or_default();
                            let _ = crate::cache::store_repr(
                                z,
                                key,
                                &upstream_headers,
                                get,
                                &entry,
                                loc.proxy_cache_ignore.vary,
                            );
                        }
                    }
                }
            }
        }

        // Hand the connection back so the next request -- including another
        // subrequest -- reuses it, as nginx does. A close-delimited reply is
        // kept because it was read to EOF, which is a message boundary too.
        let reuse = head.keepalive && loc.proxy_http_version == 1 && !req.chunked;
        if reuse {
            let cap = match pp.target {
                crate::config::ProxyTarget::Upstream(i) => loc_upstream_cap(i, &pp).unwrap_or(0),
                _ => 0,
            };
            checkin(key, up, cap);
        }
        return Some(Response {
            status: head.status,
            headers: Vec::new(),
            raw,
            explicit_len: true,
            no_error_page: false,
            trailers: Vec::new(),
            expect_trailers: false,
            server_tokens: None,
            headers_finalized: true,
            body: Body::Bytes(body),
        });
    }

    if let Some(e) = &last_err {
        eprintln!(
            "ngxrs: [error] h2 upstream failure for {}: {e}",
            req.raw_target
        );
    }
    Some(Response::bytes(
        502,
        "text/html",
        crate::http::error_body(502, true),
    ))
}

/// Offset just past the final blank line of a chunked body, if the terminator
/// has actually arrived. `dechunk` decodes as soon as it sees the `0` line, which
/// is not enough to know the message ended.
fn chunked_body_end(input: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    loop {
        let line_end = memchr::memmem::find(input.get(i..)?, b"\r\n")? + i;
        let size = usize::from_str_radix(
            std::str::from_utf8(&input[i..line_end])
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        i = line_end + 2;
        if size == 0 {
            return chunked_message_end(input, i);
        }
        if i + size + 2 > input.len() {
            return None;
        }
        i += size + 2;
    }
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
/// Turn a stored entry into a response, for the socket-free path.
/// nginx's `not_modified` filter applied to a cached response: a conditional
/// request that matches the stored validators gets 304, whatever protocol
/// served it. nginx does this in a header filter, so a cache hit and a fresh
/// upstream response behave the same.
fn cached_not_modified(entry: &crate::cache::Cached, req: &Request) -> Option<Response> {
    if entry.status != 200 {
        return None;
    }
    let hdr = |name: &str| {
        entry
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let mut matched = false;
    if let Some(inm) = req.headers.get("if-none-match") {
        if let Some(etag) = hdr("etag") {
            matched = crate::http::static_file::etag_list_matches(inm, etag);
        }
    } else if let Some(ims) = req.headers.get("if-modified-since") {
        if let (Some(lm), Some(t)) = (hdr("last-modified"), crate::util::parse_http_date(ims)) {
            if let Some(mtime) = crate::util::parse_http_date(lm) {
                matched = mtime <= t;
            }
        }
    }
    if !matched {
        return None;
    }
    let mut resp = Response::empty(304);
    if let Some(etag) = hdr("etag") {
        resp = resp.header("ETag", etag);
    }
    if let Some(lm) = hdr("last-modified") {
        resp = resp.header("Last-Modified", lm);
    }
    Some(resp)
}

fn cached_response(entry: crate::cache::Cached, loc: &LocCfg, status: &str) -> Response {
    let mut raw = Vec::with_capacity(entry.body.len() + 256);
    for (k, v) in &entry.headers {
        raw.extend_from_slice(k.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(v.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    crate::http::apply_add_headers_upstream(&mut raw, &loc.headers, entry.status, status, "");
    raw.extend_from_slice(b"Content-Length: ");
    raw.extend_from_slice(entry.body.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n");
    Response {
        status: entry.status,
        headers: Vec::new(),
        raw,
        explicit_len: true,
        no_error_page: false,
        trailers: Vec::new(),
        expect_trailers: false,
        server_tokens: None,
        headers_finalized: true,
        body: Body::Bytes(entry.body),
    }
}

pub fn cache_key_for(loc: &LocCfg, req: &Request, peer_ip: &str) -> Option<String> {
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
            spec,
            scheme,
            proxy_host,
            host,
            &req.raw_target,
            &uri_only,
            &args_only,
            peer_ip,
            req.method.as_str(),
        ),
        None => crate::cache::default_key(scheme, proxy_host, &req.raw_target),
    })
}

/// Refresh a stale cache entry behind the client's back.
///
/// Everything the task needs is materialised before spawning: neither `Request`
/// nor `Http` is `Clone`, and both are borrowed from the live request.
/// Start a background refresh and return its task handle.
///
/// nginx postpones finalizing the client request until the background
/// subrequest completes (its tests rely on the follow-up request seeing a
/// refreshed entry), so the caller must await the handle after the stale body
/// has been written.
pub fn spawn_background_update(
    loc: &LocCfg,
    http: &Http,
    req: &Request,
    key: String,
    peer_ip: &str,
    target_uri: &str,
    cached: &crate::cache::Cached,
) -> Option<tokio::task::JoinHandle<()>> {
    let Some(zone) = loc
        .proxy_cache
        .as_ref()
        .and_then(|name| http.cache_zones.iter().find(|z| &z.name == name))
        .cloned()
    else {
        return None;
    };
    let Some(pp) = loc.proxy_pass.clone() else {
        return None;
    };
    let Some(candidates) = choose(
        http,
        loc,
        &match peer_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return None,
        },
        // No variable scope here: a `hash` upstream falls back to round-robin
        // for the background refresh (any peer can serve it).
        None,
    ) else {
        return None;
    };
    let addrs: Vec<SocketAddr> = candidates
        .into_iter()
        // A unix target cannot be represented as a SocketAddr; a background
        // cache refresh for one simply does not run.
        .filter_map(|c| match c {
            Chosen::Direct(_, a) => Some(a),
            Chosen::Upstream { addr, .. } => Some(addr),
            Chosen::Unix(_) => None,
        })
        .collect();

    // The refresh reuses the target the foreground request resolved, so a
    // `location ~ /(reg)(?P<name>exp)` style `proxy_pass .../$1$name` keeps its
    // captures instead of being rebuilt from the raw URI.
    // The background refresh re-fetches the whole entity for the cache.
    // `proxy_cache_revalidate`: the refresh is conditional, exactly like the
    // foreground path, so an unchanged upstream answers 304 and the stored body
    // is kept instead of being replaced by a bodyless 200.
    let reval = if loc.proxy_cache_revalidate {
        Some(cached)
    } else {
        None
    };
    // The task outlives this call, so it needs its own copy.
    let cached_owned = cached.clone();
    let head = build_upstream_head(
        req,
        target_uri,
        &[],
        loc,
        &pp,
        peer_ip,
        false,
        true,
        reval,
        true,
    );

    let connect_timeout = loc.proxy_connect_timeout;
    let read_timeout = loc.proxy_read_timeout;
    let loc_owned = loc.clone();
    let key_for_mark = key.clone();
    if !updating_mark(&key_for_mark) {
        return None;
    }

    Some(tokio::spawn(async move {
        // The mark must be dropped on every exit path, otherwise a single failed
        // refresh leaves the key permanently "updating".
        struct Mark(String);
        impl Drop for Mark {
            fn drop(&mut self) {
                updating_clear(&self.0);
            }
        }
        let _mark = Mark(key_for_mark);

        let Some((status, headers, body)) =
            refetch(&head, &addrs, connect_timeout, read_timeout).await
        else {
            return;
        };
        // A revalidating subrequest keeps the stored response and only refreshes
        // its validity (`ngx_http_upstream_304`): the body is unchanged, so
        // replacing it would lose the payload the client will ask for next.
        if status == 304 && loc_owned.proxy_cache_revalidate {
            let refreshed = crate::cache::Cached {
                stored_at: crate::cache::now(),
                ..cached_owned
            };
            let _ = crate::cache::store(&zone, &key, &refreshed);
            return;
        }
        if let Some(valid) =
            crate::cache::ttl(&loc_owned, status, &headers, loc_owned.proxy_cache_ignore)
        {
            let entry = crate::cache::Cached {
                status,
                headers,
                body,
                stored_at: crate::cache::now(),
                valid_for: valid.as_secs(),
                error: None,
            };
            let _ = crate::cache::store(&zone, &key, &entry);
        }
    }))
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
        if let Ok(Ok(s)) =
            tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await
        {
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
/// Slice a buffered 200 body for a `Range` request.
///
/// Callers decide *whether* ranges apply: `proxy_force_ranges`, or a cached
/// entry whose origin advertised `Accept-Ranges: bytes`. Re-checking the
/// directive here would silently disable the cache path, which is exactly the
/// bug `proxy_cache_range.t` caught.
fn apply_force_ranges(
    req: &Request,
    status: u16,
    raw: &mut Vec<u8>,
    body: Vec<u8>,
    max_ranges: u32,
) -> (u16, Vec<u8>, Vec<u8>) {
    if status != 200 {
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
            get("etag")
                .map(|e| e.trim() == cond.trim())
                .unwrap_or(false)
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

    match crate::http::static_file::parse_ranges(range, size, max_ranges as usize) {
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
                let mbody = crate::http::static_file::multipart_body(
                    &boundary,
                    &content_type,
                    size,
                    &spans,
                    &body,
                );
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

/// Remove every `name:` line from a rendered head block.
fn drop_header(raw: &[u8], name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while pos < raw.len() {
        let end = memchr::memmem::find(&raw[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(raw.len());
        let line = &raw[pos..end];
        let same = line.len() > name.len()
            && line[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            && line[name.len()] == b':';
        if !same {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        pos = end + 2;
    }
    out
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
        .any(|n| line.len() > n.len() && line[..n.len()].eq_ignore_ascii_case(n.as_bytes()));
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

/// `proxy_redirect`: rewrite the `Location` and `Refresh` headers of a proxied
/// response.
///
/// nginx passes a `prefix` to the rewrite so `Refresh: 7; url=<u>` can have its
/// `<u>` replaced while `7; url=` survives. For `Refresh` the prefix is
/// everything up to and including the **last** `=` in the value.
///
/// Prefix rules replace the matched prefix and keep the remainder. Regex rules
/// replace the **whole** URL with the expanded replacement -- the test suite
/// pins this (`regexp w/captures` expects the trailing `/test.html` to be
/// dropped, not appended), and it is why a `$1/$2/x.html` replacement produces
/// nginx's exact output.
fn apply_proxy_redirect(raw: &mut Vec<u8>, loc: &LocCfg, vars: &crate::http::ServerVars<'_>) {
    let rules = &loc.proxy_redirects;
    if rules.is_empty() || matches!(rules.first(), Some(crate::config::RedirectRule::Off)) {
        return;
    }
    // Some call sites pass the header lines only (no terminating blank line),
    // others pass the whole block; handle both.
    let head_end = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i + 2,
        None => raw.len(),
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();

    let mut out = String::with_capacity(head.len() + 64);
    for line in head.split_inclusive("\r\n") {
        let trimmed = line.trim_end_matches("\r\n");
        let lower = trimmed.to_ascii_lowercase();
        let (name, prefix_len) = if lower.starts_with("location:") {
            // Skip the spaces after the colon: the value starts at the first
            // non-space, and `before` keeps them verbatim.
            let mut i = 9;
            let b = trimmed.as_bytes();
            while i < b.len() && b[i] == b' ' {
                i += 1;
            }
            ("location", i)
        } else if lower.starts_with("refresh:") {
            match trimmed.rfind('=') {
                Some(i) => ("refresh", i + 1),
                None => {
                    out.push_str(line);
                    continue;
                }
            }
        } else {
            out.push_str(line);
            continue;
        };
        let _ = name;
        if prefix_len >= trimmed.len() {
            out.push_str(line);
            continue;
        }
        let before = &trimmed[..prefix_len];
        let url = &trimmed[prefix_len..];
        let mut rewritten = rewrite_one(url, rules, vars).unwrap_or_else(|| url.to_string());
        if lower.starts_with("location:") {
            // The proxy path writes straight to the socket and never reaches
            // `finalize_response`, so the absolutisation nginx's header filter
            // performs has to happen here. `Refresh` is deliberately excluded:
            // nginx leaves it relative.
            rewritten = absolute_location(&rewritten, loc, vars);
        }
        out.push_str(before);
        out.push_str(&rewritten);
        out.push_str("\r\n");
    }
    out.push_str(&String::from_utf8_lossy(&raw[head_end..]));
    *raw = out.into_bytes();
}

fn rewrite_one(
    url: &str,
    rules: &[crate::config::RedirectRule],
    vars: &crate::http::ServerVars<'_>,
) -> Option<String> {
    for rule in rules {
        match rule {
            crate::config::RedirectRule::Off => {}
            crate::config::RedirectRule::Prefix { from, to } => {
                let from = vars.expand(from);
                if from.is_empty() || !url.starts_with(&from) {
                    continue;
                }
                return Some(format!("{}{}", vars.expand(to), &url[from.len()..]));
            }
            crate::config::RedirectRule::Regex { re, to } => {
                let Some(caps) = re.captures(url) else {
                    continue;
                };
                // Positional captures become `$1..$n` for the replacement.
                let mut expanded = String::new();
                let bytes = to.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'$' && i + 1 < bytes.len() {
                        if bytes[i + 1].is_ascii_digit() {
                            let n = (bytes[i + 1] - b'0') as usize;
                            if let Some(m) = caps.get(n) {
                                expanded.push_str(m.as_str());
                            }
                            i += 2;
                            continue;
                        }
                        if bytes[i + 1] == b'{' {
                            if let Some(close) = to[i + 2..].find('}') {
                                let name = &to[i + 2..i + 2 + close];
                                if let Some(m) = caps.name(name) {
                                    expanded.push_str(m.as_str());
                                }
                                i += 2 + close + 1;
                                continue;
                            }
                        }
                    }
                    expanded.push(bytes[i] as char);
                    i += 1;
                }
                return Some(vars.expand(&expanded));
            }
        }
    }
    None
}

/// Absolutise a `Location` value the way `ngx_http_header_filter` does when
/// `absolute_redirect` is on. Mirrors `http::redirect_location`, without the
/// listening-socket fallback for a missing Host (that address is not available
/// on the proxy path; nginx only uses it when the request carried no usable
/// Host, in which case the value is left relative here).
fn absolute_location(value: &str, loc: &LocCfg, vars: &crate::http::ServerVars<'_>) -> String {
    if !loc.absolute_redirect || !value.starts_with('/') {
        return value.to_string();
    }
    let host = if loc.server_name_in_redirect && !loc.server_name.is_empty() {
        loc.server_name.clone()
    } else {
        let h = vars.req.host.as_ref().map(|h| h.as_str()).unwrap_or("");
        if h.is_empty() || !crate::http::request::host_is_usable(h) {
            return value.to_string();
        }
        h.to_string()
    };
    if loc.port_in_redirect && vars.server_port != 80 {
        format!("http://{}:{}{}", host, vars.server_port, value)
    } else {
        format!("http://{}{}", host, value)
    }
}

/// Host part of an `authority`, without the port. Handles `[v6]:port` too.
fn authority_host(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    match authority.rsplit_once(':') {
        // Only strip when the tail really is a port, so a bare IPv6 address
        // (which contains colons) is left intact.
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
        _ => authority.to_string(),
    }
}

#[cfg(test)]
mod chunk_tests {
    use super::{chunked_body_end, dechunk};

    /// `dechunk` decodes as soon as it sees the `0` line, which is not the same
    /// as the message having ended: the blank line that terminates it may still
    /// be in flight. Pooling a connection at that point left one byte behind and
    /// the next response on it parsed off by one.
    #[test]
    fn terminator_must_arrive_before_the_message_counts_as_complete() {
        assert_eq!(chunked_body_end(b"0\r\n\r\n"), Some(5));
        assert_eq!(chunked_body_end(b"0\r\n"), None, "closing CRLF still missing");
        assert_eq!(
            dechunk(b"0\r\n").is_some(),
            true,
            "dechunk alone is why this needed a separate check"
        );
    }

    #[test]
    fn terminator_with_trailers() {
        // `0`, two trailer lines, then the blank line.
        let body = b"0\r\nX-A: 1\r\nX-B: 2\r\n\r\n";
        assert_eq!(chunked_body_end(body), Some(body.len()));
        assert_eq!(chunked_body_end(&body[..body.len() - 1]), None);
    }

    #[test]
    fn chunked_body_with_data() {
        let body = b"a\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(chunked_body_end(body), Some(body.len()));
        // A truncated data chunk is not complete either.
        assert_eq!(chunked_body_end(b"a\r\n0123"), None);
        assert_eq!(dechunk(body).as_deref(), Some(&b"0123456789"[..]));
    }

    /// A zero-size chunk is a complete, empty body -- the `proxy_keepalive.t`
    /// "0 chunk" case, which must still produce a body boundary.
    #[test]
    fn empty_chunked_body() {
        assert_eq!(chunked_body_end(b"0\r\n\r\n"), Some(5));
        assert_eq!(dechunk(b"0\r\n\r\n").as_deref(), Some(&b""[..]));
    }
}
