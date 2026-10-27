//! DNS client for the `resolver` directive, following `ngx_resolver.c`.
//!
//! nginx only consults `resolver` for a peer name that exists at request time
//! (`proxy_pass http://$host`). One name is one cache entry, and each entry
//! holds either the addresses or a CNAME to follow -- the same shape as
//! `ngx_resolver_node_t`.
//!
//! The parts of nginx's behaviour that decide the observable result:
//!
//!   * both an A and an AAAA query go out, to the same server, at once;
//!   * **any** error response (SERVFAIL, FORMERR, NXDOMAIN, a malformed body,
//!     a name that does not parse) fails the whole name -- a partial answer is
//!     never used. `http_resolver_aaaa.t` checks this from every direction:
//!     `n-e` (A ok, AAAA SERVFAIL) must be a 502, not the A address;
//!   * an empty NOERROR answer for one type is fine and contributes nothing;
//!   * the addresses of both types are merged, A first;
//!   * a CNAME is only followed when the answer carried **no** addresses, and
//!     the CNAME from whichever response completed the name wins (`c1-c2`:
//!     A names `alias4`, AAAA names `alias6`, and only `alias6` is resolved);
//!   * the cache lifetime is the smallest TTL in the answer, or `valid=` when
//!     given.  A zero TTL is never cached;
//!   * the server is rotated per *name*, not per query (`r->last_connection++`
//!     runs when the node is created), which is what makes `resolver <bad>
//!     <good>` answer 502 once and then succeed;
//!   * a query is resent every `resend_timeout` (5s) until `resolver_timeout`,
//!     rotating the server each time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// `NGX_RESOLVER_MAX_RECURSION`: a CNAME chain longer than this is a loop.
const MAX_RECURSION: u32 = 50;
/// `ngx_resolver.c`'s `resend_timeout`, in seconds.
const RESEND: Duration = Duration::from_secs(5);

/// Parsed `resolver <addr>... [valid=...]` directive.
#[derive(Debug, Clone)]
pub struct Resolver {
    pub servers: Vec<SocketAddr>,
    /// `resolver_timeout`; the whole resolution, resends included, is bounded
    /// by this.
    pub timeout: Duration,
    /// `valid=`: overrides the TTL the server sends.
    pub valid: Option<Duration>,
    /// Identity of this directive instance. nginx keeps one rbtree per resolver,
    /// so two locations with different `resolver` directives do not share
    /// answers.
    id: u64,
    /// Round-robin position, advanced once per name resolved.
    next: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Resolver {
    pub fn parse(args: &[String], prefix: &std::path::Path) -> Option<Resolver> {
        let _ = prefix;
        let mut servers = Vec::new();
        let mut valid = None;
        for a in args {
            if let Some(v) = a.strip_prefix("valid=") {
                valid = crate::config::typed::parse_time(v);
                continue;
            }
            if let Some(addr) = parse_server(a) {
                servers.push(addr);
            }
        }
        if servers.is_empty() {
            return None;
        }
        Some(Resolver {
            servers,
            timeout: Duration::from_secs(30),
            valid,
            id: next_id(),
            next: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// A copy of this resolver with `resolver_timeout` applied. The name and the
    /// rotation position stay shared, because `resolver_timeout` is a separate
    /// directive and may appear on either side of `resolver`.
    pub fn with_timeout(&self, timeout: Option<Duration>) -> Resolver {
        let mut r = self.clone();
        if let Some(t) = timeout {
            r.timeout = t;
        }
        r
    }
}

fn next_id() -> u64 {
    static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `127.0.0.1:5353`, `127.0.0.1` or `[::1]:5353`; DNS defaults to port 53.
fn parse_server(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

// ---- cache ---------------------------------------------------------------

/// One resolved name. `ngx_resolver_node_t` holds either addresses or a CNAME.
#[derive(Clone)]
enum Entry {
    Addrs { addrs: Vec<IpAddr>, expires: Instant },
    Cname { target: String, expires: Instant },
}

thread_local! {
    static CACHE: std::cell::RefCell<std::collections::HashMap<(u64, String), Entry>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

fn cache_get(id: u64, name: &str) -> Option<Entry> {
    CACHE.with(|c| {
        c.borrow()
            .get(&(id, name.to_string()))
            .filter(|e| match e {
                Entry::Addrs { expires, .. } | Entry::Cname { expires, .. } => {
                    *expires > Instant::now()
                }
            })
            .cloned()
    })
}

fn cache_put(id: u64, name: &str, entry: Entry) {
    CACHE.with(|c| {
        c.borrow_mut().insert((id, name.to_string()), entry);
    });
}

// ---- wire format ---------------------------------------------------------

const T_A: u16 = 1;
const T_CNAME: u16 = 5;
const T_AAAA: u16 = 28;

/// What one response said.
struct Answer {
    /// `nan`: answer records in the message, whatever their type. A response
    /// with none is `NXDOMAIN` when it arrives last and the other type had no
    /// addresses -- that asymmetry is what `z-c` (follow the CNAME) and `c-z`
    /// (502) distinguish.
    nan: u16,
    addrs: Vec<IpAddr>,
    /// The last CNAME in the answer section, if any.
    cname: Option<String>,
    /// Smallest TTL over every record seen; `None` when there were none, so an
    /// empty answer does not drag the name's lifetime down to zero. nginx
    /// starts the node's TTL at `NGX_MAX_UINT32_VALUE` for the same reason.
    ttl: Option<u32>,
}

/// The verdict after both responses are in.
enum Step {
    /// Addresses were found (or the other type answered); deliver them.
    Export,
    /// No addresses anywhere, but the name is an alias: resolve the target.
    Follow(String),
    /// Nothing usable: nginx's `NXDOMAIN`.
    Fail,
}

/// `ngx_resolver_process_a`'s decision, with the A response processed first and
/// the AAAA one second -- the order nginx sees them in, and the order that
/// decides which CNAME wins and whether an empty answer is `NXDOMAIN`.
fn combine(a: &Answer, a6: &Answer) -> Step {
    let mut known_a: Option<usize> = None;
    let mut known_a6: Option<usize> = None;
    let mut cname: Option<String> = None;

    for (is_a, ans) in [(true, a), (false, a6)] {
        if ans.nan == 0 {
            if is_a {
                known_a = Some(0);
            } else {
                known_a6 = Some(0);
            }
            // The other type decides: addresses there mean the name resolves,
            // nothing there means the name does not exist.
            match if is_a { known_a6 } else { known_a } {
                None => continue,
                Some(n) if n > 0 => return Step::Export,
                Some(_) => return Step::Fail,
            }
        }
        if is_a {
            known_a = Some(ans.addrs.len());
        } else {
            known_a6 = Some(ans.addrs.len());
        }
        if ans.cname.is_some() {
            // Whichever response completed the name stores its CNAME; that is
            // the AAAA response when both carry a different one (`c1-c2`).
            cname = ans.cname.clone();
        }
        if known_a.is_some() && known_a6.is_some() {
            let total = known_a.unwrap_or(0) + known_a6.unwrap_or(0);
            if total > 0 {
                return Step::Export;
            }
            return match cname {
                Some(t) => Step::Follow(t),
                None => Step::Fail,
            };
        }
    }
    Step::Fail
}

/// Why a query produced no usable answer.
enum Fail {
    /// A response arrived with a non-zero rcode: fail the name outright.
    Rcode,
    /// Nothing arrived in the allotted slice, or the socket broke: resend.
    Retry,
}

/// Resolve `name`, returning every address nginx would try.
pub async fn resolve(resolver: &Resolver, name: &str) -> Option<Vec<IpAddr>> {
    resolve_rec(resolver, name, 0).await
}

async fn resolve_rec(resolver: &Resolver, name: &str, recursion: u32) -> Option<Vec<IpAddr>> {
    if recursion > MAX_RECURSION {
        return None;
    }
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    if let Ok(ip) = key.parse::<IpAddr>() {
        return Some(vec![ip]);
    }
    match cache_get(resolver.id, &key) {
        Some(Entry::Addrs { addrs, .. }) => return Some(addrs),
        Some(Entry::Cname { target, .. }) => {
            return Box::pin(resolve_rec(resolver, &target, recursion + 1)).await;
        }
        None => {}
    }

    // Both types go to the same server, and the pairing is decided once per
    // name: `r->last_connection++` happens when the node is created.
    let sockaddr = {
        let idx = resolver
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        resolver.servers[idx % resolver.servers.len()]
    };
    let budget = Instant::now() + resolver.timeout;
    let (ra, ra6) = tokio::join!(
        query(resolver, &key, T_A, sockaddr, budget),
        query(resolver, &key, T_AAAA, sockaddr, budget)
    );
    let a = ra.ok()?;
    let a6 = ra6.ok()?;

    let step = combine(&a, &a6);
    let ttl = match (a.ttl, a6.ttl) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    // `valid=` wins over the TTL; with neither there is nothing to cache by.
    let lifetime = resolver
        .valid
        .or(ttl.map(|t| Duration::from_secs(t as u64)))
        .unwrap_or(Duration::ZERO);

    match step {
        Step::Export => {
            let mut addrs = a.addrs;
            addrs.extend(a6.addrs);
            if !lifetime.is_zero() {
                cache_put(
                    resolver.id,
                    &key,
                    Entry::Addrs {
                        addrs: addrs.clone(),
                        expires: Instant::now() + lifetime,
                    },
                );
            }
            Some(addrs)
        }
        Step::Follow(target) => {
            if !lifetime.is_zero() {
                cache_put(
                    resolver.id,
                    &key,
                    Entry::Cname {
                        target: target.clone(),
                        expires: Instant::now() + lifetime,
                    },
                );
            }
            Box::pin(resolve_rec(resolver, &target, recursion + 1)).await
        }
        Step::Fail => None,
    }
}

/// Send one query, resending every `RESEND` on the next server until `budget`
/// runs out.
async fn query(
    resolver: &Resolver,
    name: &str,
    qtype: u16,
    start: SocketAddr,
    budget: Instant,
) -> Result<Answer, ()> {
    let start_idx = resolver
        .servers
        .iter()
        .position(|s| *s == start)
        .unwrap_or(0);
    let mut attempt = 0usize;
    loop {
        let now = Instant::now();
        if now >= budget {
            return Err(());
        }
        let server = resolver.servers[(start_idx + attempt) % resolver.servers.len()];
        // nginx waits `resend_timeout` before retrying, but never past
        // `resolver_timeout`.
        let wait = RESEND.min(budget - now);
        match query_once(server, name, qtype, wait).await {
            Ok(a) => return Ok(a),
            // A real DNS error fails the name; there is nothing to resend.
            Err(Fail::Rcode) => return Err(()),
            Err(Fail::Retry) => attempt += 1,
        }
        if attempt > resolver.servers.len() + 1 && Instant::now() >= budget {
            return Err(());
        }
    }
}

async fn query_once(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    wait: Duration,
) -> Result<Answer, Fail> {
    let id = next_id16();
    let sock = match server {
        SocketAddr::V4(_) => tokio::net::UdpSocket::bind("0.0.0.0:0").await,
        SocketAddr::V6(_) => tokio::net::UdpSocket::bind("[::]:0").await,
    };
    let sock = sock.map_err(|_| Fail::Retry)?;
    sock.connect(server).await.map_err(|_| Fail::Retry)?;
    let query = build_query(name, qtype, id).ok_or(Fail::Rcode)?;
    sock.send(&query).await.map_err(|_| Fail::Retry)?;

    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Fail::Retry);
        }
        let n = match tokio::time::timeout(left, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            // ICMP unreachable (a closed port) arrives as an error here, which
            // nginx treats the same as a timeout: try the next server.
            _ => return Err(Fail::Retry),
        };
        // A truncated UDP answer means "ask again over TCP", which nginx does
        // against the same server (`ngx_resolver_send_tcp_query`). The resolver
        // tests exercise this with a stub that sets TC on UDP and answers on TCP.
        if n >= 4 && u16::from_be_bytes([buf[2], buf[3]]) & 0x0200 != 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Fail::Retry);
            }
            return query_tcp(server, name, qtype, id, left).await;
        }
        // A reply for another query (wrong id, another name) is ignored, exactly
        // like nginx's `wrong ident` path -- `id.example.net` in
        // http_resolver.t depends on the request being retried, not answered.
        match parse_response(&buf[..n], id, name) {
            Some(r) => return r,
            None => continue,
        }
    }
}

/// One DNS exchange over TCP: a 2-byte length prefix each way.
async fn query_tcp(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    id: u16,
    wait: Duration,
) -> Result<Answer, Fail> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let query = build_query(name, qtype, id).ok_or(Fail::Rcode)?;
    let fut = async {
        let mut sock = tokio::net::TcpStream::connect(server).await.map_err(|_| Fail::Retry)?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        sock.write_all(&framed).await.map_err(|_| Fail::Retry)?;
        let len = sock.read_u16().await.map_err(|_| Fail::Retry)? as usize;
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body).await.map_err(|_| Fail::Retry)?;
        match parse_response(&body, id, name) {
            Some(r) => r,
            None => Err(Fail::Retry),
        }
    };
    match tokio::time::timeout(wait, fut).await {
        Ok(r) => r,
        Err(_) => Err(Fail::Retry),
    }
}

fn next_id16() -> u16 {
    static ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0x1234);
    ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn build_query(name: &str, qtype: u16, id: u16) -> Option<Vec<u8>> {
    let mut r = Vec::with_capacity(32 + name.len());
    r.extend_from_slice(&id.to_be_bytes());
    r.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    for label in name.split('.') {
        if label.len() > 63 || label.is_empty() {
            return None;
        }
        r.push(label.len() as u8);
        r.extend_from_slice(label.as_bytes());
    }
    r.push(0);
    r.extend_from_slice(&qtype.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes()); // IN
    Some(r)
}

/// `Some(Some(_))` for a usable answer, `Some(Err(_))` for a response that
/// decides the name's fate, `None` when the datagram is not ours.
fn parse_response(buf: &[u8], id: u16, name: &str) -> Option<Result<Answer, Fail>> {
    if buf.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // not a response
    }
    let rcode = (flags & 0x000f) as u8;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    // The question name has to match what we asked (nginx looks the node up by
    // the reply's question). Comparing case-insensitively keeps
    // `CASE.example.net` on the cached entry for `case.example.net`.
    let mut p = 12;
    let mut qname = String::new();
    for _ in 0..qdcount {
        let (n, next) = read_name(buf, p)?;
        if qname.is_empty() {
            qname = n;
        }
        p = next + 4; // QTYPE + QCLASS
        if p > buf.len() {
            return None;
        }
    }
    if !qname.eq_ignore_ascii_case(name) {
        return None;
    }
    // A non-zero rcode fails the whole name, even if records came with it.
    if rcode != 0 {
        return Some(Err(Fail::Rcode));
    }

    let mut answer = Answer {
        nan: ancount as u16,
        addrs: Vec::new(),
        cname: None,
        ttl: None,
    };
    for _ in 0..ancount {
        let (_owner, next) = read_name(buf, p)?;
        p = next;
        if p + 10 > buf.len() {
            return Some(Err(Fail::Rcode));
        }
        let ty = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let class = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        let rd = p + 10;
        if rd + rdlen > buf.len() {
            return Some(Err(Fail::Rcode));
        }
        if class != 1 {
            return Some(Err(Fail::Rcode));
        }
        answer.ttl = Some(match answer.ttl {
            Some(t) => t.min(ttl),
            None => ttl,
        });
        match ty {
            T_A => {
                // A records are only expected in an A answer; a malformed one
                // (zero-length rdata, `short.example.net`) is an error, not a
                // skipped record.
                if rdlen != 4 {
                    return Some(Err(Fail::Rcode));
                }
                answer.addrs.push(IpAddr::V4(Ipv4Addr::new(
                    buf[rd],
                    buf[rd + 1],
                    buf[rd + 2],
                    buf[rd + 3],
                )));
            }
            T_AAAA => {
                if rdlen != 16 {
                    return Some(Err(Fail::Rcode));
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[rd..rd + 16]);
                answer.addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            T_CNAME => {
                let (target, _) = read_name(buf, rd)?;
                answer.cname = Some(target);
            }
            // DNAME (39) and anything else: ignored, as `process_a` does. The
            // DNAME test also carries the CNAME that supersedes it.
            _ => {}
        }
        p = rd + rdlen;
    }
    Some(Ok(answer))
}

/// Read a (possibly compressed) name. Returns the dotted text and the offset
/// just past the name in the *original* position.
fn read_name(buf: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = 0usize;
    let mut jumped = false;
    let mut hops = 0usize;
    loop {
        let len = *buf.get(p)? as usize;
        if len & 0xC0 == 0xC0 {
            let low = *buf.get(p + 1)? as usize;
            let target = ((len & 0x3F) << 8) | low;
            if !jumped {
                end = p + 2;
                jumped = true;
            }
            hops += 1;
            if hops > 32 || target >= buf.len() {
                return None;
            }
            p = target;
            continue;
        }
        if len == 0 {
            if !jumped {
                end = p + 1;
            }
            return Some((out, end));
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = buf.get(p + 1..p + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        p += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_query() {
        let q = build_query("example.net", T_A, 0x1234).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // 7"example" 3"net" 0, then QTYPE/QCLASS.
        assert_eq!(&q[12..], b"\x07example\x03net\x00\x00\x01\x00\x01");
    }

    #[test]
    fn rejects_bad_labels() {
        assert!(build_query("", T_A, 1).is_none());
        assert!(build_query("a..b", T_A, 1).is_none());
        assert!(build_query(&"x".repeat(64), T_A, 1).is_none());
    }

    /// `n3N nCa5n` CNAME record from the tests, then an A record, all pointing
    /// at the question name with `0xc00c`.
    fn response(id: u16, name: &str, rrs: &[u8], count: u16, rcode: u16) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&count.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        for l in name.split('.') {
            r.push(l.len() as u8);
            r.extend_from_slice(l.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&T_A.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(rrs);
        r
    }

    fn a_record(addr: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut r = vec![0xC0, 12];
        r.extend_from_slice(&T_A.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&addr);
        r
    }

    #[test]
    fn parses_an_a_answer() {
        let body = a_record([127, 0, 0, 1], 60);
        let msg = response(7, "example.net", &body, 1, 0);
        let a = match parse_response(&msg, 7, "example.net") {
            Some(Ok(a)) => a,
            _ => panic!("expected an answer"),
        };
        assert_eq!(a.addrs, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        assert_eq!(a.ttl, Some(60));
        assert!(a.cname.is_none());
    }

    #[test]
    fn ignores_a_reply_for_another_id_or_name() {
        let body = a_record([127, 0, 0, 1], 60);
        let msg = response(7, "example.net", &body, 1, 0);
        assert!(parse_response(&msg, 8, "example.net").is_none());
        assert!(parse_response(&msg, 7, "other.net").is_none());
        // Case-insensitive, so `CASE.example.net` finds the cached entry.
        assert!(matches!(
            parse_response(&msg, 7, "EXAMPLE.NET"),
            Some(Ok(_))
        ));
    }

    #[test]
    fn an_error_rcode_fails_the_name_even_with_records() {
        let body = a_record([127, 0, 0, 1], 60);
        let msg = response(7, "example.net", &body, 1, 2); // SERVFAIL
        assert!(matches!(parse_response(&msg, 7, "example.net"), Some(Err(Fail::Rcode))));
    }

    #[test]
    fn a_zero_length_a_record_is_an_error() {
        // `short.example.net`: `rd_addr($ttl, '')` produces rdlen 0.
        let mut body = vec![0xC0, 12];
        body.extend_from_slice(&T_A.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&60u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let msg = response(7, "example.net", &body, 1, 0);
        assert!(matches!(parse_response(&msg, 7, "example.net"), Some(Err(Fail::Rcode))));
    }

    #[test]
    fn cname_target_uses_a_compression_pointer_into_the_question() {
        // `pack("n3N nCa5n", 0xc00c, CNAME, IN, ttl, 8, 5, 'alias', 0xc011)`:
        // the rdata is `5"alias"` followed by a pointer to offset 17, which
        // lands inside the question name -- `alias2.example.net` in the tests is
        // built the same way.
        let labels: Vec<&str> = "cname.example.net".split('.').collect();
        let mut off = 12;
        for l in &labels {
            off += 1 + l.len();
        }
        let _ = off;
        let mut rrs = Vec::new();
        rrs.extend_from_slice(&[0xC0, 12]);
        rrs.extend_from_slice(&T_CNAME.to_be_bytes());
        rrs.extend_from_slice(&1u16.to_be_bytes());
        rrs.extend_from_slice(&3600u32.to_be_bytes());
        rrs.extend_from_slice(&7u16.to_be_bytes());
        rrs.push(5);
        rrs.extend_from_slice(b"alias");
        // Offset of "example" inside the question name: 12 + 1 + 5 = 18.
        rrs.extend_from_slice(&[0xC0, 18]);
        let msg = response(9, "cname.example.net", &rrs, 1, 0);
        let a = match parse_response(&msg, 9, "cname.example.net") {
            Some(Ok(a)) => a,
            _ => panic!("expected an answer"),
        };
        assert_eq!(a.cname.as_deref(), Some("alias.example.net"));
        assert!(a.addrs.is_empty());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(parse_response(&[0u8; 8], 1, "x").is_none());
        assert!(read_name(&[0xC0], 0).is_none());
    }
}
