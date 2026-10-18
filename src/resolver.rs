//! A minimal DNS client for the `resolver` directive.
//!
//! nginx only consults `resolver` for addresses it cannot know at config time
//! (a `proxy_pass`/`grpc_pass` target built from variables). Only A records are
//! supported here, which is what the compatibility suites exercise.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Parsed `resolver <addr>... [valid=...]` directive.
#[derive(Debug, Clone)]
pub struct Resolver {
    pub servers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub valid: Duration,
}

impl Resolver {
    pub fn parse(args: &[String], prefix: &std::path::Path) -> Option<Resolver> {
        let _ = prefix;
        let mut servers = Vec::new();
        let mut timeout = Duration::from_secs(30);
        let mut valid = Duration::from_secs(30);
        for a in args {
            if let Some(v) = a.strip_prefix("valid=") {
                if let Some(d) = crate::config::typed::parse_time(v) {
                    valid = d;
                }
                continue;
            }
            if let Some(v) = a.strip_prefix("timeout=") {
                if let Some(d) = crate::config::typed::parse_time(v) {
                    timeout = d;
                }
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
            timeout,
            valid,
        })
    }
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

/// One cached answer.
struct Entry {
    addr: Ipv4Addr,
    expires: Instant,
}

thread_local! {
    static CACHE: std::cell::RefCell<std::collections::HashMap<String, Entry>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Resolve `name` to an IPv4 address using this resolver's servers.
pub async fn resolve(resolver: &Resolver, name: &str) -> Option<IpAddr> {
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(ip) = key.parse::<IpAddr>().ok() {
        return Some(ip);
    }
    let hit = CACHE.with(|c| {
        c.borrow()
            .get(&key)
            .filter(|e| e.expires > Instant::now())
            .map(|e| e.addr)
    });
    if let Some(a) = hit {
        return Some(IpAddr::V4(a));
    }

    let query = build_query(&key, 0x1234)?;
    for server in &resolver.servers {
        let Some(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok() else {
            continue;
        };
        if sock.connect(server).await.is_err() {
            continue;
        }
        if sock.send(&query).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 1500];
        let n = match tokio::time::timeout(resolver.timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if let Some((addr, ttl)) = parse_answer(&buf[..n], 0x1234) {
            let ttl = ttl.min(resolver.valid.as_secs() as u32).max(1);
            CACHE.with(|c| {
                c.borrow_mut().insert(
                    key.clone(),
                    Entry {
                        addr,
                        expires: Instant::now() + Duration::from_secs(ttl as u64),
                    },
                )
            });
            return Some(IpAddr::V4(addr));
        }
    }
    None
}

fn build_query(name: &str, id: u16) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    Some(q)
}

/// Walk the answer section and return the first A record with its TTL.
fn parse_answer(buf: &[u8], id: u16) -> Option<(Ipv4Addr, u32)> {
    if buf.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(buf, p)?;
        p = p.checked_add(4)?; // QTYPE + QCLASS
    }
    for _ in 0..an {
        p = skip_name(buf, p)?;
        if p + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        p += 10;
        if p + rdlen > buf.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            return Some((
                Ipv4Addr::new(buf[p], buf[p + 1], buf[p + 2], buf[p + 3]),
                ttl,
            ));
        }
        p += rdlen;
    }
    None
}

/// Skip a possibly-compressed name, returning the offset just past it.
fn skip_name(buf: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let len = *buf.get(p)?;
        if len == 0 {
            return Some(p + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: two bytes, no labels follow.
            return Some(p + 2);
        }
        p += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_query() {
        let q = build_query("localhost", 0x1234).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[12..14], &[9, b'l']);
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn parses_an_a_answer() {
        let q = build_query("localhost", 1).unwrap();
        let mut r = q.clone();
        r[2] = 0x81; // QR + RD + RA
        r[3] = 0x80;
        r[6] = 0;
        r[7] = 1; // ANCOUNT = 1
        r.extend_from_slice(&[0xC0, 12]); // pointer to the question name
        r.extend_from_slice(&1u16.to_be_bytes()); // A
        r.extend_from_slice(&1u16.to_be_bytes()); // IN
        r.extend_from_slice(&60u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[127, 0, 0, 1]);
        let (addr, ttl) = parse_answer(&r, 1).unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ttl, 60);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_answer(&[0u8; 8], 1).is_none());
    }
}
