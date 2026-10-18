//! `geo {}` — map a client address to a variable value (`ngx_http_geo_module`).
//!
//! Two modes: CIDR longest-prefix match (default) and `ranges` (explicit
//! `start-end` intervals). `delete` removes a previously declared entry.

use std::net::IpAddr;

#[derive(Debug, Clone)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
    value: String,
}

#[derive(Debug, Clone)]
struct Range {
    start: u128,
    end: u128,
    v6: bool,
    value: String,
}

#[derive(Debug, Clone, Default)]
pub struct GeoDef {
    /// `None` means `$remote_addr`.
    pub source: Option<String>,
    pub var: String,
    pub ranges: bool,
    pub default: Option<String>,
    /// `proxy_recursive`: walk X-Forwarded-For from the right, skipping
    /// trusted proxies.
    pub proxy_recursive: bool,
    pub proxies: Vec<Cidr>,
    cidrs: Vec<Cidr>,
    ranges_v: Vec<Range>,
}

impl GeoDef {
    pub fn new(source: Option<String>, var: String) -> Self {
        GeoDef {
            source,
            var,
            default: None,
            ..Default::default()
        }
    }

    pub fn set_ranges(&mut self) {
        self.ranges = true;
    }

    pub fn set_default(&mut self, v: String) {
        self.default = Some(v);
    }

    /// `1.2.3.0/24 value` or, in `ranges` mode, `1.2.3.4-1.2.3.9 value`.
    pub fn add(&mut self, key: &str, value: String) -> bool {
        if self.ranges {
            if let Some((s, e)) = parse_range(key) {
                self.ranges_v.push(Range {
                    start: s.0,
                    end: e.0,
                    v6: s.1,
                    value,
                });
                return true;
            }
        }
        if let Some((net, prefix)) = parse_cidr(key) {
            self.cidrs.push(Cidr { net, prefix, value });
            return true;
        }
        false
    }

    /// `delete <key>`.
    ///
    /// For CIDR entries this removes the exact network. For `ranges` it
    /// *subtracts* the interval, splitting any overlapping entry (verified
    /// against nginx 1.28 by `geo.t`'s "ranges delete" cases).
    pub fn delete(&mut self, key: &str) {
        if let Some((s, e)) = parse_range(key) {
            let (ds, de, dv6) = (s.0, e.0, s.1);
            if ds > de {
                return;
            }
            let mut out = Vec::with_capacity(self.ranges_v.len() + 2);
            for r in self.ranges_v.drain(..) {
                if r.v6 != dv6 || r.end < ds || r.start > de {
                    out.push(r);
                    continue;
                }
                // Left remainder.
                if r.start < ds {
                    out.push(Range {
                        start: r.start,
                        end: ds - 1,
                        v6: r.v6,
                        value: r.value.clone(),
                    });
                }
                // Right remainder.
                if r.end > de {
                    out.push(Range {
                        start: de + 1,
                        end: r.end,
                        v6: r.v6,
                        value: r.value,
                    });
                }
            }
            self.ranges_v = out;
            return;
        }
        if let Some((net, prefix)) = parse_cidr(key) {
            self.cidrs.retain(|c| !(c.net == net && c.prefix == prefix));
        }
    }

    /// `proxy <addr>`: mark a trusted proxy address.
    pub fn add_proxy(&mut self, key: &str) -> bool {
        let Some((net, prefix)) = parse_cidr(key) else {
            return false;
        };
        self.proxies.push(Cidr {
            net,
            prefix,
            value: String::new(),
        });
        true
    }

    /// Is `addr` one of the configured trusted proxies?
    pub fn is_trusted(&self, addr: &str) -> bool {
        let Ok(ip) = addr.trim().parse::<IpAddr>() else {
            return false;
        };
        self.proxies
            .iter()
            .any(|c| cidr_contains(&c.net, c.prefix, ip).is_some())
    }

    /// Pick the address that should be looked up, honouring `proxy`.
    ///
    /// `peer` is the connection's address; `xff` the `X-Forwarded-For` value.
    pub fn resolve_addr(&self, peer: &str, xff: Option<&str>) -> String {
        let Some(xff) = xff else {
            return peer.to_string();
        };
        if self.proxies.is_empty() || !self.is_trusted(peer) {
            return peer.to_string();
        }
        let parts: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return peer.to_string();
        }
        if !self.proxy_recursive {
            // Only the address the trusted proxy appended.
            return parts[parts.len() - 1].to_string();
        }
        // recursive: skip trusted proxies from the right
        for p in parts.iter().rev() {
            if !self.is_trusted(p) {
                return p.to_string();
            }
        }
        peer.to_string()
    }

    pub fn lookup(&self, addr: &str) -> Option<&str> {
        let ip: IpAddr = addr.trim().parse().ok()?;

        if self.ranges {
            let (n, v6) = to_num(ip)?;
            let mut best: Option<(u128, &str)> = None;
            for r in &self.ranges_v {
                if r.v6 != v6 {
                    continue;
                }
                if n >= r.start && n <= r.end {
                    let span = r.end - r.start;
                    if best.map_or(true, |(b, _)| span < b) {
                        best = Some((span, &r.value));
                    }
                }
            }
            if let Some((_, v)) = best {
                return Some(v);
            }
            return self.default.as_deref();
        }

        // Longest prefix wins.
        let mut best: Option<(u8, &str)> = None;
        for c in &self.cidrs {
            if let Some(len) = cidr_contains(&c.net, c.prefix, ip) {
                if best.map_or(true, |(b, _)| len > b) {
                    best = Some((len, &c.value));
                }
            }
        }
        best.map(|(_, v)| v).or(self.default.as_deref())
    }
}

fn to_num(ip: IpAddr) -> Option<(u128, bool)> {
    match ip {
        IpAddr::V4(v) => Some((u32::from(v) as u128, false)),
        IpAddr::V6(v) => Some((u128::from(v), true)),
    }
}

fn parse_cidr(key: &str) -> Option<(IpAddr, u8)> {
    match key.split_once('/') {
        Some((ip, p)) => Some((ip.parse().ok()?, p.parse().ok()?)),
        None => {
            let ip: IpAddr = key.parse().ok()?;
            let p = if ip.is_ipv4() { 32 } else { 128 };
            Some((ip, p))
        }
    }
}

fn parse_range(key: &str) -> Option<((u128, bool), (u128, bool))> {
    let (a, b) = key.split_once('-')?;
    let a: IpAddr = a.trim().parse().ok()?;
    let b: IpAddr = b.trim().parse().ok()?;
    Some((to_num(a)?, to_num(b)?))
}

/// Does `ip` fall inside `net/prefix`? Returns the prefix length when it does.
fn cidr_contains(net: &IpAddr, prefix: u8, ip: IpAddr) -> Option<u8> {
    let (n, n6) = to_num(*net)?;
    let (m, m6) = to_num(ip)?;
    if n6 != m6 {
        return None;
    }
    let width: u32 = if m6 { 128 } else { 32 };
    let p = prefix as u32;
    if p > width {
        return None;
    }
    let shift = width - p;
    if shift == 0 {
        // A /32 (or /128) must still be an exact match — forgetting this made
        // `proxy 127.0.0.1` trust every address.
        return if n == m { Some(prefix) } else { None };
    }
    let mask = u128::MAX << shift;
    if (n & mask) == (m & mask) {
        Some(prefix)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo(entries: &[(&str, &str)]) -> GeoDef {
        let mut g = GeoDef::new(None, "geo".into());
        for (k, v) in entries {
            assert!(g.add(k, v.to_string()), "bad key {k}");
        }
        g
    }

    #[test]
    fn longest_prefix_wins() {
        let g = geo(&[
            ("127.0.0.0/8", "loopback"),
            ("192.0.2.0/24", "test"),
            ("0.0.0.0/0", "world"),
        ]);
        assert_eq!(g.lookup("127.0.0.1"), Some("loopback"));
        assert_eq!(g.lookup("192.0.2.5"), Some("test"));
        assert_eq!(g.lookup("8.8.8.8"), Some("world"));
    }

    #[test]
    fn delete_removes_entry() {
        let mut g = geo(&[("127.0.0.0/8", "loopback"), ("0.0.0.0/0", "world")]);
        g.delete("127.0.0.0/8");
        assert_eq!(g.lookup("127.0.0.1"), Some("world"));
    }

    #[test]
    fn single_host_cidr_is_exact() {
        let g = geo(&[("127.0.0.1", "loopback"), ("0.0.0.0/0", "world")]);
        assert_eq!(g.lookup("127.0.0.1"), Some("loopback"));
        assert_eq!(g.lookup("127.0.0.2"), Some("world"));
        assert_eq!(g.lookup("10.1.2.3"), Some("world"));
    }

    #[test]
    fn ranges_mode() {
        let mut g = GeoDef::new(Some("$arg_ip".into()), "v".into());
        g.set_ranges();
        g.set_default("default".into());
        assert!(g.add("127.0.0.0-127.0.0.1", "loopback".into()));
        assert!(g.add("10.10.3.0-10.11.2.255", "foo".into()));
        g.delete("10.10.3.0-10.11.2.255");
        assert_eq!(g.lookup("127.0.0.1"), Some("loopback"));
        assert_eq!(g.lookup("10.10.3.5"), Some("default"));
        assert_eq!(g.lookup("9.9.9.9"), Some("default"));
    }
}
