//! Stream variables, for `return` (and anything else that needs `$name`).
//!
//! `ngx_stream_*_module` registers variables the same way the http modules do,
//! with one namespace per section: a `geo` block in `stream {}` creates stream
//! variables, and the http ones are invisible here. Two things follow, and both
//! are asserted by `stream_geo.t`:
//!
//!   * a `geo` source may itself be a variable (`geo $var $geo_from_var`), so
//!     resolution recurses -- `map` first, then `geo`, then the connection;
//!   * a source that is not an address at all (`$var` = `loopback`) makes the
//!     lookup fall through to `geo`'s `default`, rather than erroring.

use std::net::SocketAddr;

use crate::geo::GeoDef;
use crate::mapping::MapDef;

/// The TLS facts `$ssl_*` report, filled in after the handshake.
///
/// `ngx_stream_ssl_module` registers these as ordinary variables, so on a
/// plaintext connection they are simply *not found* and render as the empty
/// string -- which is why `stream_ssl_variables.t` expects `:::` from a
/// non-TLS listener.
#[derive(Default, Clone)]
pub struct SslFacts {
    /// `$ssl_session_reused`: `r` when the handshake resumed, `.` otherwise.
    pub reused: bool,
    pub session_id: String,
    pub cipher: String,
    /// `TLSv1.3`, `TLSv1.2`, ... (nginx's spelling, not rustls's).
    pub protocol: String,
    pub server_name: String,
    /// `$ssl_alpn_protocol`: the negotiated ALPN protocol, empty when the
    /// client offered none.
    pub alpn: String,
    pub client_verify: String,
    pub client_cert: String,
}

/// Everything a stream variable may read.
pub struct Vars<'a> {
    pub peer: SocketAddr,
    /// The client arrived over a unix socket. nginx renders `$remote_addr` as
    /// the literal `unix:` and leaves `$remote_port` empty for those sessions
    /// (verified against the reference build: `addr=[unix:] port=[]`), which is
    /// what `stream_geo_unix.t` depends on -- geo cannot parse `unix:` and falls
    /// back to INADDR_NONE, so a `255.255.255.255` entry matches.
    pub peer_unix: bool,
    /// `$remote_addr` after `set_real_ip_from` rewrote it, if it did.
    pub eff: Option<SocketAddr>,
    pub local: SocketAddr,
    /// `proxy` addressed this server? nginx reports `PROXY` for a connection
    /// that carried a header, `TCP`/`UDP` otherwise.
    pub udp: bool,
    pub maps: &'a [MapDef],
    pub geos: &'a [GeoDef],
    pub ssl: Option<&'a SslFacts>,
    /// The header consumed by `listen ... proxy_protocol`, which backs
    /// `$proxy_protocol_addr` / `_port` / `_server_*` / `_tlv_*`.
    pub proxy_protocol: Option<&'a crate::proxyproto::Pp>,
    /// Values produced by `set`, which override both the built-ins and any
    /// `map`/`geo` of the same name (`stream_set.t`).
    pub custom: &'a std::collections::HashMap<String, String>,
    /// `split_clients` buckets, resolved like a `map`.
    pub splits: &'a [crate::split::SplitClients],
    /// `$connection`: 1 for the first connection to this worker.
    pub connection: u64,
}

impl Vars<'_> {
    /// Resolve one variable name (without the `$`). `None` means "no such
    /// variable", which renders as the empty string.
    pub fn get(&self, name: &str) -> Option<String> {
        if let Some(v) = self.custom.get(name) {
            return Some(v.clone());
        }
        Some(match name {
            // After `set_real_ip_from` the address is the rewritten one whatever
            // the peer family was (`ngx_stream_realip_set_addr` overwrites
            // `c->addr_text` outright), so `eff` wins over the unix marker.
            "remote_addr" => match self.eff {
                Some(a) => a.ip().to_string(),
                None if self.peer_unix => "unix:".to_string(),
                None => self.peer.ip().to_string(),
            },
            // `ngx_stream_realip_remote_addr_variable`: the saved original when
            // realip applied, otherwise the peer itself -- so the two agree
            // whenever nothing was rewritten.
            "realip_remote_addr" => {
                if self.peer_unix {
                    "unix:".to_string()
                } else {
                    self.peer.ip().to_string()
                }
            }
            "realip_remote_port" => {
                if self.peer_unix {
                    String::new()
                } else {
                    self.peer.port().to_string()
                }
            }
            "remote_port" => match self.eff {
                Some(a) => a.port().to_string(),
                None if self.peer_unix => String::new(),
                None => self.peer.port().to_string(),
            },
            "server_addr" => self.local.ip().to_string(),
            "server_port" => self.local.port().to_string(),
            "binary_remote_addr" => binary_addr(&self.eff.unwrap_or(self.peer)),
            // `$proxy_protocol_*`: absent without a header, like nginx.
            "proxy_protocol_addr" => self.proxy_protocol?.src_addr.clone(),
            "proxy_protocol_port" => {
                crate::proxyproto::Pp::port_text(self.proxy_protocol?.src_port)
            }
            "proxy_protocol_server_addr" => self.proxy_protocol?.dst_addr.clone(),
            "proxy_protocol_server_port" => {
                crate::proxyproto::Pp::port_text(self.proxy_protocol?.dst_port)
            }
            "protocol" => {
                if self.udp {
                    "UDP".to_string()
                } else {
                    "TCP".to_string()
                }
            }
            "status" => "200".to_string(),
            "bytes_sent" | "bytes_received" => "0".to_string(),
            "nginx_version" => crate::COMPAT_VERSION.to_string(),
            "hostname" => std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap_or_default()
                .trim()
                .to_lowercase(),
            "pid" => std::process::id().to_string(),
            "msec" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                format!("{}.{:03}", now.as_secs(), now.subsec_millis())
            }
            "time_local" => crate::util::strftime_gmt(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                "%d/%b/%Y:%H:%M:%S +0000",
            ),
            "time_iso8601" => crate::util::strftime_gmt(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                "%Y-%m-%dT%H:%M:%S+00:00",
            ),
            "session_time" => "0.000".to_string(),
            "connection" => self.connection.to_string(),
            "connection_requests" => "1".to_string(),
            // Every `$ssl_*` is absent on a plaintext connection.
            "ssl_session_reused" => {
                let f = self.ssl?;
                if f.reused {
                    "r".to_string()
                } else {
                    ".".to_string()
                }
            }
            "ssl_session_id" => self.ssl?.session_id.clone(),
            "ssl_cipher" => self.ssl?.cipher.clone(),
            "ssl_protocol" => self.ssl?.protocol.clone(),
            "ssl_server_name" => self.ssl?.server_name.clone(),
            "ssl_alpn_protocol" => self.ssl?.alpn.clone(),
            "ssl_client_verify" => self.ssl?.client_verify.clone(),
            "ssl_client_cert" => self.ssl?.client_cert.clone(),
            _ => {
                if let Some(tlv) = name.strip_prefix("proxy_protocol_tlv_") {
                    let pp = self.proxy_protocol?;
                    return match pp.tlv(tlv) {
                        Ok(Some(v)) => Some(String::from_utf8_lossy(&v).to_string()),
                        Ok(None) => Some(String::new()),
                        Err(()) => Some(String::new()),
                    };
                }
                if let Some(m) = self.maps.iter().find(|m| m.var == name) {
                    return Some(self.eval_map(m));
                }
                if let Some(g) = self.geos.iter().find(|g| g.var == name) {
                    return Some(self.eval_geo(g));
                }
                if let Some(sc) = self.splits.iter().find(|s| s.var == name) {
                    let key = self.expand(&sc.source);
                    return Some(sc.pick(&key).unwrap_or_default().to_string());
                }
                return None;
            }
        })
    }

    fn eval_map(&self, m: &MapDef) -> String {
        let input = self.expand(&m.source);
        match m.lookup_with_captures(&input) {
            Some((value, caps)) => self.expand_with(value, &caps),
            None => String::new(),
        }
    }

    fn eval_geo(&self, g: &GeoDef) -> String {
        // `geo` with no source reads `$remote_addr`; with one, that variable.
        //
        // The implicit case must go through the *same* rendering, not
        // `peer.ip()`: for a unix session `$remote_addr` is the literal `unix:`,
        // which geo cannot parse and therefore maps to INADDR_NONE -- the same
        // value nginx uses for an AF_UNIX peer (`stream_geo_unix.t`, "geo unix").
        let addr = match &g.source {
            Some(src) => self.expand(src),
            None => self.get("remote_addr").unwrap_or_default(),
        };
        g.lookup(&addr)
            .map(|v| v.to_string())
            .or_else(|| g.default.clone())
            .unwrap_or_default()
    }

    /// Expand every `$name` in `text`.
    ///
    /// A single pass, so a value that itself contains `$` is never re-expanded
    /// -- nginx compiles these at config time and does the same.
    pub fn expand(&self, text: &str) -> String {
        self.expand_with(text, &[])
    }

    /// Expand with a capture table in scope, which is how a `map` value
    /// template reaches `$1` / `$ncap`.
    pub fn expand_with(&self, text: &str, caps: &[(String, String)]) -> String {
        if !text.contains('$') {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len() + 16);
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'$' {
                let start = i;
                while i < bytes.len() && bytes[i] != b'$' {
                    i += 1;
                }
                // Slice, not byte-push: a UTF-8 literal must stay byte-identical.
                out.push_str(&text[start..i]);
                continue;
            }
            i += 1;
            if i < bytes.len() && bytes[i] == b'{' {
                let close = text[i..].find('}').map(|p| i + p);
                if let Some(end) = close {
                    let name = &text[i + 1..end];
                    out.push_str(&self.resolve(name, caps).unwrap_or_default());
                    i = end + 1;
                    continue;
                }
            }
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if start == i {
                // A lone `$`: nginx keeps it.
                out.push('$');
                continue;
            }
            out.push_str(&self.resolve(&text[start..i], caps).unwrap_or_default());
        }
        out
    }
}

impl Vars<'_> {
    /// A name in scope: the capture table first (a `map`'s `$1` shadows
    /// nothing, because nginx keeps captures in a separate array), then the
    /// ordinary variables.
    fn resolve(&self, name: &str, caps: &[(String, String)]) -> Option<String> {
        if let Some((_, v)) = caps.iter().find(|(k, _)| k == name) {
            return Some(v.clone());
        }
        self.get(name)
    }
}

/// `$binary_remote_addr`: the packed address as raw bytes.
fn binary_addr(a: &SocketAddr) -> String {
    match a.ip() {
        std::net::IpAddr::V4(v) => v
            .octets()
            .iter()
            .map(|b| (*b as char).to_string())
            .collect(),
        std::net::IpAddr::V6(v) => v
            .octets()
            .iter()
            .map(|b| (*b as char).to_string())
            .collect(),
    }
}

#[cfg(test)]
fn no_custom() -> &'static std::collections::HashMap<String, String> {
    static EMPTY: std::sync::OnceLock<std::collections::HashMap<String, String>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(std::collections::HashMap::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars<'a>(maps: &'a [MapDef], geos: &'a [GeoDef]) -> Vars<'a> {
        Vars {
            peer_unix: false,
            eff: None,
            peer: "127.0.0.1:5000".parse().unwrap(),
            local: "127.0.0.1:8080".parse().unwrap(),
            udp: false,
            maps,
            geos,
            ssl: None,
            proxy_protocol: None,
            custom: no_custom(),
            splits: &[],
            connection: 1,
        }
    }

    #[test]
    fn connection_variables() {
        let (maps, geos) = (Vec::new(), Vec::new());
        let v = vars(&maps, &geos);
        assert_eq!(v.expand("$remote_addr"), "127.0.0.1");
        assert_eq!(v.expand("$server_port"), "8080");
        assert_eq!(v.expand("a${remote_port}b"), "a5000b");
        // An unknown name is the empty string, not a literal.
        assert_eq!(v.expand("x$nope.y"), "x.y");
        // No `$` at all: returned untouched, byte for byte.
        assert_eq!(v.expand("模様"), "模様");
    }

    #[test]
    fn map_then_geo() {
        // `map $server_port $var { ... }` feeding `geo $var $g`.
        let mut m = MapDef {
            source: "$server_port".into(),
            var: "var".into(),
            hostnames: false,
            volatile: false,
            default: None,
            entries: Vec::new(),
        };
        m.entries.push(crate::mapping::Entry {
            key: "8080".into(),
            value: "192.0.2.1".into(),
        });
        let mut g = GeoDef::new(Some("$var".into()), "g".into());
        g.set_default("default".into());
        g.add("192.0.2.0/24", "test".into());
        g.add("127.0.0.0/8", "loopback".into());
        let (maps, geos) = (vec![m], vec![g]);
        let v = vars(&maps, &geos);
        assert_eq!(v.expand("$var"), "192.0.2.1");
        assert_eq!(v.expand("$g"), "test");
    }

    #[test]
    fn a_non_address_source_falls_through_to_default() {
        let mut m = MapDef {
            source: "$server_port".into(),
            var: "var".into(),
            hostnames: false,
            volatile: false,
            default: None,
            entries: Vec::new(),
        };
        m.entries.push(crate::mapping::Entry {
            key: "8080".into(),
            value: "loopback".into(),
        });
        let mut g = GeoDef::new(Some("$var".into()), "g".into());
        g.set_default("default".into());
        g.add("127.0.0.0/8", "loopback".into());
        let (maps, geos) = (vec![m], vec![g]);
        assert_eq!(vars(&maps, &geos).expand("$g"), "default");
    }
}
