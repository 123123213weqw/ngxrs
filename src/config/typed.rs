//! Typed, nginx-shaped configuration model.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::parser::{ConfigError, Directive};

pub const DEFAULT_CLIENT_MAX_BODY: u64 = 1024 * 1024;
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(75);

#[derive(Debug, Clone)]
pub enum Match {
    Exact(String),
    Prefix(String),
    PrefixNoRegex(String),
    Regex { re: regex::Regex, ci: bool, src: String },
    Named(String),
}

#[derive(Debug, Clone)]
pub struct Location {
    pub matcher: Match,
    pub cfg: LocCfg,
    pub nested: Vec<Location>,
}

#[derive(Debug, Clone)]
pub struct LocCfg {
    pub root: PathBuf,
    pub alias: Option<PathBuf>,
    pub index: Vec<String>,
    pub autoindex: bool,
    pub gzip: bool,
    pub client_max_body_size: u64,
    pub headers: Vec<(String, String)>,
    pub error_pages: BTreeMap<u16, String>,
    pub ret: Option<(u16, String)>,
    pub try_files: Vec<String>,
    pub internal: bool,
    pub expires: Option<String>,
    /// Length of the location prefix, used to strip it for `alias`.
    pub prefix_len: usize,
    // ---- gzip ----
    pub gzip_min_length: u64,
    pub gzip_comp_level: u32,
    pub gzip_types: Vec<String>,
    pub gzip_vary: bool,
    // ---- reverse proxy ----
    /// `rewrite <regex> <replacement> [flag]` entries, in config order.
    pub rewrites: Vec<Rewrite>,
    pub proxy_pass: Option<ProxyPass>,
    /// Set while parsing `proxy_pass http://<name>` so the http level can
    /// resolve the name to an `upstream` index after all blocks are read.
    pub proxy_upstream_name: Option<String>,
    pub proxy_set_headers: Vec<(String, String)>,
    pub proxy_http_version: u8,
    pub proxy_connect_timeout: Duration,
    pub proxy_read_timeout: Duration,
    pub proxy_send_timeout: Duration,
    pub proxy_buffering: bool,
    pub proxy_hide_headers: Vec<String>,
}

impl LocCfg {
    fn new(root: PathBuf) -> Self {
        LocCfg {
            root,
            alias: None,
            index: vec!["index.html".to_string()],
            autoindex: false,
            gzip: false,
            client_max_body_size: DEFAULT_CLIENT_MAX_BODY,
            headers: Vec::new(),
            error_pages: BTreeMap::new(),
            ret: None,
            try_files: Vec::new(),
            internal: false,
            expires: None,
            prefix_len: 0,
            gzip_min_length: 20,
            gzip_comp_level: 1,
            gzip_types: Vec::new(),
            gzip_vary: false,
            rewrites: Vec::new(),
            proxy_pass: None,
            proxy_upstream_name: None,
            proxy_set_headers: Vec::new(),
            proxy_http_version: 1,
            proxy_connect_timeout: Duration::from_secs(60),
            proxy_read_timeout: Duration::from_secs(60),
            proxy_send_timeout: Duration::from_secs(60),
            proxy_buffering: true,
            proxy_hide_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub re: regex::Regex,
    pub replacement: String,
    pub flag: RewriteFlag,
}

/// Compile nginx's `$1..$9` replacement syntax into a format we can expand.
pub fn compile_rewrite(re_src: &str, replacement: &str, flag: RewriteFlag) -> Option<Rewrite> {
    let re = regex::Regex::new(re_src).ok()?;
    Some(Rewrite {
        re,
        replacement: replacement.to_string(),
        flag,
    })
}

#[derive(Debug, Clone)]
pub enum ProxyTarget {
    /// `proxy_pass http://127.0.0.1:8080` or with an explicit host name.
    Addr(SocketAddr),
    /// Reference to an `upstream {}` block.
    Upstream(usize),
}

#[derive(Debug, Clone)]
pub struct ProxyPass {
    pub target: ProxyTarget,
    /// URI prefix to substitute for the matched location prefix (may be empty).
    pub uri: Option<String>,
    pub host_header: String,
    pub https: bool,
}

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub addr: SocketAddr,
    pub weight: u32,
    pub backup: bool,
    pub down: bool,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbMethod {
    RoundRobin,
    LeastConn,
    IpHash,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub method: LbMethod,
    pub keepalive: usize,
}

#[derive(Debug, Clone)]
pub struct AccessLog {
    pub path: PathBuf,
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub idx: usize,
    pub names: Vec<String>,
    pub default_loc: LocCfg,
    pub locations: Vec<Location>,
    pub access_logs: Vec<AccessLog>,
    pub keepalive_timeout: Duration,
    pub server_tokens: bool,
    pub error_pages: BTreeMap<u16, String>,
    pub access_log_off: bool,
    pub regex_names: Vec<regex::Regex>,
    // ---- TLS ----
    pub ssl: bool,
    pub ssl_certificate: Option<PathBuf>,
    pub ssl_certificate_key: Option<PathBuf>,
    pub http2: bool,
}

#[derive(Debug, Clone)]
pub struct ListenGroup {
    pub addr: SocketAddr,
    pub servers: Vec<usize>,
    pub default_server: usize,
    /// True when any server on this socket enabled TLS.
    pub ssl: bool,
}

#[derive(Debug)]
pub struct MimeMap {
    map: HashMap<String, String>,
}

impl MimeMap {
    fn new() -> Self {
        let mut map = HashMap::new();
        for (ty, exts) in BUILTIN_TYPES {
            for e in exts.split_whitespace() {
                map.insert(e.to_string(), ty.to_string());
            }
        }
        MimeMap { map }
    }

    pub fn insert(&mut self, ty: &str, ext: &str) {
        self.map.insert(ext.to_ascii_lowercase(), ty.to_string());
    }

    pub fn get(&self, ext: &str) -> Option<&str> {
        self.map.get(ext).map(|s| s.as_str())
    }
}

const BUILTIN_TYPES: &[(&str, &str)] = &[
    ("text/html", "html htm shtml"),
    ("text/css", "css"),
    ("text/xml", "xml"),
    ("text/plain", "txt text conf"),
    ("application/javascript", "js mjs"),
    ("application/json", "json"),
    ("application/pdf", "pdf"),
    ("application/wasm", "wasm"),
    ("application/zip", "zip"),
    ("application/gzip", "gz"),
    ("image/gif", "gif"),
    ("image/jpeg", "jpeg jpg"),
    ("image/png", "png"),
    ("image/svg+xml", "svg svgz"),
    ("image/webp", "webp"),
    ("image/avif", "avif"),
    ("image/x-icon", "ico"),
    ("font/woff", "woff"),
    ("font/woff2", "woff2"),
    ("font/ttf", "ttf"),
    ("font/otf", "otf"),
    ("application/vnd.ms-fontobject", "eot"),
    ("audio/mpeg", "mp3"),
    ("audio/ogg", "ogg"),
    ("video/mp4", "mp4"),
    ("video/webm", "webm"),
    ("application/octet-stream", "bin exe dll"),
];

#[derive(Debug)]
pub struct Http {
    pub servers: Vec<Server>,
    pub groups: Vec<ListenGroup>,
    pub mime: MimeMap,
    pub default_type: String,
    pub keepalive_timeout: Duration,
    pub keepalive_requests: u64,
    pub sendfile: bool,
    pub tcp_nopush: bool,
    pub tcp_nodelay: bool,
    pub gzip: bool,
    pub server_tokens: bool,
    pub client_max_body_size: u64,
    pub default_loc: LocCfg,
    pub default_access_logs: Vec<AccessLog>,
    pub upstreams: Vec<Upstream>,
    pub log_formats: HashMap<String, String>,
}

#[derive(Debug)]
pub struct Config {
    pub prefix: PathBuf,
    pub conf_path: PathBuf,
    pub worker_processes: usize,
    pub daemon: bool,
    pub pid: Option<PathBuf>,
    pub error_log: Option<PathBuf>,
    pub http: Http,
    pub warnings: Vec<String>,
}

impl Http {
    pub fn server(&self, idx: usize) -> &Server {
        &self.servers[idx]
    }

    pub fn group_for(&self, addr: &SocketAddr) -> Option<&ListenGroup> {
        self.groups.iter().find(|g| &g.addr == addr)
    }
}

fn sem(file: &Path, line: u32, msg: impl Into<String>) -> ConfigError {
    ConfigError::Semantic {
        file: file.to_path_buf(),
        line,
        msg: msg.into(),
    }
}

fn parse_on_off(s: &str) -> Option<bool> {
    match s {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

pub fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1024u64),
        b'm' | b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.parse::<u64>().ok().map(|v| v * mult)
}

pub fn parse_time(s: &str) -> Option<Duration> {
    let b = s.as_bytes();
    let (num, mult) = match b.last()? {
        b's' => (&s[..s.len() - 1], 1000u64),
        b'm' => (&s[..s.len() - 1], 60 * 1000),
        b'h' => (&s[..s.len() - 1], 3600 * 1000),
        b'd' => (&s[..s.len() - 1], 86400 * 1000),
        b'w' => (&s[..s.len() - 1], 7 * 86400 * 1000),
        b'M' => (&s[..s.len() - 1], 30 * 86400 * 1000),
        b'y' => (&s[..s.len() - 1], 365 * 86400 * 1000),
        _ => (s, 1000),
    };
    num.parse::<u64>()
        .ok()
        .map(|v| Duration::from_millis(v.saturating_mul(mult)))
}

fn resolve_path(prefix: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        prefix.join(pb)
    }
}

/// `http://host[:port][/uri]` -> ProxyPass. Upstream names are resolved later.
pub fn parse_proxy_pass(url: &str) -> Option<ProxyPass> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return None;
    };
    let (authority, uri) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    if authority.is_empty() {
        return None;
    }

    let target = match parse_listen(authority) {
        Some(addr) => ProxyTarget::Addr(addr),
        None => ProxyTarget::Upstream(usize::MAX),
    };
    // A bare port or host:port defaults to port 80 when only a host is given.
    let target = match target {
        ProxyTarget::Addr(a) if !authority.contains(':') => {
            ProxyTarget::Addr(SocketAddr::new(a.ip(), 80))
        }
        other => other,
    };
    // nginx's $proxy_host is the authority exactly as written in proxy_pass.
    let host_header = authority.to_string();

    Some(ProxyPass {
        target,
        uri,
        host_header,
        https: scheme,
    })
}

pub fn proxy_upstream_name(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    if authority.is_empty() || parse_listen(authority).is_some() {
        return None;
    }
    Some(authority.to_string())
}

fn parse_upstream(d: &Directive) -> Result<Upstream, ConfigError> {
    let name = d
        .args
        .first()
        .ok_or_else(|| sem(&d.file, d.line, "upstream requires a name"))?
        .clone();
    let mut up = Upstream {
        name,
        servers: Vec::new(),
        method: LbMethod::RoundRobin,
        keepalive: 0,
    };

    for child in d.block.as_ref().map(|b| b.as_slice()).unwrap_or(&[]) {
        match child.name.as_str() {
            "server" => {
                let addr_arg = child
                    .args
                    .first()
                    .ok_or_else(|| sem(&child.file, child.line, "server requires an address"))?;
                let mut addr = parse_listen(addr_arg).ok_or_else(|| {
                    sem(&child.file, child.line, format!("invalid server address \"{addr_arg}\""))
                })?;
                // upstream "host:port" without an IP is resolved later; here we
                // accept IPv4/IPv6 literals and fall back to 127.0.0.1.
                if !addr_arg.contains(':') {
                    addr = SocketAddr::new(addr.ip(), 80);
                }
                let mut srv = UpstreamServer {
                    addr,
                    weight: 1,
                    backup: false,
                    down: false,
                    name: addr_arg.clone(),
                };
                for p in &child.args[1..] {
                    if p == "backup" {
                        srv.backup = true;
                    } else if p == "down" {
                        srv.down = true;
                    } else if let Some(w) = p.strip_prefix("weight=") {
                        srv.weight = w.parse().unwrap_or(1).max(1);
                    }
                }
                up.servers.push(srv);
            }
            "least_conn" => up.method = LbMethod::LeastConn,
            "ip_hash" => up.method = LbMethod::IpHash,
            "keepalive" => {
                up.keepalive = child
                    .args
                    .first()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
            }
            "keepalive_requests" | "keepalive_timeout" | "zone" | "hash" | "queue" | "resolver" => {}
            other => {
                return Err(sem(
                    &child.file,
                    child.line,
                    format!("unknown directive \"{other}\" in upstream"),
                ))
            }
        }
    }

    if up.servers.is_empty() {
        return Err(sem(&d.file, d.line, "upstream has no servers"));
    }
    Ok(up)
}

/// Patch every location's `proxy_pass http://<name>` to the upstream index.
fn resolve_proxy_upstreams(http: &mut Http) -> Result<(), ConfigError> {
    let lookup: HashMap<String, usize> = http
        .upstreams
        .iter()
        .enumerate()
        .map(|(i, u)| (u.name.clone(), i))
        .collect();

    fn fix(cfg: &mut LocCfg, lookup: &HashMap<String, usize>) -> Result<(), ConfigError> {
        if let (Some(name), Some(pp)) = (cfg.proxy_upstream_name.clone(), cfg.proxy_pass.as_mut()) {
            match lookup.get(&name) {
                Some(&idx) => {
                    pp.target = ProxyTarget::Upstream(idx);
                    pp.host_header = name.clone();
                    if std::env::var_os("NGXRS_DEBUG_CONFIG").is_some() {
                        eprintln!("ngxrs: resolved proxy_pass {name} -> upstream #{idx}");
                    }
                }
                None => {
                    return Err(ConfigError::Semantic {
                        file: PathBuf::from("<config>"),
                        line: 0,
                        msg: format!("proxy_pass refers to unknown upstream \"{name}\""),
                    })
                }
            }
        }
        Ok(())
    }

    fn walk(locs: &mut [Location], lookup: &HashMap<String, usize>) -> Result<(), ConfigError> {
        for l in locs {
            fix(&mut l.cfg, lookup)?;
            walk(&mut l.nested, lookup)?;
        }
        Ok(())
    }

    fix(&mut http.default_loc, &lookup)?;
    for s in &mut http.servers {
        fix(&mut s.default_loc, &lookup)?;
        walk(&mut s.locations, &lookup)?;
    }
    let _ = http;
    Ok(())
}

fn parse_listen(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    }
    if s == "*" {
        return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)));
    }
    if let Some(rest) = s.strip_prefix("*:") {
        if let Ok(port) = rest.parse::<u16>() {
            return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
        }
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 80));
        }
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, port));
            }
            if host == "*" {
                return Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
            }
        }
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 80));
    }
    None
}

fn build_regex(src: &str, ci: bool) -> Option<regex::Regex> {
    let pattern = if ci {
        format!("(?i:{src})")
    } else {
        src.to_string()
    };
    regex::Regex::new(&pattern).ok()
}

struct Builder {
    prefix: PathBuf,
    warnings: Vec<String>,
}

impl Builder {
    fn warn(&mut self, d: &Directive, msg: impl Into<String>) {
        self.warnings.push(format!(
            "{}:{}: {}",
            d.file.display(),
            d.line,
            msg.into()
        ));
    }

    fn unknown(&mut self, d: &Directive, ctx: &str) {
        self.warn(d, format!("unknown directive \"{}\" in {}", d.name, ctx));
    }

    fn apply_loc(&mut self, d: &Directive, cfg: &mut LocCfg) -> Result<bool, ConfigError> {
        match d.name.as_str() {
            "root" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "root requires a path"))?;
                cfg.root = resolve_path(&self.prefix, v);
            }
            "alias" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "alias requires a path"))?;
                cfg.alias = Some(resolve_path(&self.prefix, v));
            }
            "index" => {
                cfg.index = d.args.clone();
            }
            "autoindex" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "autoindex requires on|off"))?;
                cfg.autoindex = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid autoindex value \"{v}\"")))?;
            }
            "gzip" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "gzip requires on|off"))?;
                cfg.gzip = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid gzip value \"{v}\"")))?;
            }
            "client_max_body_size" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "client_max_body_size requires a size"))?;
                cfg.client_max_body_size = if v == "0" {
                    u64::MAX
                } else {
                    parse_size(v).ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?
                };
            }
            "add_header" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "add_header requires at least 2 arguments"));
                }
                cfg.headers
                    .push((d.args[0].clone(), d.args[1].clone()));
            }
            "error_page" => {
                let mut codes: Vec<u16> = Vec::new();
                let mut uri: Option<String> = None;
                let mut override_status: Option<String> = None;
                for a in &d.args {
                    if a.starts_with('=') {
                        // `error_page 404 =200 /empty.gif`
                        override_status = Some(a.clone());
                    } else if let Ok(c) = a.parse::<u16>() {
                        codes.push(c);
                    } else {
                        uri = Some(a.clone());
                    }
                }
                let uri = uri.ok_or_else(|| sem(&d.file, d.line, "error_page requires a URI"))?;
                let stored = match override_status {
                    Some(o) => format!("{o} {uri}"),
                    None => uri,
                };
                for c in codes {
                    cfg.error_pages.insert(c, stored.clone());
                }
            }
            "rewrite" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "rewrite requires a regex and a replacement"));
                }
                let flag = match d.args.get(2).map(|s| s.as_str()) {
                    None => RewriteFlag::None,
                    Some("last") => RewriteFlag::Last,
                    Some("break") => RewriteFlag::Break,
                    Some("redirect") => RewriteFlag::Redirect,
                    Some("permanent") => RewriteFlag::Permanent,
                    Some(other) => {
                        return Err(sem(
                            &d.file,
                            d.line,
                            format!("invalid rewrite flag \"{other}\""),
                        ))
                    }
                };
                let rw = compile_rewrite(&d.args[0], &d.args[1], flag)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid regex \"{}\"", d.args[0])))?;
                cfg.rewrites.push(rw);
            }
            "set" | "if" | "break" => {
                // Accepted at this scope; conditional evaluation is not wired
                // into the rewrite engine yet (see COMPAT.md).
            }
            "return" => {
                if d.args.len() < 1 {
                    return Err(sem(&d.file, d.line, "return requires a status code"));
                }
                let code: u16 = d.args[0]
                    .parse()
                    .map_err(|_| sem(&d.file, d.line, "return requires a numeric status"))?;
                let body = d.args.get(1).cloned().unwrap_or_default();
                cfg.ret = Some((code, body));
            }
            "try_files" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "try_files requires at least 2 arguments"));
                }
                cfg.try_files = d.args.clone();
            }
            "internal" => cfg.internal = true,
            "expires" => {
                cfg.expires = Some(d.args.first().cloned().unwrap_or_else(|| "off".into()));
            }
            "gzip_min_length" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "gzip_min_length requires a size"))?;
                cfg.gzip_min_length = parse_size(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid size \"{v}\"")))?;
            }
            "gzip_comp_level" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "gzip_comp_level requires a level"))?;
                cfg.gzip_comp_level = v
                    .parse::<u32>()
                    .ok()
                    .filter(|l| (1..=9).contains(l))
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid gzip level \"{v}\"")))?;
            }
            "gzip_types" => {
                cfg.gzip_types = d.args.clone();
            }
            "gzip_vary" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "gzip_vary requires on|off"))?;
                cfg.gzip_vary = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid gzip_vary value \"{v}\"")))?;
            }
            "proxy_pass" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "proxy_pass requires a URL"))?;
                cfg.proxy_pass = Some(parse_proxy_pass(v).ok_or_else(|| {
                    sem(&d.file, d.line, format!("invalid proxy_pass URL \"{v}\""))
                })?);
                cfg.proxy_pass.as_mut().unwrap().target = cfg
                    .proxy_pass
                    .as_ref()
                    .unwrap()
                    .target
                    .clone();
                if let Some(name) = proxy_upstream_name(v) {
                    cfg.proxy_upstream_name = Some(name);
                }
            }
            "proxy_set_header" => {
                if d.args.len() < 2 {
                    return Err(sem(&d.file, d.line, "proxy_set_header requires 2 arguments"));
                }
                cfg.proxy_set_headers
                    .push((d.args[0].clone(), d.args[1..].join(" ")));
            }
            "proxy_http_version" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "proxy_http_version requires a value"))?;
                cfg.proxy_http_version = match v.as_str() {
                    "1.0" => 0,
                    "1.1" => 1,
                    _ => return Err(sem(&d.file, d.line, format!("invalid proxy_http_version \"{v}\""))),
                };
            }
            "proxy_connect_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_connect_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_connect_timeout"))?;
                }
            }
            "proxy_read_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_read_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_read_timeout"))?;
                }
            }
            "proxy_send_timeout" => {
                if let Some(v) = d.args.first() {
                    cfg.proxy_send_timeout = parse_time(v)
                        .ok_or_else(|| sem(&d.file, d.line, "invalid proxy_send_timeout"))?;
                }
            }
            "proxy_buffering" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "proxy_buffering requires on|off"))?;
                cfg.proxy_buffering = parse_on_off(v)
                    .ok_or_else(|| sem(&d.file, d.line, format!("invalid proxy_buffering \"{v}\"")))?;
            }
            "proxy_next_upstream" | "proxy_next_upstream_tries" | "proxy_buffers"
            | "proxy_buffer_size" | "proxy_busy_buffers_size" | "proxy_max_temp_file_size"
            | "proxy_temp_file_write_size" | "proxy_redirect" | "proxy_cache"
            | "proxy_cache_valid" | "proxy_cache_key" | "proxy_cache_bypass" | "proxy_no_cache"
            | "proxy_intercept_errors" | "proxy_pass_request_body" | "proxy_pass_request_headers"
            | "proxy_ssl_server_name" | "proxy_ssl_verify" => {
                // Accepted, not yet honoured.
            }
            "limit_rate" | "limit_rate_after" | "sendfile" | "tcp_nopush" | "tcp_nodelay"
            | "keepalive_timeout" | "keepalive_requests" | "server_tokens" | "default_type"
            | "charset"
            | "merge_slashes" | "absolute_redirect" | "server_name_in_redirect"
            | "port_in_redirect" | "log_not_found" | "open_file_cache" | "etag" | "msie_padding" => {
                // Accepted at this scope but not yet plumbed through: handled at
                // http/server level where relevant, otherwise silently accepted.
                return Ok(true);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn parse_location(
        &mut self,
        d: &Directive,
        parent: &LocCfg,
    ) -> Result<Location, ConfigError> {
        let block = d
            .block
            .as_ref()
            .ok_or_else(|| sem(&d.file, d.line, "location requires a block"))?;

        let matcher = match d.args.as_slice() {
            [one] if one.starts_with('@') => Match::Named(one.clone()),
            [one] => Match::Prefix(one.clone()),
            [m, v] => match m.as_str() {
                "=" => Match::Exact(v.clone()),
                "~" => Match::Regex {
                    re: build_regex(v, false)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid regex \"{v}\"")))?,
                    ci: false,
                    src: v.clone(),
                },
                "~*" => Match::Regex {
                    re: build_regex(v, true)
                        .ok_or_else(|| sem(&d.file, d.line, format!("invalid regex \"{v}\"")))?,
                    ci: true,
                    src: v.clone(),
                },
                "^~" => Match::PrefixNoRegex(v.clone()),
                other => {
                    return Err(sem(
                        &d.file,
                        d.line,
                        format!("invalid location modifier \"{other}\""),
                    ))
                }
            },
            _ => return Err(sem(&d.file, d.line, "invalid location arguments")),
        };

        let mut cfg = parent.clone();
        cfg.prefix_len = match &matcher {
            Match::Exact(s) | Match::Prefix(s) | Match::PrefixNoRegex(s) => s.len(),
            _ => 0,
        };

        let mut nested = Vec::new();
        for child in block {
            if child.name == "location" {
                nested.push(self.parse_location(child, &cfg)?);
            } else if !self.apply_loc(child, &mut cfg)? {
                self.unknown(child, "location");
            }
        }

        Ok(Location {
            matcher,
            cfg,
            nested,
        })
    }

    fn parse_server(
        &mut self,
        d: &Directive,
        index: usize,
        http_default: &LocCfg,
        log_formats: &HashMap<String, String>,
        http_keepalive: Duration,
        http_tokens: bool,
    ) -> Result<(Server, Vec<(SocketAddr, bool)>), ConfigError> {
        let block = d
            .block
            .as_ref()
            .ok_or_else(|| sem(&d.file, d.line, "server requires a block"))?;

        let mut default_loc = http_default.clone();
        let mut names: Vec<String> = Vec::new();
        let mut locations: Vec<Location> = Vec::new();
        let mut access_logs: Vec<AccessLog> = Vec::new();
        let mut listens: Vec<(SocketAddr, bool)> = Vec::new();
        let mut keepalive = http_keepalive;
        let mut tokens = http_tokens;
        let mut access_log_off = false;
        let mut ssl = false;
        let mut http2 = false;
        let mut ssl_certificate: Option<PathBuf> = None;
        let mut ssl_certificate_key: Option<PathBuf> = None;

        for child in block {
            match child.name.as_str() {
                "listen" => {
                    let addr = child
                        .args
                        .first()
                        .and_then(|a| parse_listen(a))
                        .ok_or_else(|| {
                            sem(
                                &child.file,
                                child.line,
                                format!(
                                    "invalid listen address \"{}\"",
                                    child.args.first().cloned().unwrap_or_default()
                                ),
                            )
                        })?;
                    let is_default = child.args[1..]
                        .iter()
                        .any(|p| p == "default_server" || p == "default");
                    if child.args[1..].iter().any(|p| p == "ssl") {
                        ssl = true;
                    }
                    if child.args[1..].iter().any(|p| p == "http2" || p == "quic") {
                        http2 = true;
                    }
                    listens.push((addr, is_default));
                }
                "server_name" => names.extend(child.args.iter().cloned()),
                "location" => {
                    let loc = self.parse_location(child, &default_loc)?;
                    locations.push(loc);
                }
                "access_log" => {
                    if child.args.first().map(|s| s.as_str()) == Some("off") {
                        access_logs.clear();
                        access_log_off = true;
                    } else if !access_log_off {
                        let path = match child.args.first() {
                            Some(p) => p,
                            None => continue,
                        };
                        let format = match child.args.get(1).map(|s| s.as_str()).unwrap_or("combined")
                        {
                            "combined" => "combined".to_string(),
                            name => log_formats
                                .get(name)
                                .cloned()
                                .unwrap_or_else(|| "combined".to_string()),
                        };
                        access_logs.push(AccessLog {
                            path: resolve_path(&self.prefix, path),
                            format,
                        });
                        }
                }
                "keepalive_timeout" => {
                    if let Some(v) = child.args.first() {
                        keepalive = parse_time(v)
                            .ok_or_else(|| sem(&child.file, child.line, "invalid keepalive_timeout"))?;
                    }
                }
                "ssl_certificate" => {
                    if let Some(v) = child.args.first() {
                        ssl_certificate = Some(resolve_path(&self.prefix, v));
                        ssl = true;
                    }
                }
                "ssl_certificate_key" => {
                    if let Some(v) = child.args.first() {
                        ssl_certificate_key = Some(resolve_path(&self.prefix, v));
                        ssl = true;
                    }
                }
                "ssl_protocols" | "ssl_ciphers" | "ssl_prefer_server_ciphers"
                | "ssl_session_cache" | "ssl_session_timeout" | "ssl_session_tickets"
                | "ssl_dhparam" | "ssl_ecdh_curve" | "ssl_stapling" | "ssl_stapling_verify"
                | "ssl_buffer_size" | "ssl_verify_client" | "ssl_client_certificate"
                | "ssl_trusted_certificate" | "ssl_early_data" | "ssl_conf_command"
                | "http2_max_field_size" | "http2_max_header_size" | "http2_idle_timeout" => {
                    // Parsed and accepted; rustls picks safe defaults.
                }
                "server_tokens" => {
                    if let Some(v) = child.args.first() {
                        tokens = match v.as_str() {
                            "on" | "build" => true,
                            "off" => false,
                            _ => return Err(sem(&child.file, child.line, "invalid server_tokens")),
                        };
                    }
                }
                "error_page" => {
                    self.apply_loc(child, &mut default_loc)?;
                }
                _ => {
                    if !self.apply_loc(child, &mut default_loc)? {
                        self.unknown(child, "server");
                    }
                }
            }
        }


        let mut regex_names = Vec::new();
        for n in &names {
            if let Some(re) = n.strip_prefix('~') {
                if let Some(r) = build_regex(re, true) {
                    regex_names.push(r);
                } else {
                    self.warn(d, format!("invalid server_name regex \"{n}\""));
                }
            }
        }

        if listens.is_empty() {
            listens.push((SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)), false));
        }

        Ok((
            Server {
                idx: index,
                names,
                error_pages: default_loc.error_pages.clone(),
                default_loc,
                locations,
                access_logs,
                keepalive_timeout: keepalive,
                server_tokens: tokens,
                access_log_off,
                regex_names,
                ssl,
                ssl_certificate,
                ssl_certificate_key,
                http2,
            },
            listens,
        ))
    }
}

pub fn build(
    tree: Vec<Directive>,
    prefix: &Path,
    conf_path: PathBuf,
) -> Result<Config, ConfigError> {
    let mut b = Builder {
        prefix: prefix.to_path_buf(),
        warnings: Vec::new(),
    };

    let mut worker_processes = 0usize; // 0 = auto
    let mut daemon = true;
    let mut pid: Option<PathBuf> = None;
    let mut error_log: Option<PathBuf> = None;
    let mut http_roots: Vec<Directive> = Vec::new();
    let mut saw_http = false;

    for d in tree {
        match d.name.as_str() {
            "worker_processes" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "worker_processes requires a value"))?;
                worker_processes = if v == "auto" {
                    0
                } else {
                    v.parse::<usize>()
                        .map_err(|_| sem(&d.file, d.line, "invalid worker_processes"))?
                };
            }
            "daemon" => {
                let v = d.args.first().ok_or_else(|| sem(&d.file, d.line, "daemon requires on|off"))?;
                daemon = parse_on_off(v).ok_or_else(|| sem(&d.file, d.line, "invalid daemon value"))?;
            }
            "pid" => {
                if let Some(p) = d.args.first() {
                    pid = Some(resolve_path(prefix, p));
                }
            }
            "error_log" => {
                if let Some(p) = d.args.first() {
                    if p != "stderr" {
                        error_log = Some(resolve_path(prefix, p));
                    }
                }
            }
            "events" | "worker_rlimit_nofile" | "worker_connections" | "use" | "accept_mutex"
            | "multi_accept" | "worker_aio_requests" => {}
            "http" => {
                if saw_http {
                    return Err(sem(&d.file, d.line, "\"http\" directive is duplicate"));
                }
                saw_http = true;
                http_roots = d.block.clone().unwrap_or_default();
            }
            "stream" | "mail" => {
                b.warn(&d, format!("module \"{}\" is not implemented yet; section ignored", d.name));
            }
            other => {
                b.warn(
                    &d,
                    format!("unknown directive \"{other}\" in main context; ignored"),
                );
            }
        }
    }

    let mut http = Http {
        servers: Vec::new(),
        groups: Vec::new(),
        mime: MimeMap::new(),
        default_type: "text/plain".to_string(),
        keepalive_timeout: DEFAULT_KEEPALIVE,
        keepalive_requests: 1000,
        sendfile: false,
        tcp_nopush: false,
        tcp_nodelay: true,
        gzip: false,
        server_tokens: true,
        client_max_body_size: DEFAULT_CLIENT_MAX_BODY,
        default_loc: LocCfg::new(prefix.to_path_buf()),
        upstreams: Vec::new(),
        default_access_logs: vec![AccessLog {
            path: prefix.join("logs/access.log"),
            format: "combined".to_string(),
        }],
        log_formats: HashMap::new(),
    };

    // ---- http-level: globals first, then servers -------------------------
    let mut server_dirs: Vec<Directive> = Vec::new();
    let mut http_access_log_set = false;
    let mut upstream_index: HashMap<String, usize> = HashMap::new();

    for d in &http_roots {
        match d.name.as_str() {
            "server" => server_dirs.push(d.clone()),
            "types" => {
                if let Some(block) = &d.block {
                    for t in block {
                        for ext in &t.args {
                            http.mime.insert(&t.name, ext);
                        }
                    }
                }
            }
            "default_type" => {
                if let Some(v) = d.args.first() {
                    http.default_type = v.clone();
                }
            }
            "sendfile" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.sendfile = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid sendfile value"))?;
            }
            "tcp_nopush" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.tcp_nopush = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid tcp_nopush value"))?;
            }
            "tcp_nodelay" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.tcp_nodelay = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid tcp_nodelay value"))?;
            }
            "keepalive_timeout" => {
                if let Some(v) = d.args.first() {
                    http.keepalive_timeout =
                        parse_time(v).ok_or_else(|| sem(&d.file, d.line, "invalid keepalive_timeout"))?;
                }
            }
            "keepalive_requests" => {
                if let Some(v) = d.args.first() {
                    http.keepalive_requests = v
                        .parse()
                        .map_err(|_| sem(&d.file, d.line, "invalid keepalive_requests"))?;
                }
            }
            "gzip" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.gzip = parse_on_off(&v)
                    .ok_or_else(|| sem(&d.file, d.line, "invalid gzip value"))?;
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "gzip_min_length" | "gzip_comp_level" | "gzip_types" | "gzip_vary" => {
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "server_tokens" => {
                let v = d.args.first().cloned().unwrap_or_default();
                http.server_tokens = match v.as_str() {
                    "on" | "build" => true,
                    "off" => false,
                    _ => return Err(sem(&d.file, d.line, "invalid server_tokens")),
                };
            }
            "client_max_body_size" => {
                if let Some(v) = d.args.first() {
                    http.client_max_body_size = if v == "0" {
                        u64::MAX
                    } else {
                        parse_size(v).ok_or_else(|| sem(&d.file, d.line, "invalid size"))?
                    };
                }
            }
            "log_format" => {
                if d.args.len() >= 2 {
                    http.log_formats
                        .insert(d.args[0].clone(), d.args[1..].join(" "));
                }
            }
            "access_log" => {
                if !http_access_log_set {
                    http.default_access_logs.clear();
                    http_access_log_set = true;
                }
                if d.args.first().map(|s| s.as_str()) == Some("off") {
                    http.default_access_logs.clear();
                } else if let Some(path) = d.args.first() {
                    let fmt = match d.args.get(1).map(|s| s.as_str()).unwrap_or("combined") {
                        "combined" => "combined".to_string(),
                        name => http
                            .log_formats
                            .get(name)
                            .cloned()
                            .unwrap_or_else(|| "combined".to_string()),
                    };
                    http.default_access_logs.push(AccessLog {
                        path: resolve_path(prefix, path),
                        format: fmt,
                    });
                }
            }
            "root" | "index" | "autoindex" | "add_header" | "error_page" | "expires" => {
                b.apply_loc(d, &mut http.default_loc)?;
            }
            "upstream" => {
                let mut up = parse_upstream(d)?;
                if http.upstreams.iter().any(|u| u.name == up.name) {
                    return Err(sem(&d.file, d.line, format!("duplicate upstream \"{}\"", up.name)));
                }
                // preserve declaration order for stable round-robin indices
                up.name = up.name.clone();
                upstream_index.insert(up.name.clone(), http.upstreams.len());
                http.upstreams.push(up);
            }
            "location" | "if" | "map" | "resolver" | "geo" | "split_clients"
            | "limit_req_zone" | "limit_conn_zone" | "proxy_cache_path" | "charset"
            | "log_format_escape" | "types_hash_max_size" | "server_names_hash_bucket_size"
            | "open_file_cache" | "access_log_off" | "default_type_off" => {
                if d.name == "map" || d.name == "limit_req_zone"
                    || d.name == "proxy_cache_path" || d.name == "geo" || d.name == "split_clients"
                {
                    b.warn(d, format!("directive \"{}\" is not implemented yet; ignored", d.name));
                }
            }
            _ => {
                if !b.apply_loc(d, &mut http.default_loc)? {
                    b.unknown(d, "http");
                }
            }
        }
    }

    let mut groups: BTreeMap<u16, ListenGroup> = BTreeMap::new();
    let mut listens_by_server: Vec<(usize, Vec<(SocketAddr, bool)>)> = Vec::new();

    for (i, sd) in server_dirs.iter().enumerate() {
        let (server, listens) = b.parse_server(
            sd,
            i,
            &http.default_loc,
            &http.log_formats,
            http.keepalive_timeout,
            http.server_tokens,
        )?;
        if server.names.is_empty() {
            // nginx default server_name is ""
        }
        listens_by_server.push((i, listens.clone()));
        http.servers.push(server);
    }

    {
        let defaults = http.default_access_logs.clone();
        for s in &mut http.servers {
            if !s.access_log_off && s.access_logs.is_empty() {
                s.access_logs = defaults.clone();
            }
        }
    }

    resolve_proxy_upstreams(&mut http)?;

    for (idx, listens) in listens_by_server {
        for (addr, is_default) in listens {
            let group = groups.entry(addr.port()).or_insert_with(|| ListenGroup {
                addr,
                servers: Vec::new(),
                default_server: 0,
                ssl: false,
            });
            if addr.ip().is_unspecified() {
                group.addr = addr;
            }
            if !group.servers.contains(&idx) {
                group.servers.push(idx);
            }
            if is_default {
                group.default_server = idx;
            }
            if http.servers[idx].ssl {
                group.ssl = true;
            }
        }
    }

    for (_port, mut g) in groups {
        if !g.servers.contains(&g.default_server) {
            // keep nginx's "first server on this address" default
            g.default_server = g.servers[0];
        }
        http.groups.push(g);
    }

    if http.groups.is_empty() {
        return Err(sem(&conf_path, 0, "no server listen sockets configured"));
    }

    Ok(Config {
        prefix: prefix.to_path_buf(),
        conf_path,
        worker_processes,
        daemon,
        pid,
        error_log,
        http,
        warnings: b.warnings,
    })
}

impl Server {
    pub fn locate(&self, path: &str) -> &LocCfg {
        match match_list(&self.locations, path) {
            Some(c) => c,
            None => &self.default_loc,
        }
    }
}

fn match_list<'a>(list: &'a [Location], path: &str) -> Option<&'a LocCfg> {
    let mut best: Option<&'a Location> = None;
    for l in list {
        match &l.matcher {
            Match::Exact(s) if s == path => return Some(&l.cfg),
            Match::Prefix(s) | Match::PrefixNoRegex(s) => {
                if path.starts_with(s.as_str())
                    && best.map_or(true, |b| prefix_of(&b.matcher).len() < s.len())
                {
                    best = Some(l);
                }
            }
            _ => {}
        }
    }

    if let Some(b) = best {
        if let Some(child) = match_list(&b.nested, path) {
            return Some(child);
        }
        if matches!(b.matcher, Match::PrefixNoRegex(_)) {
            return Some(&b.cfg);
        }
    }

    for l in list {
        if let Match::Regex { re, .. } = &l.matcher {
            if re.is_match(path) {
                if let Some(child) = match_list(&l.nested, path) {
                    return Some(child);
                }
                return Some(&l.cfg);
            }
        }
    }

    best.map(|b| &b.cfg)
}

fn prefix_of(m: &Match) -> &str {
    match m {
        Match::Exact(s) | Match::Prefix(s) | Match::PrefixNoRegex(s) => s,
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times() {
        assert_eq!(parse_size("10k"), Some(10240));
        assert_eq!(parse_size("1m"), Some(1048576));
        assert_eq!(parse_time("65s").unwrap().as_secs(), 65);
        assert_eq!(parse_time("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_time("100").unwrap().as_millis(), 100_000);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(parse_listen("8080"), Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080))));
        assert_eq!(
            parse_listen("127.0.0.1:8081"),
            Some(SocketAddr::from(([127, 0, 0, 1], 8081)))
        );
        assert_eq!(parse_listen("*:8082"), Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8082))));
        assert_eq!(
            parse_listen("[::]:8083"),
            Some(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 8083)))
        );
    }

    fn build_from(src: &str) -> Config {
        let tree = super::super::parser::parse_str(Path::new("t.conf"), src).unwrap();
        build(tree, Path::new("/prefix"), PathBuf::from("t.conf")).unwrap()
    }

    #[test]
    fn location_matching_order() {
        let cfg = build_from(
            r#"
            events {}
            http {
              server {
                listen 8080;
                location / { return 200 "root"; }
                location /api/ { return 200 "api"; }
                location = /exact { return 200 "exact"; }
                location ~ \.php$ { return 200 "php"; }
                location ^~ /static/ { return 200 "static"; }
                location ~ ^/static/x { return 200 "regex-static"; }
              }
            }
        "#,
        );
        let s = &cfg.http.servers[0];
        assert_eq!(s.locate("/api/x").ret.as_ref().unwrap().1, "api");
        assert_eq!(s.locate("/exact").ret.as_ref().unwrap().1, "exact");
        assert_eq!(s.locate("/a.php").ret.as_ref().unwrap().1, "php");
        assert_eq!(s.locate("/static/x").ret.as_ref().unwrap().1, "static");
        assert_eq!(s.locate("/other").ret.as_ref().unwrap().1, "root");
    }
}
