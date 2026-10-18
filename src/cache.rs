//! `proxy_cache`: an on-disk cache with nginx's observable semantics.
//!
//! Layout mirrors nginx's: one file per key under the `proxy_cache_path`
//! directory (with `levels=` subdirectories), a small text header recording the
//! status, validity and stored headers, then the body. Entries are keyed by
//! `proxy_cache_key` (default `$scheme$proxy_host$request_uri`) and expire per
//! `proxy_cache_valid`.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{CacheZone, LocCfg};

pub const CACHE_STATUS_KEY: &str = "X-Cache-Status";

/// A stored response.
pub struct Cached {
    pub status: u16,
    /// Header lines as `Name: value`.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stored_at: i64,
    pub valid_for: u64,
}

impl Cached {
    /// `c->valid_sec + c->updating_sec >= now` — may a stale copy be served?
    ///
    /// `updating_sec` comes from `Cache-Control: stale-while-revalidate`, which
    /// is derived from the stored headers so it never drifts out of sync with
    /// the on-disk format.
    pub fn may_serve_stale(&self, now: i64) -> bool {
        let swr = stale_while_revalidate(&self.headers) as i64;
        swr > 0 && self.stored_at + self.valid_for as i64 + swr >= now
    }

    pub fn is_fresh(&self, now: i64) -> bool {
        // `valid_for == 0` means "stored but already stale" (an `@N`
        // X-Accel-Expires in the past), which nginx reports as EXPIRED.
        now - self.stored_at < self.valid_for as i64
    }
}

fn key_hash(key: &str) -> u64 {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    h.finish()
}

/// nginx's `levels=1:2` layout: split the hex digest into suffix directories.
fn entry_path(zone: &CacheZone, key: &str) -> PathBuf {
    let hex = format!("{:016x}", key_hash(key));
    let mut path = zone.path.clone();
    if let Some(levels) = &zone.levels {
        let mut rest = hex.as_str();
        let mut dirs: Vec<&str> = Vec::new();
        for part in levels.split(':') {
            let n: usize = part.trim().parse().unwrap_or(0);
            if n == 0 || rest.len() < n {
                break;
            }
            let (head, tail) = rest.split_at(rest.len() - n);
            let _ = head;
            dirs.push(tail);
            rest = &rest[..rest.len() - n];
        }
        for d in dirs {
            path.push(d);
        }
    }
    path.join(hex)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Default key, matching nginx: `$scheme$proxy_host$request_uri`.
pub fn default_key(scheme: &str, proxy_host: &str, request_uri: &str) -> String {
    format!("{scheme}{proxy_host}{request_uri}")
}

/// Expand `proxy_cache_key`. Supports the variables nginx documents for it.
pub fn expand_key(
    spec: &str,
    scheme: &str,
    proxy_host: &str,
    host: &str,
    request_uri: &str,
    uri: &str,
    args: &str,
    remote_addr: &str,
    method: &str,
) -> String {
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
        let v = match name {
            "scheme" => scheme,
            "proxy_host" => proxy_host,
            "host" => host,
            "request_uri" => request_uri,
            "uri" => uri,
            "args" => args,
            "remote_addr" => remote_addr,
            "request_method" => method,
            "is_args" => {
                if args.is_empty() {
                    ""
                } else {
                    "?"
                }
            }
            _ => "",
        };
        out.push_str(v);
        i += 1 + n;
    }
    out
}

/// How long an entry stays valid, from `proxy_cache_valid`.
pub fn validity(loc: &LocCfg, status: u16) -> Option<Duration> {
    for (codes, dur) in &loc.proxy_cache_valid {
        if codes.iter().any(|c| *c == status) {
            return Some(*dur);
        }
    }
    None
}

/// `Cache-Control: stale-while-revalidate=N` (nginx's `updating_sec`).
pub fn stale_while_revalidate(headers: &[(String, String)]) -> u64 {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
        .flat_map(|(_, v)| v.split(','))
        .find_map(|part| {
            let part = part.trim();
            let n = part
                .strip_prefix("stale-while-revalidate=")
                .or_else(|| part.strip_prefix("Stale-While-Revalidate="))?;
            n.trim().parse::<u64>().ok()
        })
        .unwrap_or(0)
}

/// `proxy_ignore_headers` bit set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ignore {
    pub cache_control: bool,
    pub expires: bool,
    pub x_accel_expires: bool,
    pub set_cookie: bool,
    /// `proxy_ignore_headers Vary`: cache one representation regardless of the
    /// request headers named by the response.
    pub vary: bool,
}

/// How long a response may be cached.
///
/// Verified against nginx 1.28: the precedence is strictly
/// `X-Accel-Expires` > `Cache-Control` > `Expires`, independent of the order
/// the headers appear in. `Set-Cookie` blocks caching outright.
///
/// Returns `None` when the response must not be cached. A `Some(Duration::ZERO)`
/// means "cache it, but it is already stale" (`@1` style `X-Accel-Expires`).
pub fn ttl(loc: &LocCfg, status: u16, headers: &[(String, String)], ignore: Ignore) -> Option<Duration> {
    // All occurrences of one header, trimmed, in order.
    let all = |name: &str| -> Vec<String> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
            .collect()
    };

    // Set-Cookie wins over everything.
    if !ignore.set_cookie && !all("set-cookie").is_empty() {
        return None;
    }

    // ---- 1. X-Accel-Expires ----
    if !ignore.x_accel_expires {
        // The first occurrence is the one nginx honours.
        if let Some(v) = all("x-accel-expires").first() {
            if let Some(rest) = v.strip_prefix('@') {
                // Absolute unix time; a past value is stored but already stale.
                let at: i64 = match rest.parse() {
                    Ok(n) => n,
                    Err(_) => return None,
                };
                let now = now() as i64;
                return Some(if at > now {
                    Duration::from_secs((at - now) as u64)
                } else {
                    Duration::ZERO
                });
            }
            let secs: i64 = match v.parse() {
                Ok(n) => n,
                Err(_) => return None,
            };
            if secs <= 0 {
                return None;
            }
            return Some(Duration::from_secs(secs as u64));
        }
    }

    // ---- 2. Cache-Control ----
    if !ignore.cache_control {
        let values = all("cache-control");
        if !values.is_empty() {
            let joined = values.join(",");
            let lower = joined.to_ascii_lowercase();
            for part in lower.split(',') {
                let part = part.trim();
                if part == "no-cache" || part == "no-store" || part == "private" {
                    return None;
                }
            }
            let mut best: Option<u64> = None;
            for part in lower.split(',') {
                let part = part.trim();
                let v = part
                    .strip_prefix("s-maxage=")
                    .or_else(|| part.strip_prefix("max-age="));
                if let Some(v) = v {
                    if let Ok(n) = v.trim().parse::<u64>() {
                        best = Some(best.map_or(n, |b: u64| b.max(n)));
                    }
                }
            }
            if let Some(n) = best {
                return Some(Duration::from_secs(n));
            }
            // Other Cache-Control values do not determine cacheability.
        }
    }

    // ---- 3. Expires ----
    if !ignore.expires {
        if let Some(v) = all("expires").first() {
            match crate::util::parse_http_date(v) {
                Some(at) => {
                    let now = now() as i64;
                    return Some(if at > now {
                        Duration::from_secs((at - now) as u64)
                    } else {
                        Duration::ZERO
                    });
                }
                None => return None,
            }
        }
    }

    // ---- 4. proxy_cache_valid ----
    validity(loc, status)
}

pub fn load(zone: &CacheZone, key: &str) -> Option<Cached> {
    let path = entry_path(zone, key);
    let data = fs::read(&path).ok()?;
    parse(&data)
}

fn parse(data: &[u8]) -> Option<Cached> {
    // Format: "NGXRS-CACHE 1\n" then headers, then "\n", then body.
    let magic = b"NGXRS-CACHE 1\n";
    if !data.starts_with(magic) {
        return None;
    }
    let rest = &data[magic.len()..];
    let sep = memchr::memmem::find(rest, b"\n\n")?;
    let head = &rest[..sep];
    let body = rest[sep + 2..].to_vec();

    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status: u16 = lines.next()?.parse().ok()?;
    let meta = lines.next()?;
    let mut it = meta.split(' ');
    let stored_at: i64 = it.next()?.parse().ok()?;
    let valid_for: u64 = it.next().unwrap_or("0").parse().unwrap_or(0);

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(": ") {
            headers.push((k.to_string(), v.to_string()));
        }
    }
    Some(Cached {
        status,
        headers,
        body,
        stored_at,
        valid_for,
    })
}

pub fn store(zone: &CacheZone, key: &str, entry: &Cached) -> io::Result<()> {
    let path = entry_path(zone, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out = Vec::with_capacity(entry.body.len() + 512);
    out.extend_from_slice(b"NGXRS-CACHE 1\n");
    out.extend_from_slice(entry.status.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(
        format!("{} {}", entry.stored_at, entry.valid_for).as_bytes(),
    );
    out.push(b'\n');
    for (k, v) in &entry.headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(&entry.body);

    // Atomic replace so concurrent readers never see a partial file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, &path)?;
    enforce_max_size(zone);
    Ok(())
}

/// Evict oldest files when the zone exceeds `max_size` (nginx's cache manager).
fn enforce_max_size(zone: &CacheZone) {
    let mut files: Vec<(i64, u64, PathBuf)> = Vec::new();
    let mut total: u64 = 0;
    collect(&zone.path, &mut files, &mut total, 0);
    if total <= zone.max_size {
        return;
    }
    files.sort_by_key(|(mtime, _, _)| *mtime);
    for (_, size, path) in files {
        if total <= zone.max_size {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn collect(dir: &Path, out: &mut Vec<(i64, u64, PathBuf)>, total: &mut u64, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_dir() {
            collect(&e.path(), out, total, depth + 1);
            continue;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        *total += meta.len();
        out.push((mtime, meta.len(), e.path()));
    }
}

pub fn now() -> i64 {
    now_secs()
}


// ---------------------------------------------------------------------------
// `Vary` support
//
// nginx stores one representation per `Vary` combination and looks a request up
// by comparing the stored request-header values with the incoming ones. We keep
// a sidecar index at `<base>|vary` listing `sig` lines, where each line reads
// `header=value|header=value` using the Vary names of the stored response.
// ---------------------------------------------------------------------------

/// Build the variant signature for a request given the response's `Vary` names.
pub fn vary_signature(
    var_names: &[String],
    get: impl Fn(&str) -> String,
) -> String {
    var_names
        .iter()
        .map(|n| format!("{}={}", n.to_ascii_lowercase(), get(n)))
        .collect::<Vec<_>>()
        .join("|")
}

/// `Vary` header names of a response, lower-cased, `*` excluded.
pub fn vary_names(headers: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("vary") {
            continue;
        }
        for part in v.split(',') {
            let n = part.trim();
            if n.is_empty() || n == "*" {
                continue;
            }
            let n = n.to_ascii_lowercase();
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    names
}

fn vary_index_path(zone: &CacheZone, base: &str) -> PathBuf {
    entry_path(zone, &format!("{base}\u{1}vary"))
}

fn variant_key(base: &str, sig: &str) -> String {
    format!("{base}\u{1}{:016x}", key_hash(sig))
}

/// Store a variant plus its index line. Any previous entry for the same
/// signature is replaced (nginx keeps at most one entry per variant).
pub fn store_variant(zone: &CacheZone, base: &str, sig: &str, entry: &Cached) -> io::Result<()> {
    store(zone, &variant_key(base, sig), entry)?;
    let path = vary_index_path(zone, base);
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let mut lines: Vec<String> = fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty() && !l.ends_with(&format!("\t{sig}")))
        .map(|l| l.to_string())
        .collect();
    lines.push(sig.to_string());
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, lines.join("\n"))?;
    fs::rename(&tmp, &path)
}

/// Drop every stored variant for `base` (a response without `Vary` replaces
/// all previously cached representations, as in `proxy_cache_vary.t`).
pub fn clear_variants(zone: &CacheZone, base: &str) {
    let path = vary_index_path(zone, base);
    if let Ok(text) = fs::read_to_string(&path) {
        for sig in text.lines().filter(|l| !l.is_empty()) {
            let _ = fs::remove_file(entry_path(zone, &variant_key(base, sig)));
        }
    }
    let _ = fs::remove_file(&path);
}

/// Find the stored variant matching the current request.
pub fn load_variant(
    zone: &CacheZone,
    base: &str,
    get: impl Fn(&str) -> String,
) -> Option<Cached> {
    let text = fs::read_to_string(vary_index_path(zone, base)).ok()?;
    for sig in text.lines().filter(|l| !l.is_empty()) {
        let matches = sig.split('|').all(|pair| match pair.split_once('=') {
            Some((name, want)) => get(name) == want,
            None => false,
        });
        if matches {
            if let Some(e) = load(zone, &variant_key(base, sig)) {
                return Some(e);
            }
        }
    }
    None
}
