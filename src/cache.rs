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
    pub fn is_fresh(&self, now: i64) -> bool {
        self.valid_for == 0 || now - self.stored_at < self.valid_for as i64
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
    // nginx: only codes listed in proxy_cache_valid are cached.
    None
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
