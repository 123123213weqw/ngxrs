//! Static file handler: index, autoindex, ETag/Last-Modified, Range, sendfile.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::config::{Http, LocCfg};
use crate::http::request::Request;
use crate::http::{error_body, Body, Response};
use crate::util::{http_date, parse_http_date, push_http_date};

pub fn respond(
    req: &Request,
    uri: &str,
    _query: &str,
    loc: &LocCfg,
    http: &Http,
) -> io::Result<Response> {
    let fs_path = map_path(uri, loc);
    respond_fs(req, &fs_path, uri, loc, http)
}

pub fn map_path(uri: &str, loc: &LocCfg) -> PathBuf {
    match &loc.alias {
        Some(alias) => {
            let cut = loc.prefix_len.min(uri.len());
            let suffix = uri[cut..].trim_start_matches('/');
            alias.join(suffix)
        }
        None => loc.root.join(uri.trim_start_matches('/')),
    }
}

pub fn respond_fs(
    req: &Request,
    fs_path: &Path,
    uri: &str,
    loc: &LocCfg,
    http: &Http,
) -> io::Result<Response> {
    // Open first, then fstat: one syscall less than statx+open, and no TOCTOU
    // window (nginx does the same).
    let file = match File::open(fs_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Response::empty(403)),
        Err(_) => return Ok(Response::empty(404)),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Response::empty(403)),
        Err(_) => return Ok(Response::empty(404)),
    };

    if meta.is_dir() {
        if !uri.ends_with('/') {
            let mut location = format!("{uri}/");
            if !req.raw_target.contains('?') {
                // no query to preserve
            }
            if let Some(q) = req.raw_target.split_once('?').map(|(_, q)| q) {
                location.push('?');
                location.push_str(q);
            }
            return Ok(Response::empty(301)
                .header("Location", location)
                .header("Content-Length", "0"));
        }

        for index in &loc.index {
            if index.starts_with('/') {
                continue;
            }
            let candidate = fs_path.join(index);
            let idx_file = match File::open(&candidate) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let meta = match idx_file.metadata() {
                Ok(m) if m.is_file() => m,
                Ok(_) => continue,
                Err(_) => continue,
            };
            return serve_entry(
                req,
                idx_file,
                index,
                meta.len(),
                meta_mtime(&meta),
                loc,
                http,
            );
        }

        if loc.autoindex {
            return autoindex(fs_path, uri, loc, http);
        }
        return Ok(Response::empty(403));
    }

    if uri.ends_with('/') {
        return Ok(Response::empty(404));
    }

    let name = fs_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    serve_entry(req, file, &name, meta.len(), meta_mtime(&meta), loc, http)
}

fn meta_mtime(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn serve_entry(
    req: &Request,
    file: File,
    name_for_mime: &str,
    size: u64,
    mtime: i64,
    loc: &LocCfg,
    http: &Http,
) -> io::Result<Response> {
    let etag = format!("\"{:x}-{:x}\"", mtime, size);
    let last_modified = http_date(mtime);

    // ---- preconditions ------------------------------------------------
    if let Some(inm) = req.headers.get("if-none-match") {
        if etag_list_matches(inm, &etag) {
            return Ok(Response::empty(304)
                .header("ETag", etag)
                .header("Last-Modified", last_modified));
        }
    } else if let Some(ims) = req.headers.get("if-modified-since") {
        if let Some(t) = parse_http_date(ims) {
            if mtime <= t {
                return Ok(Response::empty(304)
                    .header("ETag", etag)
                    .header("Last-Modified", last_modified));
            }
        }
    }
    if let Some(im) = req.headers.get("if-match") {
        if !etag_list_matches(im, &etag) {
            if im.trim() != "*" {
                return Ok(Response::empty(412).header("Content-Length", "0"));
            }
        }
    }
    if let Some(ius) = req.headers.get("if-unmodified-since") {
        if let Some(t) = parse_http_date(ius) {
            if mtime > t {
                return Ok(Response::empty(412).header("Content-Length", "0"));
            }
        }
    }

    let mime = http
        .mime
        .get(extension(name_for_mime).as_str())
        .unwrap_or(http.default_type.as_str());

    // ---- range --------------------------------------------------------
    let mut status = 200u16;
    let mut offset = 0u64;
    let mut len = size;
    let mut content_range: Option<(u64, u64)> = None;

    if let Some(range) = req.headers.get("range") {
        let if_range_ok = match req.headers.get("if-range") {
            None => true,
            Some(v) => {
                if v.trim().starts_with('"') || v.trim().starts_with("W/") {
                    v.trim() == etag
                } else {
                    parse_http_date(v).map(|t| mtime <= t).unwrap_or(false)
                }
            }
        };
        if if_range_ok {
            match parse_range(range, size) {
                RangeSpec::Single(start, end) => {
                    status = 206;
                    offset = start;
                    len = end - start + 1;
                    content_range = Some((start, end));
                }
                RangeSpec::Unsatisfiable => {
                    let body = error_body(416, http.server_tokens);
                    let mut raw = Vec::with_capacity(160);
                    raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
                    raw.extend_from_slice(body.len().to_string().as_bytes());
                    raw.extend_from_slice(b"\r\nContent-Range: bytes */");
                    raw.extend_from_slice(size.to_string().as_bytes());
                    raw.extend_from_slice(b"\r\n");
                    return Ok(Response::raw(416, raw, Body::Bytes(body)));
                }
                RangeSpec::Ignore => {}
            }
        }
    }

    // Pre-render every header line into one buffer: no per-header Strings.
    let mut raw = Vec::with_capacity(256);
    raw.extend_from_slice(b"Content-Type: ");
    raw.extend_from_slice(mime.as_bytes());
    raw.extend_from_slice(b"\r\nContent-Length: ");
    raw.extend_from_slice(len.to_string().as_bytes());
    raw.extend_from_slice(b"\r\nLast-Modified: ");
    push_http_date(&mut raw, mtime);
    raw.extend_from_slice(b"\r\nETag: ");
    raw.extend_from_slice(etag.as_bytes());
    raw.extend_from_slice(b"\r\n");
    if status == 200 {
        raw.extend_from_slice(b"Accept-Ranges: bytes\r\n");
    }
    if let Some((start, end)) = content_range {
        raw.extend_from_slice(b"Content-Range: bytes ");
        raw.extend_from_slice(start.to_string().as_bytes());
        raw.push(b'-');
        raw.extend_from_slice(end.to_string().as_bytes());
        raw.push(b'/');
        raw.extend_from_slice(size.to_string().as_bytes());
        raw.extend_from_slice(b"\r\n");
    }

    Ok(Response {
        status,
        headers: Vec::new(),
        raw,
        no_error_page: false,
            explicit_len: true,
        body: Body::File { file, offset, len },
    })
}

fn extension(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i + 1 < name.len() => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn etag_list_matches(header: &str, etag: &str) -> bool {
    for part in header.split(',') {
        let p = part.trim();
        if p == "*" {
            return true;
        }
        let p = p.strip_prefix("W/").unwrap_or(p);
        let e = etag.strip_prefix("W/").unwrap_or(etag);
        if p == e {
            return true;
        }
    }
    false
}

pub enum RangeSpec {
    Single(u64, u64),
    Unsatisfiable,
    Ignore,
}

pub fn parse_range(header: &str, size: u64) -> RangeSpec {
    let spec = match header.trim().strip_prefix("bytes=") {
        Some(s) => s,
        None => return RangeSpec::Ignore,
    };
    if spec.contains(',') {
        // multipart/byteranges not implemented yet
        return RangeSpec::Ignore;
    }
    let (a, b) = match spec.split_once('-') {
        Some(v) => v,
        None => return RangeSpec::Ignore,
    };

    if a.is_empty() {
        // suffix range: bytes=-N
        let n: u64 = match b.trim().parse() {
            Ok(v) => v,
            Err(_) => return RangeSpec::Ignore,
        };
        if n == 0 || size == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let n = n.min(size);
        return RangeSpec::Single(size - n, size - 1);
    }

    let start: u64 = match a.trim().parse() {
        Ok(v) => v,
        Err(_) => return RangeSpec::Ignore,
    };
    if start >= size {
        return RangeSpec::Unsatisfiable;
    }
    let end: u64 = if b.trim().is_empty() {
        size - 1
    } else {
        match b.trim().parse::<u64>() {
            Ok(v) => v.min(size - 1),
            Err(_) => return RangeSpec::Ignore,
        }
    };
    if end < start {
        return RangeSpec::Unsatisfiable;
    }
    RangeSpec::Single(start, end)
}

fn autoindex(dir: &Path, uri: &str, loc: &LocCfg, http: &Http) -> io::Result<Response> {
    let mut entries: Vec<(String, bool, u64, i64)> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = match e {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = e.file_name().to_string_lossy().to_string();
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push((name, meta.is_dir(), meta.len(), meta_mtime(&meta)));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut html = String::with_capacity(1024 + entries.len() * 96);
    html.push_str("<html>\r\n<head><title>Index of ");
    html.push_str(&escape_html(uri));
    html.push_str("</title></head>\r\n<body>\r\n<h1>Index of ");
    html.push_str(&escape_html(uri));
    html.push_str("</h1><hr><pre><a href=\"../\">../</a>\r\n");
    for (name, is_dir, size, mtime) in entries {
        let mut href = url_encode(&name);
        let mut label = name.clone();
        if is_dir {
            href.push('/');
            label.push('/');
        }
        html.push_str("<a href=\"");
        html.push_str(&escape_html(&href));
        html.push_str("\">");
        html.push_str(&escape_html(&label));
        html.push_str("</a>");
        html.push_str(&" ".repeat(4));
        html.push_str(&http_date(mtime));
        if !is_dir {
            html.push_str(&format!(" {:>12}", size));
        }
        html.push_str("\r\n");
    }
    html.push_str("</pre><hr></body>\r\n</html>\r\n");

    let resp = Response::bytes(200, "text/html", html.into_bytes());
    let _ = http;
    Ok(resp)
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        match parse_range("bytes=0-99", 1000) {
            RangeSpec::Single(s, e) => assert_eq!((s, e), (0, 99)),
            _ => panic!(),
        }
        match parse_range("bytes=-100", 1000) {
            RangeSpec::Single(s, e) => assert_eq!((s, e), (900, 999)),
            _ => panic!(),
        }
        match parse_range("bytes=500-", 1000) {
            RangeSpec::Single(s, e) => assert_eq!((s, e), (500, 999)),
            _ => panic!(),
        }
        assert!(matches!(parse_range("bytes=1000-", 1000), RangeSpec::Unsatisfiable));
        assert!(matches!(parse_range("bytes=0-1,3-4", 1000), RangeSpec::Ignore));
    }

    #[test]
    fn etags() {
        assert!(etag_list_matches("\"a-1\", \"b-2\"", "\"b-2\""));
        assert!(etag_list_matches("W/\"a-1\"", "\"a-1\""));
        assert!(!etag_list_matches("\"a-1\"", "\"b-2\""));
    }
}
