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
    respond_indexed(req, uri, loc, http, None)
}

/// `respond` with the location's `index` names already expanded. `index` is a
/// complex value in nginx, so `index index${{variant}}.html` picks a file from a
/// `split_clients` result; the caller that has the variables expands them.
pub fn respond_indexed(
    req: &Request,
    uri: &str,
    loc: &LocCfg,
    http: &Http,
    expanded_index: Option<&[String]>,
) -> io::Result<Response> {
    // `empty_gif` and `stub_status` are content handlers that take precedence
    // over the static handler: nginx registers one content handler per
    // location, and the location's own wins over the default file handler.
    if let Some(r) = small_content(req, loc) {
        return Ok(r);
    }
    let fs_path = map_path(uri, loc);
    respond_fs_indexed(req, &fs_path, uri, loc, http, expanded_index)
}

/// Content handlers that produce a response without touching the file system.
fn small_content(req: &Request, loc: &LocCfg) -> Option<Response> {
    if loc.empty_gif {
        // `ngx_http_empty_gif_handler` refuses anything but GET/HEAD with 405.
        if !matches!(req.method.as_str(), "GET" | "HEAD") {
            return Some(Response::empty(405).header("Allow", "GET, HEAD"));
        }
        return Some(Response::bytes(
            200,
            "image/gif",
            super::small::EMPTY_GIF.to_vec(),
        ));
    }
    if loc.stub_status {
        if !matches!(req.method.as_str(), "GET" | "HEAD") {
            return Some(Response::empty(405).header("Allow", "GET, HEAD"));
        }
        return Some(Response::bytes(
            200,
            "text/plain",
            crate::stats::stub_status_body().into_bytes(),
        ));
    }
    None
}

pub fn map_path(uri: &str, loc: &LocCfg) -> PathBuf {
    match &loc.alias {
        Some(alias) => {
            // The offset belongs to the location that declared `alias`; a
            // nested location inherits both.
            let cut = loc.alias_prefix_len.min(uri.len());
            let suffix = uri[cut..].trim_start_matches('/');
            // An exact-match location leaves no remainder; `alias` then *is*
            // the file. `Path::join("")` would append a separator and turn
            // `/tmp/t2.html` into `/tmp/t2.html/`, which never stats.
            if suffix.is_empty() {
                alias.clone()
            } else {
                alias.join(suffix)
            }
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
    respond_fs_indexed(req, fs_path, uri, loc, http, None)
}

pub fn respond_fs_indexed(
    req: &Request,
    fs_path: &Path,
    uri: &str,
    loc: &LocCfg,
    http: &Http,
    expanded_index: Option<&[String]>,
) -> io::Result<Response> {
    // nginx splits the method check in two. Anything outside GET/HEAD/POST is
    // rejected *before* the path is resolved, so TRACE or DELETE to a missing
    // file is 405 rather than 404. POST is only rejected once the target is
    // known to exist, so POST to a missing file is 404.
    if !matches!(
        req.method,
        crate::http::Method::Get | crate::http::Method::Head | crate::http::Method::Post
    ) {
        return Ok(Response::empty(405));
    }

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

    // POST is only known to be disallowed now that the target exists; a
    // directory answers 403 (no index, autoindex off) before that check.
    if !req.method.is_read() {
        if meta.is_dir() {
            return Ok(Response::empty(403));
        }
        return Ok(Response::empty(405));
    }

    if meta.is_dir() {
        if !uri.ends_with('/') {
            // nginx escapes the URI when building the redirect target.
            let mut location = format!("{}/", crate::util::escape_uri(uri.trim_end_matches('/')));
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

        // `random_index` picks one directory entry at random instead of trying
        // the configured names in order (`ngx_http_random_index_handler`).
        // A directory with no eligible file still answers 403, like nginx.
        if loc.random_index {
            if let Some(name) = crate::http::small::random_index_pick(fs_path) {
                if let Ok(idx_file) = File::open(fs_path.join(&name)) {
                    if let Ok(meta) = idx_file.metadata() {
                        if meta.is_file() {
                            return serve_entry(
                                req,
                                idx_file,
                                &name,
                                meta.len(),
                                meta_mtime(&meta),
                                loc,
                                http,
                            );
                        }
                    }
                }
            }
            return Ok(Response::empty(403));
        }

        for (i, index_spec) in loc.index.iter().enumerate() {
            // `index` is a complex value: `index index${variant}.html` is the
            // documented way to pick a file from a `split_clients`/`map`
            // result, so the name is expanded per request.
            let index_owned = match expanded_index {
                Some(list) => list.get(i).cloned().unwrap_or_else(|| index_spec.clone()),
                None => index_spec.clone(),
            };
            let index: &str = &index_owned;
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
    // Built into fixed storage: this is on the hot path for every static
    // response, and `format!` + `http_date` cost two allocations per request.
    let mut eb = [0u8; 40];
    let mut n = 0usize;
    eb[n] = b'"';
    n += 1;
    n += crate::util::write_hex_u64(&mut eb[n..], mtime as u64);
    eb[n] = b'-';
    n += 1;
    n += crate::util::write_hex_u64(&mut eb[n..], size);
    eb[n] = b'"';
    n += 1;
    let etag = std::str::from_utf8(&eb[..n]).unwrap_or("\"\"");

    // ---- preconditions ------------------------------------------------
    if let Some(inm) = req.headers.get("if-none-match") {
        if etag_list_matches(inm, etag) {
            return Ok(Response::empty(304)
                .header("ETag", etag)
                .header("Last-Modified", http_date(mtime)));
        }
    } else if let Some(ims) = req.headers.get("if-modified-since") {
        if let Some(t) = parse_http_date(ims) {
            if mtime <= t {
                return Ok(Response::empty(304)
                    .header("ETag", etag)
                    .header("Last-Modified", http_date(mtime)));
            }
        }
    }
    if let Some(im) = req.headers.get("if-match") {
        if !etag_list_matches(im, etag) {
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

    // Extension lookup without allocating: probed as-is first (nginx's mime
    // table is lowercase and so are most filenames), falling back to a
    // lowercased copy in stack storage.
    let ext = extension(name_for_mime);
    let mime = {
        let mut lb = [0u8; 32];
        if ext.bytes().any(|b| b.is_ascii_uppercase()) {
            if ext.len() <= lb.len() {
                for (i, b) in ext.bytes().enumerate() {
                    lb[i] = b.to_ascii_lowercase();
                }
                let key = std::str::from_utf8(&lb[..ext.len()]).unwrap_or(ext);
                http.mime.get(key).unwrap_or(http.default_type.as_str())
            } else {
                // Too long for stack storage: keep the old allocating path so
                // case-insensitivity is preserved for unusual names.
                http.mime
                    .get(&ext.to_ascii_lowercase())
                    .unwrap_or(http.default_type.as_str())
            }
        } else {
            http.mime.get(ext).unwrap_or(http.default_type.as_str())
        }
    };

    // ---- range --------------------------------------------------------
    let mut status = 200u16;
    let mut offset = 0u64;
    let mut len = size;
    let mut content_range: Option<(u64, u64)> = None;
    // Set when the request asked for more than one span: the reply becomes
    // `multipart/byteranges`, which cannot be expressed as a file slice.
    let mut multipart: Option<Vec<u8>> = None;

    // `max_ranges 0` disables byte ranges entirely; any other value caps how
    // many spans a request may ask for (nginx ignores the header beyond it).
    let range_header = req.headers.get("range").filter(|r| match loc.max_ranges {
        Some(0) => false,
        Some(max) => (r.matches(',').count() as u32 + 1) <= max,
        None => true,
    });
    if let Some(range) = range_header {
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
            // `bytes=0-2,4-` produces one part per span (nginx builds a
            // multipart body); a single span stays a plain 206.
            if range.contains(',') {
                match parse_multi_range(range, size) {
                    MultiRange::Ranges(spans) if spans.len() > 1 => {
                        let boundary = format!("{:016X}", multipart_seed(req, size));
                        status = 206;
                        multipart = Some(read_multipart(&file, &boundary, mime, size, &spans)?);
                    }
                    MultiRange::Unsatisfiable => {
                        status = 416;
                        len = 0;
                        content_range = Some((u64::MAX, size));
                    }
                    _ => {}
                }
            } else {
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
                        crate::util::push_u64(&mut raw, body.len() as u64);
                        raw.extend_from_slice(b"\r\nContent-Range: bytes */");
                        crate::util::push_u64(&mut raw, size);
                        raw.extend_from_slice(b"\r\n");
                        return Ok(Response::raw(416, raw, Body::Bytes(body)));
                    }
                    RangeSpec::Ignore => {}
                }
            }
        }
    }

    // Pre-render every header line into one buffer: no per-header Strings.
    let mut raw = Vec::with_capacity(256);
    raw.extend_from_slice(b"Content-Type: ");
    match &multipart {
        Some(body) => {
            raw.extend_from_slice(b"multipart/byteranges; boundary=");
            raw.extend_from_slice(format!("{:016X}", multipart_seed(req, size)).as_bytes());
            len = body.len() as u64;
        }
        None => raw.extend_from_slice(mime.as_bytes()),
    }
    raw.extend_from_slice(b"\r\nContent-Length: ");
    crate::util::push_u64(&mut raw, len);
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
        crate::util::push_u64(&mut raw, start);
        raw.push(b'-');
        crate::util::push_u64(&mut raw, end);
        raw.push(b'/');
        crate::util::push_u64(&mut raw, size);
        raw.extend_from_slice(b"\r\n");
    }

    Ok(Response {
        status,
        headers: Vec::new(),
        raw,
        no_error_page: false,
        explicit_len: true,
        trailers: Vec::new(),
        expect_trailers: false,
        body: match multipart {
            Some(b) => Body::Bytes(b),
            None => Body::File { file, offset, len },
        },
    })
}

fn extension(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i + 1 < name.len() => &name[i + 1..],
        _ => "",
    }
}

pub(crate) fn etag_list_matches(header: &str, etag: &str) -> bool {
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

/// Result of parsing a `Range` header that may list several spans.
pub enum MultiRange {
    /// One or more inclusive `(start, end)` spans, in request order.
    Ranges(Vec<(u64, u64)>),
    Unsatisfiable,
    Ignore,
}

/// Parse every span of a `Range: bytes=...` header.
///
/// Overlapping or out-of-order spans are kept as requested (nginx does not
/// coalesce them).
pub fn parse_multi_range(header: &str, size: u64) -> MultiRange {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return MultiRange::Ignore;
    };
    let mut spans = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((a, b)) = part.split_once('-') else {
            return MultiRange::Ignore;
        };
        let (a, b) = (a.trim(), b.trim());
        if a.is_empty() {
            // suffix range: bytes=-N
            let Ok(n) = b.parse::<u64>() else {
                return MultiRange::Ignore;
            };
            if n == 0 || size == 0 {
                return MultiRange::Unsatisfiable;
            }
            let n = n.min(size);
            spans.push((size - n, size - 1));
            continue;
        }
        let Ok(start) = a.parse::<u64>() else {
            return MultiRange::Ignore;
        };
        if start >= size {
            return MultiRange::Unsatisfiable;
        }
        let end = if b.is_empty() {
            size - 1
        } else {
            let Ok(e) = b.parse::<u64>() else {
                return MultiRange::Ignore;
            };
            if e < start {
                return MultiRange::Ignore;
            }
            e.min(size - 1)
        };
        spans.push((start, end));
    }
    if spans.is_empty() {
        return MultiRange::Ignore;
    }
    MultiRange::Ranges(spans)
}

/// Boundary seed: nginx derives it from the request and the entity size.
fn multipart_seed(req: &Request, size: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.raw_target.hash(&mut h);
    size.hash(&mut h);
    h.finish()
}

/// Read every span from `file` and lay them out as `multipart/byteranges`.
///
/// The parts are framed here rather than through [`multipart_body`]: that
/// helper slices the *whole* entity by absolute offsets, so handing it a single
/// span's bytes would index past the end and silently drop the data.
fn read_multipart(
    file: &std::fs::File,
    boundary: &str,
    content_type: &str,
    size: u64,
    spans: &[(u64, u64)],
) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let total: u64 = spans.iter().map(|(a, b)| b - a + 1).sum();
    let mut buf = Vec::with_capacity(total as usize + spans.len() * 128);
    for (start, end) in spans {
        buf.extend_from_slice(b"\r\n--");
        buf.extend_from_slice(boundary.as_bytes());
        buf.extend_from_slice(b"\r\nContent-Type: ");
        buf.extend_from_slice(content_type.as_bytes());
        buf.extend_from_slice(b"\r\nContent-Range: bytes ");
        buf.extend_from_slice(start.to_string().as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(end.to_string().as_bytes());
        buf.push(b'/');
        buf.extend_from_slice(size.to_string().as_bytes());
        buf.extend_from_slice(b"\r\n\r\n");
        let mut part = vec![0u8; (end - start + 1) as usize];
        file.read_exact_at(&mut part, *start)?;
        buf.extend_from_slice(&part);
    }
    buf.extend_from_slice(b"\r\n--");
    buf.extend_from_slice(boundary.as_bytes());
    buf.extend_from_slice(b"--\r\n");
    Ok(buf)
}

/// Build a `multipart/byteranges` body exactly as nginx lays it out.
pub fn multipart_body(
    boundary: &str,
    content_type: &str,
    size: u64,
    spans: &[(u64, u64)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + spans.len() * 128);
    for (start, end) in spans {
        out.extend_from_slice(b"\r\n--");
        out.extend_from_slice(boundary.as_bytes());
        out.extend_from_slice(b"\r\nContent-Type: ");
        out.extend_from_slice(content_type.as_bytes());
        out.extend_from_slice(b"\r\nContent-Range: bytes ");
        out.extend_from_slice(start.to_string().as_bytes());
        out.push(b'-');
        out.extend_from_slice(end.to_string().as_bytes());
        out.push(b'/');
        out.extend_from_slice(size.to_string().as_bytes());
        out.extend_from_slice(b"\r\n\r\n");
        let lo = (*start as usize).min(body.len());
        let hi = (*end as usize + 1).min(body.len());
        out.extend_from_slice(&body[lo..hi]);
    }
    out.extend_from_slice(b"\r\n--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"--\r\n");
    out
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

/// nginx's `NGX_HTTP_AUTOINDEX_NAME_LEN`. A name wider than this is truncated
/// to `NAME_LEN - 3` columns and suffixed with `..>`.
const AUTOINDEX_NAME_LEN: usize = 50;

fn autoindex(dir: &Path, uri: &str, loc: &LocCfg, http: &Http) -> io::Result<Response> {
    let mut entries: Vec<(String, bool, u64, i64)> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = match e {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = e.file_name().to_string_lossy().to_string();
        // `DirEntry::metadata` does not follow symlinks (it is lstat), so a
        // symlink to a directory was rendered as a plain file with no trailing
        // slash. nginx reports the target's type.
        let meta = match std::fs::metadata(e.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push((name, meta.is_dir(), meta.len(), meta_mtime(&meta)));
    }
    // `ngx_http_autoindex_cmp_entries` puts every directory before every file,
    // then compares names -- not one flat name sort.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut html = String::with_capacity(1024 + entries.len() * 96);
    html.push_str("<html>\r\n<head><title>Index of ");
    html.push_str(&escape_html(uri));
    html.push_str("</title></head>\r\n<body>\r\n<h1>Index of ");
    html.push_str(&escape_html(uri));
    html.push_str("</h1><hr><pre><a href=\"../\">../</a>\r\n");
    for (name, is_dir, size, mtime) in entries {
        html.push_str("<a href=\"");
        html.push_str(&escape_href(&name));
        if is_dir {
            html.push('/');
        }
        html.push_str("\">");
        let (label, columns) = label_for(&name, is_dir, loc.charset_utf8);
        html.push_str(&label);
        html.push_str("</a>");
        // Pad the name column, then one space, then the date.
        for _ in columns..AUTOINDEX_NAME_LEN {
            html.push(' ');
        }
        html.push(' ');
        html.push_str(&autoindex_time(mtime));
        html.push(' ');
        if is_dir {
            html.push_str(&format!("{:>19}", "-"));
        } else {
            html.push_str(&format!("{size:>19}"));
        }
        html.push_str("\r\n");
    }
    html.push_str("</pre><hr></body>\r\n</html>\r\n");

    let resp = Response::bytes(200, "text/html", html.into_bytes());
    let _ = http;
    Ok(resp)
}

/// Render one directory entry's label, returning it together with the number of
/// columns it occupies.
///
/// nginx measures the width in characters when the charset is utf-8 and in bytes
/// otherwise (`entry->utf_len`), truncates anything longer than
/// `AUTOINDEX_NAME_LEN` to `NAME_LEN - 3` and appends `..>`, then HTML-escapes
/// the result — so the appended `>` becomes `&gt;` in the output.
fn label_for(name: &str, is_dir: bool, utf8: bool) -> (String, usize) {
    let width = if utf8 {
        name.chars().count()
    } else {
        name.len()
    };
    let mut out = String::with_capacity(name.len() + 8);
    if width > AUTOINDEX_NAME_LEN {
        let keep = AUTOINDEX_NAME_LEN - 3;
        if utf8 {
            out.extend(name.chars().take(keep));
        } else {
            // Keep whole UTF-8 sequences so the output stays valid even when the
            // width is counted in bytes.
            let mut used = 0usize;
            for ch in name.chars() {
                if used + ch.len_utf8() > keep {
                    break;
                }
                used += ch.len_utf8();
                out.push(ch);
            }
        }
        out.push_str("..>");
    } else {
        out.push_str(name);
    }
    if is_dir {
        out.push('/');
    }
    let escaped = escape_html(&out);
    // Column count is the pre-escaping width; truncation already fixed it at
    // NAME_LEN columns including the `..>` suffix.
    let columns = if width > AUTOINDEX_NAME_LEN {
        AUTOINDEX_NAME_LEN + usize::from(is_dir)
    } else {
        width + usize::from(is_dir)
    };
    (escaped, columns)
}

/// nginx's autoindex date column: `dd-Mon-yyyy hh:mm`.
fn autoindex_time(ts: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        // `autoindex_localtime` defaults to off, so nginx renders GMT.
        libc::gmtime_r(&t, &mut tm);
    }
    format!(
        "{:02}-{}-{} {:02}:{:02}",
        tm.tm_mday,
        MONTHS.get(tm.tm_mon as usize).copied().unwrap_or("Jan"),
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min
    )
}

/// `ngx_escape_html`: only `& < > "` are escaped (an apostrophe is not).
///
/// Verified against nginx 1.28 by driving every printable character through a
/// real autoindex listing (bench/aiesc.sh).
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// `ngx_escape_uri(..., NGX_ESCAPE_URI_COMPONENT)`: everything except the RFC
/// 3986 unreserved set plus `~` is percent-encoded, uppercase hex.
///
/// The exact set was read off a real nginx listing rather than assumed; note
/// that `:` **is** escaped, which is what keeps `test-colon:blah` from looking
/// like a URI scheme in the rendered `href`.
fn escape_href(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
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
        assert!(matches!(
            parse_range("bytes=1000-", 1000),
            RangeSpec::Unsatisfiable
        ));
        assert!(matches!(
            parse_range("bytes=0-1,3-4", 1000),
            RangeSpec::Ignore
        ));
    }

    #[test]
    fn etags() {
        assert!(etag_list_matches("\"a-1\", \"b-2\"", "\"b-2\""));
        assert!(etag_list_matches("W/\"a-1\"", "\"a-1\""));
        assert!(!etag_list_matches("\"a-1\"", "\"b-2\""));
    }
}
