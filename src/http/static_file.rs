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
    let fs_path = map_path_flagged(
        uri,
        loc,
        req.add_uri_to_alias.load(std::sync::atomic::Ordering::Relaxed),
    );
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

/// The directory `$document_root` names for this request: the configured
/// `root`, or the `alias` itself -- both *without* the URI remainder.
///
/// nginx sets `r->doc_root` inside `ngx_http_map_uri_to_path`, so for a regex
/// location with `alias /srv/$1` it is the *expanded* alias. That is why
/// `disable_symlinks on from=$document_root` stops checking exactly where the
/// alias ends (`http_disable_symlinks.t`, `"from=" exact match`).
pub fn document_root_of(loc: &LocCfg) -> PathBuf {
    match &loc.alias {
        Some(alias) => alias.clone(),
        None => loc.root.clone(),
    }
}

pub fn map_path(uri: &str, loc: &LocCfg) -> PathBuf {
    map_path_flagged(uri, loc, false)
}

/// `add_uri_to_alias` mirrors nginx's request flag: a regex location's
/// `alias` is the whole path for a direct serve, but the try_files module
/// sets the flag so its candidates get the URI appended
/// (ngx_http_try_files_module.c:261).
pub fn map_path_flagged(uri: &str, loc: &LocCfg, add_uri_to_alias: bool) -> PathBuf {
    match &loc.alias {
        Some(alias) => {
            // The offset belongs to the location that declared `alias`; a
            // nested location inherits both. A regex location's `alias` is the
            // whole path unless the caller asked for the URI on top.
            let cut = loc.alias_prefix_len.min(uri.len());
            let suffix = if loc.alias_prefix_len == 0 && !add_uri_to_alias {
                ""
            } else {
                uri[cut..].trim_start_matches('/')
            };
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

/// `log_not_found`: nginx writes the failed `open()` to the error log at
/// `error` level, unless the location turned it off.
///
/// The message is nginx's own shape -- `open() "..." failed (2: No such file or
/// directory), client: ..., server: ..., request: "..."` -- because
/// `index.t` greps the log for `error`.
fn log_missing_file(loc: &LocCfg, http: &Http, req: &Request, path: &Path) {
    if !loc.log_not_found {
        return;
    }
    let msg = format!(
        "open() \"{}\" failed (2: No such file or directory), client: {}, server: {}, request: \"{} {}\"",
        path.display(),
        "-",
        loc.server_name,
        req.method.as_str(),
        req.raw_target
    );
    if loc.error_logs.is_empty() {
        crate::log::error_log("error", &msg);
    } else {
        for spec in &loc.error_logs {
            if let Some(sink) = crate::log::sink_cached(&spec.dest, spec.level) {
                crate::log::log_to(&[sink], crate::log::Level::Error, &msg);
            }
        }
    }
    let _ = http;
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
    // `autoindex_format jsonp` needs `?callback=`, which only the raw target
    // carries.
    let query = req
        .raw_target
        .split_once('?')
        .map(|(_, q)| q.to_string())
        .unwrap_or_default();
    let query = query.as_str();
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

    // `disable_symlinks` refuses before the open: nginx's walk with `O_NOFOLLOW`
    // fails with ELOOP, which the static handler reports as 403.
    if symlinks_disallowed(fs_path, loc, &document_root_of(loc)) {
        return Ok(Response::empty(403));
    }

    // Open first, then fstat: one syscall less than statx+open, and no TOCTOU
    // window (nginx does the same).
    let file = match File::open(fs_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Response::empty(403)),
        Err(_) => {
            log_missing_file(loc, http, req, fs_path);
            return Ok(Response::empty(404));
        }
    };
    let mut meta = match file.metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Response::empty(403)),
        Err(_) => return Ok(Response::empty(404)),
    };

    // ---- gzip_static (ngx_http_gzip_static_module) -----------------------
    //
    // A sibling `<path>.gz` is sent instead of the file when the client accepts
    // gzip. The Content-Type still comes from the *original* name, and the
    // entity really is the compressed one, so length/ETag/Range all describe
    // the `.gz`. nginx only does this for a regular file that exists.
    let mut file = file;
    let mut gzip_static = false;
    if loc.gzip_static && !meta.is_dir() && crate::gzip::accepts_gzip(req) {
        let mut gz = fs_path.as_os_str().to_os_string();
        gz.push(".gz");
        let gz = std::path::PathBuf::from(gz);
        if let Ok(f) = File::open(&gz) {
            if let Ok(m) = f.metadata() {
                if m.is_file() {
                    file = f;
                    meta = m;
                    gzip_static = true;
                }
            }
        }
    }

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
            return autoindex(fs_path, uri, query, loc, http);
        }
        return Ok(Response::empty(403));
    }

    if uri.ends_with('/') {
        log_missing_file(loc, http, req, fs_path);
        return Ok(Response::empty(404));
    }

    let name = fs_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut resp = serve_entry(req, file, &name, meta.len(), meta_mtime(&meta), loc, http)?;
    if gzip_static {
        // Mark the entity as compressed. The charset filter's rule for a
        // response that would need recoding is to leave it alone entirely
        // (`charset_gzip_static.t`, "recode gzip").
        resp.raw
            .extend_from_slice(b"Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
    }
    Ok(resp)
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

    // `max_ranges 0` disables byte ranges entirely. Any other value caps how many
    // *satisfiable* spans a request may ask for, which is a property of the parse
    // and not of the raw header: counting commas made
    // `bytes=0-9, -10, 10000-` look like three ranges when only two survive, so
    // `max_ranges 2` wrongly dropped the header (`range.t`, "max_ranges not
    // reached bad range").
    let max_ranges = loc.max_ranges.unwrap_or(u32::MAX) as usize;
    let range_header = req
        .headers
        .get("range")
        .filter(|_| loc.max_ranges != Some(0));
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
            // One parser for both shapes: nginx walks the spec once and decides
            // afterwards whether the result is a plain 206 or a multipart body.
            match parse_ranges(range, size, max_ranges) {
                MultiRange::Ranges(spans) if spans.len() == 1 => {
                    let (start, end) = spans[0];
                    status = 206;
                    offset = start;
                    len = end - start + 1;
                    content_range = Some((start, end));
                }
                MultiRange::Ranges(spans) => {
                    let boundary = format!("{:016X}", multipart_seed(req, size));
                    status = 206;
                    multipart = Some(read_multipart(&file, &boundary, mime, size, &spans)?);
                }
                MultiRange::Unsatisfiable => {
                    let body = error_body(416, http.server_tokens);
                    let mut raw = Vec::with_capacity(160);
                    raw.extend_from_slice(b"Content-Type: text/html\r\nContent-Length: ");
                    crate::util::push_u64(&mut raw, body.len() as u64);
                    raw.extend_from_slice(b"\r\nContent-Range: bytes */");
                    crate::util::push_u64(&mut raw, size);
                    raw.extend_from_slice(b"\r\n");
                    return Ok(Response::raw(416, raw, Body::Bytes(body)));
                }
                MultiRange::Ignore => {}
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
        server_tokens: None,
        cache_status: None,

        headers_finalized: false,
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
    // The single-span view of the same parser, for callers that cannot build a
    // multipart body.
    match parse_ranges(header, size, usize::MAX) {
        MultiRange::Ranges(mut v) if v.len() == 1 => {
            let (a, b) = v.remove(0);
            RangeSpec::Single(a, b)
        }
        MultiRange::Ranges(_) => RangeSpec::Ignore,
        MultiRange::Unsatisfiable => RangeSpec::Unsatisfiable,
        MultiRange::Ignore => RangeSpec::Ignore,
    }
}

/// `ngx_http_range_parse`, transcribed.
///
/// Three behaviours here are not the obvious ones, and all three are asserted by
/// `range.t`:
///
///   * a malformed spec is **416**, not "ignore" -- `bytes=alpha`,
///     `bytes=10-alpha`, `bytes=10` and `bytes=10-11 12-` must all be refused;
///   * a span that starts past the end is **skipped**, not refused, so
///     `bytes=0-9, -10, 100000-, 10-19` is a three-part 206. Only when nothing
///     remains is the answer 416;
///   * a span that ends before it starts *and* starts at zero makes nginx drop
///     the whole header (`NGX_DECLINED`), and a set of spans whose total exceeds
///     the entity does the same -- both answer 200 with the full body.
pub fn parse_ranges(header: &str, size: u64, max_ranges: usize) -> MultiRange {

    let h = header.trim();
    if h.len() < 6 || !h[..6].eq_ignore_ascii_case("bytes=") {
        return MultiRange::Ignore;
    }
    let b = h.as_bytes();
    let mut p = 6usize;
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let mut total: u64 = 0;

    loop {
        let mut start: u64 = 0;
        let mut end: u64 = 0;
        let mut suffix = false;
        // `found` is the jump target: the span is already final.
        let mut final_span = false;

        while p < b.len() && b[p] == b' ' {
            p += 1;
        }
        if p < b.len() && b[p] != b'-' {
            if !b[p].is_ascii_digit() {
                return MultiRange::Unsatisfiable;
            }
            while p < b.len() && b[p].is_ascii_digit() {
                start = match start
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((b[p] - b'0') as u64))
                {
                    Some(v) => v,
                    None => return MultiRange::Unsatisfiable,
                };
                p += 1;
            }
            while p < b.len() && b[p] == b' ' {
                p += 1;
            }
            if p >= b.len() || b[p] != b'-' {
                return MultiRange::Unsatisfiable;
            }
            p += 1;
            while p < b.len() && b[p] == b' ' {
                p += 1;
            }
            if p >= b.len() || b[p] == b',' {
                // `bytes=N-`: the end is the entity's end.
                end = size;
                final_span = true;
            }
        } else if p < b.len() {
            suffix = true;
            p += 1;
        } else {
            return MultiRange::Unsatisfiable;
        }

        if !final_span {
            if p >= b.len() || !b[p].is_ascii_digit() {
                return MultiRange::Unsatisfiable;
            }
            while p < b.len() && b[p].is_ascii_digit() {
                end = match end
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((b[p] - b'0') as u64))
                {
                    Some(v) => v,
                    None => return MultiRange::Unsatisfiable,
                };
                p += 1;
            }
            while p < b.len() && b[p] == b' ' {
                p += 1;
            }
            if p < b.len() && b[p] != b',' {
                return MultiRange::Unsatisfiable;
            }
            if suffix {
                start = if end < size { size - end } else { 0 };
                end = size;
            } else {
                // Exclusive end, clamped to the entity.
                end = if end >= size { size } else { end + 1 };
            }
        }

        if start < end {
            spans.push((start, end - 1));
            total = match total.checked_add(end - start) {
                Some(v) => v,
                None => return MultiRange::Unsatisfiable,
            };
            // nginx's `if (ranges-- == 0) return NGX_DECLINED;` fires *after*
            // the span is pushed, so exactly `max_ranges` spans still answer 206.
            if spans.len() > max_ranges {
                return MultiRange::Ignore;
            }
        } else if start == 0 {
            // `NGX_DECLINED`: nginx serves the whole body.
            return MultiRange::Ignore;
        }

        if p >= b.len() || b[p] != b',' {
            break;
        }
        p += 1;
    }

    if spans.is_empty() {
        return MultiRange::Unsatisfiable;
    }
    if total > size {
        return MultiRange::Ignore;
    }
    MultiRange::Ranges(spans)
}

/// nginx's `NGX_HTTP_AUTOINDEX_NAME_LEN`. A name wider than this is truncated
/// to `NAME_LEN - 3` columns and suffixed with `..>`.
const AUTOINDEX_NAME_LEN: usize = 50;

fn autoindex(
    dir: &Path,
    uri: &str,
    query: &str,
    loc: &LocCfg,
    http: &Http,
) -> io::Result<Response> {
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

    // `autoindex_format` picks the body; the entry list (and its ordering) is
    // shared, which is why nginx builds `entries` first and formats after.
    match loc.autoindex_format {
        crate::config::AutoindexFormat::Json | crate::config::AutoindexFormat::Jsonp => {
            return Ok(autoindex_json(&entries, loc, query));
        }
        crate::config::AutoindexFormat::Xml => return Ok(autoindex_xml(&entries)),
        crate::config::AutoindexFormat::Html => {}
    }

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

/// `ngx_escape_json`: `\` and `"` are backslash-escaped, control characters
/// become `\n`/`\r`/`\t`/`\b`/`\f` or `\u00XX`. Bytes above 0x1f pass
/// through untouched, so a UTF-8 name comes back byte-identical -- which is why
/// this writes bytes rather than chars.
fn escape_json(name: &str, out: &mut Vec<u8>) {
    for b in name.bytes() {
        if b > 0x1f {
            if b == b'\\' || b == b'"' {
                out.push(b'\\');
            }
            out.push(b);
            continue;
        }
        out.push(b'\\');
        match b {
            b'\n' => out.push(b'n'),
            b'\r' => out.push(b'r'),
            b'\t' => out.push(b't'),
            0x08 => out.push(b'b'),
            0x0c => out.push(b'f'),
            _ => out.extend_from_slice(format!("u00{:02X}", b).as_bytes()),
        }
    }
}

/// `ngx_http_autoindex_json`: the same object shape for `json` and `jsonp`,
/// with an optional callback wrapper.
///
/// The field order and the surrounding whitespace are nginx's, byte for byte,
/// because the body is compared directly: `[\r\n{ "name":"x", ... },\r\n]`.
fn autoindex_json(entries: &[(String, bool, u64, i64)], loc: &LocCfg, query: &str) -> Response {
    let mut out: Vec<u8> = Vec::with_capacity(64 + entries.len() * 128);
    let callback = if matches!(
        loc.autoindex_format,
        crate::config::AutoindexFormat::Jsonp
    ) {
        // `ngx_http_autoindex_jsonp_callback`: the `callback` argument, but only
        // if it is a plain identifier (`[A-Za-z0-9_.]`, at most 128 bytes).
        // Anything else makes nginx log and emit bare JSON.
        callback_arg(query)
    } else {
        None
    };
    if let Some(cb) = &callback {
        out.extend_from_slice(b"/* callback */\r\n");
        out.extend_from_slice(cb.as_bytes());
        out.push(b'(');
    }
    out.push(b'[');
    for (name, is_dir, size, mtime) in entries {
        out.extend_from_slice(b"\r\n{ \"name\":\"");
        escape_json(name, &mut out);
        out.extend_from_slice(b"\", \"type\":\"");
        out.extend_from_slice(if *is_dir { &b"directory"[..] } else { &b"file"[..] });
        out.extend_from_slice(b"\", \"mtime\":\"");
        out.extend_from_slice(http_time(*mtime).as_bytes());
        if *is_dir {
            out.push(b'"');
        } else {
            out.extend_from_slice(b"\", \"size\":");
            out.extend_from_slice(size.to_string().as_bytes());
        }
        out.extend_from_slice(b" },");
    }
    if !entries.is_empty() {
        out.pop();
    }
    out.extend_from_slice(b"\r\n]");
    if callback.is_some() {
        out.extend_from_slice(b");");
    }
    Response::bytes(200, "application/json", out)
}

/// `ngx_http_autoindex_xml`, byte for byte.
fn autoindex_xml(entries: &[(String, bool, u64, i64)]) -> Response {
    let mut out = String::with_capacity(64 + entries.len() * 96);
    out.push_str("<?xml version=\"1.0\"?>\r\n<list>\r\n");
    for (name, is_dir, size, mtime) in entries {
        let ty = if *is_dir { "directory" } else { "file" };
        out.push('<');
        out.push_str(ty);
        out.push_str(" mtime=\"");
        out.push_str(&iso_time(*mtime));
        if !*is_dir {
            out.push_str("\" size=\"");
            out.push_str(&size.to_string());
        }
        out.push_str("\">");
        out.push_str(&escape_html(name));
        out.push_str("</");
        out.push_str(ty);
        out.push_str(">\r\n");
    }
    out.push_str("</list>\r\n");
    Response::bytes(200, "text/xml; charset=utf-8", out.into_bytes())
}

/// The `callback` query argument when it is a valid JSONP identifier.
fn callback_arg(query: &str) -> Option<String> {
    let value = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "callback")
        .map(|(_, v)| v)?;
    if value.len() > 128 {
        return None;
    }
    if value.is_empty() {
        // `?callback=` means "no wrapper", which is bare JSON.
        return None;
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        Some(value.to_string())
    } else {
        None
    }
}

/// `ngx_http_time`: `Wed, 31 Dec 1986 10:00:00 GMT`.
fn http_time(ts: i64) -> String {
    crate::util::http_date(ts)
}

/// The XML timestamp form: `1986-12-31T10:00:00Z` (`ngx_http_autoindex_xml`
/// calls `ngx_gmtime` and prints the fields).
fn iso_time(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, mo, d) = crate::util::civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
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

    /// The three behaviours `range.t` pins down, transcribed from
    /// `ngx_http_range_parse`.
    #[test]
    fn range_syntax_errors_are_416_not_ignored() {
        for h in [
            "bytes=alpha",
            "bytes=10-alpha",
            "bytes=10",
            "bytes=10-11 12-",
            "bytes=-",
            "bytes=",
            // Wrong unit is still "not ours" and must stay ignored.
        ] {
            assert!(
                matches!(parse_range(h, 1000), RangeSpec::Unsatisfiable),
                "{h} should be refused"
            );
        }
        for h in ["none", "items=0-1", "BYTES=0-9"] {
            // `BYTES=` is valid (the comparison is case-insensitive).
            let expect_ok = h == "BYTES=0-9";
            let got = parse_range(h, 1000);
            assert_eq!(
                matches!(got, RangeSpec::Single(0, 9)),
                expect_ok,
                "{h} -> wrong verdict"
            );
        }
    }

    #[test]
    fn unsatisfiable_spans_are_skipped_when_others_remain() {
        // `bytes=100000-` alone: nothing left -> 416.
        assert!(matches!(
            parse_range("bytes=100000-", 1000),
            RangeSpec::Unsatisfiable
        ));
        // The skipped span may also be the *last* one.
        match parse_ranges("bytes=0-9, -10, 10000-", 1000, 10) {
            MultiRange::Ranges(v) => assert_eq!(v, vec![(0, 9), (990, 999)]),
            other => panic!("expected two spans, got {}", match other {
                MultiRange::Ignore => "ignore",
                MultiRange::Unsatisfiable => "unsatisfiable",
                _ => "?",
            }),
        }
        // Mixed in with satisfiable spans: it is dropped, the rest answer 206.
        match parse_ranges("bytes=0-9, -10, 100000-, 10-19", 1000, 10) {
            MultiRange::Ranges(v) => {
                assert_eq!(v, vec![(0, 9), (990, 999), (10, 19)]);
            }
            _ => panic!("expected three spans"),
        }
    }

    #[test]
    fn max_ranges_counts_satisfiable_spans_only() {
        // `max_ranges 2`: two surviving spans are fine even though the header
        // named three, because the third starts past the end (`range.t`).
        assert!(matches!(
            parse_ranges("bytes=0-9, -10, 10000-", 1000, 2),
            MultiRange::Ranges(_)
        ));
        // Three real spans with `max_ranges 2` -> the header is dropped.
        assert!(matches!(
            parse_ranges("bytes=0-9, -10, 10-19", 1000, 2),
            MultiRange::Ignore
        ));
    }

    #[test]
    fn oversized_and_zero_start_spans_drop_the_header() {
        // Total longer than the entity -> full 200.
        assert!(matches!(
            parse_ranges("bytes=0-10001, 0-0", 1000, 10),
            MultiRange::Ignore
        ));
        // A zero-start span that ends before it starts -> full 200.
        assert!(matches!(parse_ranges("bytes=0-0", 0, 10), MultiRange::Ignore));
        // Last-byte-pos past the end is clamped, still a 206.
        match parse_ranges("bytes=0-10001", 1000, 10) {
            MultiRange::Ranges(v) => assert_eq!(v, vec![(0, 999)]),
            _ => panic!("expected one span"),
        }
    }

    #[test]
    fn etags() {
        assert!(etag_list_matches("\"a-1\", \"b-2\"", "\"b-2\""));
        assert!(etag_list_matches("W/\"a-1\"", "\"a-1\""));
        assert!(!etag_list_matches("\"a-1\"", "\"b-2\""));
    }
}

// ---- disable_symlinks -----------------------------------------------------

/// `disable_symlinks on|if_not_owner [from=part]`.
///
/// nginx opens the path one component at a time from the `from` prefix (or from
/// `/`) with `O_NOFOLLOW`, so a single symlink anywhere in the checked suffix is
/// ELOOP -- which the static handler reports as 403. `if_not_owner` allows a
/// symlink whose target has the same owner as the link itself
/// (`ngx_openat_file_owner`).
pub fn symlinks_disallowed(path: &Path, loc: &LocCfg, document_root: &Path) -> bool {
    if loc.disable_symlinks == crate::config::Symlinks::Off {
        return false;
    }
    let full = path.to_string_lossy();
    let start = match &loc.disable_symlinks_from {
        None => 1,
        Some(from) => {
            let from = if from == "$document_root" {
                document_root.to_string_lossy().to_string()
            } else {
                from.clone()
            };
            let from = from.trim_end_matches('/');
            if from.is_empty() || !full.starts_with(from) {
                // nginx leaves `disable_symlinks` at its configured value but
                // with no `from`, which means the whole path is checked.
                1
            } else if from.len() == full.len() {
                // `from` is the file itself: checks are off entirely.
                return false;
            } else if full.as_bytes().get(from.len()) == Some(&b'/') {
                from.len() + 1
            } else if full.as_bytes().get(from.len().wrapping_sub(1)) == Some(&b'/') {
                from.len()
            } else {
                1
            }
        }
    };
    let bytes = full.as_bytes();
    let mut i = start;
    while i <= bytes.len() {
        let end = bytes[i..]
            .iter()
            .position(|b| *b == b'/')
            .map(|p| i + p)
            .unwrap_or(bytes.len());
        let component = &full[i.min(full.len())..end];
        if !component.is_empty() && component != "." && component != ".." {
            let mut cur = PathBuf::from(&full[..end]);
            // `symlink_metadata` is lstat: this asks about the component itself,
            // not what it points at.
            if let Ok(link) = std::fs::symlink_metadata(&cur) {
                if link.file_type().is_symlink() {
                    match loc.disable_symlinks {
                        crate::config::Symlinks::On => return true,
                        crate::config::Symlinks::IfNotOwner => {
                            use std::os::unix::fs::MetadataExt;
                            match std::fs::metadata(&cur) {
                                Ok(target) if target.uid() == link.uid() => {}
                                // Same owner (or the target vanished) allows it.
                                _ => return true,
                            }
                        }
                        crate::config::Symlinks::Off => {}
                    }
                }
            }
            cur.clear();
        }
        if end >= bytes.len() {
            break;
        }
        i = end + 1;
    }
    false
}

/// `ngx_http_index_handler`'s redirect decision: for a directory URI whose
/// `index` list names an existing file, the response is an **internal redirect**
/// to that file's URI, not an in-place serve.
///
/// That distinction is the whole point of `index.t`: `$uri` has to change, so
/// `/` with the default `index.html` reports `/index.html` in `add_header X-URI`,
/// and `index /re.html` (an absolute name) redirects to a *different* location
/// entirely. A redirect whose target is the URI it came from is a cycle, and
/// nginx answers 500 after its internal-redirect limit -- `/loop/` with
/// `index /loop/`.
///
/// `None` means "no index matched", so the caller falls through to the
/// directory handling (autoindex, or 403).
pub fn index_redirect(uri: &str, loc: &LocCfg, expanded: Option<&[String]>) -> Option<String> {
    if loc.index.is_empty() {
        return None;
    }
    // The index handler runs only for a URI with a trailing slash. A directory
    // URI *without* one is the static handler's 301 first -- `ngx_http_static_handler`
    // redirects before the index module is ever reached, so `/sub` must stay a
    // 301 rather than becoming `/sub/index.html`.
    if !uri.ends_with('/') {
        return None;
    }
    let fs_path = map_path(uri, loc);
    let base = uri.to_string();
    for (i, spec) in loc.index.iter().enumerate() {
        let name = match expanded {
            Some(list) => list.get(i).cloned().unwrap_or_else(|| spec.clone()),
            None => spec.clone(),
        };
        if name.is_empty() {
            continue;
        }
        // An absolute index names a URI, not a file inside this directory.
        if name.starts_with('/') {
            return Some(name);
        }
        if std::fs::metadata(fs_path.join(&name))
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return Some(format!("{base}{name}"));
        }
    }
    None
}
