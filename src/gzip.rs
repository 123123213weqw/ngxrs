//! `gzip` response filter: Accept-Encoding negotiation, Content-Length rewrite,
//! and a per-worker cache of compressed bodies keyed by (path, mtime, size).

use std::collections::HashMap;
use std::io::{Read, Write};

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::config::{Http, LocCfg};
use crate::http::request::Method;
use crate::http::request::Request;
use crate::http::{Body, Response};

/// Bodies above this size are streamed uncompressed (in-memory compression of
/// huge files would cost more than it saves).
const MAX_INLINE: u64 = 8 * 1024 * 1024;
const CACHE_ENTRIES: usize = 128;
const CACHE_BYTES: usize = 32 * 1024 * 1024;

thread_local! {
    static CACHE: std::cell::RefCell<Cache> = std::cell::RefCell::new(Cache::default());
}

#[derive(Default)]
struct Cache {
    map: HashMap<(String, i64, u64, u32), std::sync::Arc<Vec<u8>>>,
    total: usize,
}

fn cache_get(key: &(String, i64, u64, u32)) -> Option<std::sync::Arc<Vec<u8>>> {
    CACHE.with(|c| c.borrow().map.get(key).cloned())
}

fn cache_put(key: (String, i64, u64, u32), value: std::sync::Arc<Vec<u8>>) {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.map.len() >= CACHE_ENTRIES || c.total + value.len() > CACHE_BYTES {
            c.map.clear();
            c.total = 0;
        }
        c.total += value.len();
        c.map.insert(key, value);
    });
}

pub fn accepts_gzip(req: &Request) -> bool {
    let Some(ae) = req.headers.get("accept-encoding") else {
        return false;
    };
    for part in ae.split(',') {
        let mut bits = part.trim().split(';');
        let coding = bits.next().unwrap_or("").trim();
        if !coding.eq_ignore_ascii_case("gzip") && coding != "*" {
            continue;
        }
        let mut q = 1.0f32;
        for p in bits {
            if let Some(v) = p.trim().strip_prefix("q=") {
                q = v.parse().unwrap_or(1.0);
            }
        }
        if q > 0.0 {
            return true;
        }
    }
    false
}

fn compressible(ctype: &str, loc: &LocCfg) -> bool {
    let base = ctype
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if base == "text/html" {
        return true;
    }
    loc.gzip_types
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&base) || t == "*")
}

fn find_header(raw: &[u8], name: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + name.len() < raw.len() {
        if raw[i..].starts_with(name) && (i == 0 || raw[i - 1] == b'\n') {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn header_value<'a>(raw: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let start = find_header(raw, name)?;
    let rest = &raw[start + name.len()..];
    let end = memchr::memchr(b'\r', rest)?;
    Some(&rest[..end])
}

fn drop_header(raw: &mut Vec<u8>, name: &[u8]) {
    while let Some(pos) = find_header(raw, name) {
        let end = memchr::memchr(b'\n', &raw[pos..])
            .map(|e| pos + e + 1)
            .unwrap_or(raw.len());
        raw.drain(pos..end);
    }
}

/// Append `Vary: Accept-Encoding` unless the response already carries it.
fn add_vary(mut resp: Response) -> Response {
    let already = resp.raw.split(|&b| b == b'\n').any(|line| {
        line.len() > 5
            && line[..5].eq_ignore_ascii_case(b"vary:")
            && String::from_utf8_lossy(&line[5..])
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
    });
    if !already {
        resp.raw.extend_from_slice(b"Vary: Accept-Encoding\r\n");
    }
    resp
}

/// Body length when it is known up front, as `r->headers_out.content_length_n`
/// is for nginx. `None` stands for "unknown", which the eligibility test treats
/// as long enough.
fn known_len(resp: &Response) -> Option<u64> {
    match &resp.body {
        Body::Empty => Some(0),
        Body::Bytes(b) => Some(b.len() as u64),
        Body::File { len, .. } => Some(*len),
    }
}

pub fn maybe_compress(req: &Request, resp: Response, loc: &LocCfg, http: &Http) -> Response {
    // `ngx_http_gzip_header_filter` decides eligibility *before* it looks at
    // Accept-Encoding, and sets `r->gzip_vary` at that point. The distinction
    // matters: a response that is merely gzip-eligible still carries
    // `Vary: Accept-Encoding` when the client does not accept gzip, which is
    // what makes the cache key on the request header. Verified against nginx
    // 1.28: `Accept-Encoding: deflate` on a text/html file answers 200 with
    // `Vary: Accept-Encoding` and no Content-Encoding.
    let eligible = loc.gzip
        && matches!(resp.status, 200 | 403 | 404)
        && find_header(&resp.raw, b"Content-Encoding:").is_none()
        && known_len(&resp)
            .map(|n| n >= loc.gzip_min_length)
            .unwrap_or(true)
        && {
            let ctype = header_value(&resp.raw, b"Content-Type:")
                .map(|v| String::from_utf8_lossy(v).trim().to_string())
                .unwrap_or_else(|| http.default_type.clone());
            compressible(&ctype, loc)
        };

    if !eligible {
        return resp;
    }

    let resp = if loc.gzip_vary { add_vary(resp) } else { resp };

    if !accepts_gzip(req) || req.headers.get("range").is_some() {
        return resp;
    }

    let level = loc.gzip_comp_level.clamp(1, 9) as u32;
    let min_len = loc.gzip_min_length;

    let (mut raw, body) = (resp.raw, resp.body);
    // A HEAD answer carries the gzip headers but no body; nginx runs the header
    // filter and skips the body filter in that case.
    let head_only = req.method == Method::Head;
    let compressed: Option<Vec<u8>> = if head_only {
        Some(Vec::new())
    } else {
        match &body {
            Body::Bytes(b) => {
                if b.len() as u64 >= min_len {
                    Some(gz(b, level))
                } else {
                    None
                }
            }
            Body::File { file, offset, len } => {
                if *len >= min_len && *len <= MAX_INLINE {
                    let etag = header_value(&raw, b"ETag:")
                        .map(|v| String::from_utf8_lossy(v).trim().to_string())
                        .unwrap_or_default();
                    let last_modified = header_value(&raw, b"Last-Modified:")
                        .map(|v| String::from_utf8_lossy(v).trim().to_string())
                        .unwrap_or_default();
                    let key = (format!("{etag}|{last_modified}"), 0, *len, level);
                    if let Some(hit) = cache_get(&key) {
                        Some(hit.as_ref().clone())
                    } else {
                        use std::os::unix::fs::FileExt;
                        let mut buf = vec![0u8; *len as usize];
                        let mut read = 0usize;
                        while read < buf.len() {
                            match file.read_at(&mut buf[read..], offset + read as u64) {
                                Ok(0) => break,
                                Ok(n) => read += n,
                                Err(_) => break,
                            }
                        }
                        if read == 0 {
                            None
                        } else {
                            let out = std::sync::Arc::new(gz(&buf[..read], level));
                            cache_put(key, out.clone());
                            Some(out.as_ref().clone())
                        }
                    }
                } else {
                    None
                }
            }
            Body::Empty => None,
        }
    };

    let Some(payload) = compressed else {
        return Response {
            status: resp.status,
            headers: resp.headers,
            raw,
            explicit_len: resp.explicit_len,
            no_error_page: resp.no_error_page,
            trailers: resp.trailers,
            expect_trailers: resp.expect_trailers,
            headers_finalized: resp.headers_finalized,
            body,
        };
    };

    // nginx compresses on the fly, so the length is unknown when the head is
    // written and the reply is chunked. Verified against nginx 1.28: a gzipped
    // static file answers `Transfer-Encoding: chunked` with no Content-Length.
    drop_header(&mut raw, b"Content-Length:");
    drop_header(&mut raw, b"Accept-Ranges:");
    // The validator no longer describes the bytes being sent, so nginx weakens
    // it instead of dropping it: `ETag: W/"..."`.
    weaken_etag(&mut raw);
    raw.extend_from_slice(b"Content-Encoding: gzip\r\n");

    Response {
        status: resp.status,
        headers: resp.headers,
        raw,
        // `write_response` treats `explicit_len: false` as "measure the body",
        // so the chunked framing has to be requested the same way `add_trailer`
        // does it: `expect_trailers` switches the message to chunked framing
        // and, with no trailers queued, emits no trailer lines.
        explicit_len: false,
        no_error_page: resp.no_error_page,
        trailers: resp.trailers,
        expect_trailers: req.version_minor >= 1 || resp.expect_trailers,
        headers_finalized: resp.headers_finalized,
        body: Body::Bytes(payload),
    }
}

/// Rewrite `ETag: "x"` into `ETag: W/"x"` in place, leaving anything already
/// weak or absent alone.
fn weaken_etag(raw: &mut Vec<u8>) {
    let mut out = Vec::with_capacity(raw.len() + 2);
    let mut start = 0usize;
    let mut first = true;
    while start < raw.len() {
        let end = match memchr::memchr(b'\n', &raw[start..]) {
            Some(p) => start + p + 1,
            None => raw.len(),
        };
        let line = &raw[start..end];
        let is_etag = line.len() > 5
            && line[..5].eq_ignore_ascii_case(b"etag:")
            && !line[5..].trim_ascii_start().starts_with(b"W/");
        if is_etag && first {
            first = false;
            out.extend_from_slice(b"ETag: W/");
            let rest = &line[5..];
            let trimmed = rest.trim_ascii_start();
            out.extend_from_slice(trimmed);
        } else {
            out.extend_from_slice(line);
        }
        start = end;
    }
    *raw = out;
}

fn gz(data: &[u8], level: u32) -> Vec<u8> {
    let mut enc = GzEncoder::new(
        Vec::with_capacity(data.len() / 3 + 32),
        Compression::new(level),
    );
    if enc.write_all(data).is_err() {
        return Vec::new();
    }
    match enc.finish() {
        Ok(v) => v,
        Err(_) => Vec::new(),
    }
}

#[allow(dead_code)]
fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut d = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    Some(out)
}
