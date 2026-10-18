//! HTTP/1.x request head parser.

use crate::instr::InStr;
use crate::util::reason;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Trace,
    Connect,
    Other(InStr),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
            Method::Trace => "TRACE",
            Method::Connect => "CONNECT",
            Method::Other(s) => s.as_str(),
        }
    }

    pub fn is_read(&self) -> bool {
        matches!(self, Method::Get | Method::Head)
    }
}

#[derive(Debug, Default)]
pub struct Headers {
    items: Vec<(InStr, InStr)>,
}

// Header vectors are recycled per worker thread: a fresh 12-entry Vec per
// request is ~1.3 KB of allocator traffic at 600k rps.
thread_local! {
    static HDR_POOL: std::cell::RefCell<Vec<Vec<(InStr, InStr)>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn hdr_vec() -> Vec<(InStr, InStr)> {
    HDR_POOL
        .with(|p| p.borrow_mut().pop())
        .unwrap_or_else(|| Vec::with_capacity(12))
}

fn recycle(mut v: Vec<(InStr, InStr)>) {
    v.clear();
    if v.capacity() <= 64 {
        HDR_POOL.with(|p| {
            let mut p = p.borrow_mut();
            if p.len() < 32 {
                p.push(v);
            }
        });
    }
}

impl Headers {
    pub fn push(&mut self, name: InStr, value: InStr) {
        self.items.push((name, value));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// nginx joins repeated request headers into one value: `, ` for ordinary
    /// headers and `; ` for Cookie (`$http_*` semantics).
    pub fn get_joined(&self, name: &str) -> Option<String> {
        let sep = if name.eq_ignore_ascii_case("cookie") {
            "; "
        } else {
            ", "
        };
        let mut out = String::new();
        let mut found = false;
        for (_, v) in self.items.iter().filter(|(k, _)| k == name) {
            if found {
                out.push_str(sep);
            }
            out.push_str(v);
            found = true;
        }
        if found {
            Some(out)
        } else {
            None
        }
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.items
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.items.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpError {
    pub status: u16,
    pub close: bool,
}

impl HttpError {
    pub fn new(status: u16, close: bool) -> Self {
        HttpError { status, close }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status, reason(self.status))
    }
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub raw_target: String,
    pub version_minor: u8,
    pub headers: Headers,
    pub body_len: u64,
    pub chunked: bool,
    pub keepalive: bool,
    pub host: Option<InStr>,
    pub expect_continue: bool,
    /// TLS facts for the connection this request arrived on. Carried on the
    /// request (rather than threaded through every render helper) so `$scheme`
    /// and the `$ssl_*` family can be answered anywhere a `Request` is in scope.
    pub tls: Option<std::sync::Arc<crate::conn::TlsInfo>>,
    /// When the request head finished parsing. Backs `$request_time`.
    pub started: std::time::Instant,
}

impl Drop for Request {
    fn drop(&mut self) {
        recycle(std::mem::take(&mut self.headers.items));
    }
}

/// Is this `$host` value usable for building an absolute URL? nginx falls back
/// to the local socket address when it is not (e.g. a Host of `.`).
pub fn host_is_usable(host: &str) -> bool {
    if host.trim_matches('.').is_empty() {
        return false;
    }
    // A bare port (`:8080`) or anything with a slot separator is unusable.
    if host.starts_with(':') || host.contains('/') {
        return false;
    }
    !host.bytes().any(|b| b <= 0x20)
}

fn is_absolute_form(target: &str) -> bool {
    let lower = target.get(..8).unwrap_or("").to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Lowercase, strip the port, a stray colon and trailing dots — nginx's
/// `$host` value (`www.example.com.:80` becomes `www.example.com`).
pub fn normalize_host(host: &str) -> String {
    let no_port = strip_port(host);
    let trimmed = no_port.strip_suffix(':').unwrap_or(no_port);
    trimmed.trim_end_matches('.').to_ascii_lowercase()
}

/// Validate the host part shared by the Host header and absolute-form.
///
/// Follows `ngx_http_validate_host` (path separators and control characters
/// are rejected, consecutive dots are rejected, one trailing dot is dropped)
/// plus the request-line parser's IP-literal rules.
pub fn validate_host_name(host: &str) -> Result<(), ()> {
    if host.is_empty() {
        return Err(());
    }
    let bytes = host.as_bytes();

    // Reject path separators and control characters anywhere, including inside
    // an IP literal.
    for &c in bytes {
        if c == b'/' || c == b'\\' || c <= 0x20 || c == 0x7f {
            return Err(());
        }
    }

    let host = if host.starts_with('[') {
        let close = host.find(']').ok_or(())?;
        // Everything after `]` must be a port, i.e. `:` followed by digits.
        let after = &host[close + 1..];
        if !after.is_empty() {
            let port = after.strip_prefix(':').ok_or(())?;
            if !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
        }
        &host[..=close]
    } else {
        if host.contains('[') || host.contains(']') {
            return Err(());
        }
        host
    };

    // Two dots in a row are rejected *before* a trailing dot is dropped, so
    // `a.b..:` is invalid while `a.b.` is fine.
    if host.contains("..") {
        return Err(());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.contains("..") {
        return Err(());
    }
    Ok(())
}

/// Validate a `Host:` header value.
///
/// nginx truncates the value at the first `:` and does not check the port, so
/// `example.com:notaport` is accepted (only the host part is validated).
pub fn validate_host_header(host: &str) -> Result<(), ()> {
    let host_part = if host.starts_with('[') {
        host
    } else {
        match host.split_once(':') {
            Some((name, _)) => name,
            None => host,
        }
    };
    validate_host_name(host_part)
}

/// Validate the authority of an absolute-form request target.
///
/// Stricter than the header path: the request-line parser only allows digits in
/// the port, so `host:1:2` is malformed here even though the header form is not.
pub fn validate_authority(authority: &str) -> Result<(), ()> {
    if !authority.starts_with('[') {
        if let Some((name, port)) = authority.split_once(':') {
            if port.contains(':') || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
            return validate_host_name(name);
        }
    }
    validate_host_name(authority)
}

/// Raw authority of an absolute-form target (userinfo already dropped).
fn absolute_form_authority(target: &str) -> Option<&str> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    Some(
        authority
            .rsplit_once('@')
            .map(|(_, a)| a)
            .unwrap_or(authority),
    )
}

/// Host portion of an absolute-form target, ready for `$host`.
fn absolute_form_host(target: &str) -> Option<String> {
    let authority = absolute_form_authority(target)?;
    Some(strip_port(authority).to_string())
}

/// `example.com:80` -> `example.com`, `[::1]:80` -> `[::1]`.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(i) => &host[..=i],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Headers nginx refuses to see twice.
const UNIQUE_HEADERS: &[&str] = &[
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "if-match",
    "if-none-match",
    "content-length",
    "content-range",
    "if-range",
    "transfer-encoding",
    "expect",
    "authorization",
    "proxy-authorization",
];

fn is_token(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

impl Request {
    pub fn parse(head: &[u8], max_line: usize, max_total: usize) -> Result<Request, HttpError> {
        if head.len() > max_total {
            return Err(HttpError::new(400, true));
        }

        let mut lines = split_lines(head);
        let request_line = lines.next().ok_or_else(|| HttpError::new(400, true))?;
        if request_line.len() > max_line {
            return Err(HttpError::new(414, true));
        }
        // tolerate a stray leading CRLF (RFC 7230 §3.5)
        let request_line = if request_line.is_empty() {
            lines.next().ok_or_else(|| HttpError::new(400, true))?
        } else {
            request_line
        };

        let mut parts = request_line.split(|b| *b == b' ');
        let (m, t, v) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v), None) => (m, t, v),
            _ => return Err(HttpError::new(400, true)),
        };
        if m.is_empty() || m.len() > 32 || !m.iter().all(|b| is_token(*b)) {
            return Err(HttpError::new(400, true));
        }
        if t.is_empty() || t.iter().any(|b| *b <= 0x20 || *b == 0x7f) {
            return Err(HttpError::new(400, true));
        }

        let method = match m {
            b"GET" => Method::Get,
            b"HEAD" => Method::Head,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"OPTIONS" => Method::Options,
            b"PATCH" => Method::Patch,
            b"TRACE" => Method::Trace,
            b"CONNECT" => Method::Connect,
            other => Method::Other(InStr::new(&String::from_utf8_lossy(other))),
        };

        let target_str = String::from_utf8_lossy(t).to_string();

        let version_minor = match v {
            b"HTTP/1.1" => 1,
            b"HTTP/1.0" => 0,
            v if v.starts_with(b"HTTP/")
                && v.len() == 8
                && v[5].is_ascii_digit()
                && v[6] == b'.'
                && v[7].is_ascii_digit() =>
            {
                return Err(HttpError::new(505, true))
            }
            _ => return Err(HttpError::new(400, true)),
        };

        let mut headers = Headers { items: hdr_vec() };
        for raw in lines {
            if raw.is_empty() {
                continue;
            }
            if raw[0] == b' ' || raw[0] == b'\t' {
                // obsolete line folding is rejected by nginx
                return Err(HttpError::new(400, true));
            }
            let colon = memchr::memchr(b':', raw).ok_or_else(|| HttpError::new(400, true))?;
            let name = &raw[..colon];
            if name.is_empty() || !name.iter().all(|b| is_token(*b)) {
                return Err(HttpError::new(400, true));
            }
            let mut value = &raw[colon + 1..];
            while let Some(b' ') | Some(b'\t') = value.first() {
                value = &value[1..];
            }
            while let Some(b' ') | Some(b'\t') = value.last() {
                value = &value[..value.len() - 1];
            }
            if value.iter().any(|b| *b == 0 || *b == b'\r' || *b == b'\n') {
                return Err(HttpError::new(400, true));
            }
            // Lowercase in place: header names are ASCII tokens.
            let mut lowered = [0u8; 48];
            let lname: &str = if name.len() <= lowered.len() {
                for (i, b) in name.iter().enumerate() {
                    lowered[i] = b.to_ascii_lowercase();
                }
                // SAFETY: header names are ASCII tokens (checked above).
                unsafe { std::str::from_utf8_unchecked(&lowered[..name.len()]) }
            } else {
                ""
            };
            let lname = if lname.is_empty() && !name.is_empty() {
                String::from_utf8_lossy(name).to_ascii_lowercase()
            } else {
                lname.to_string()
            };
            headers.items.push((
                InStr::new(&lname),
                InStr::new(&String::from_utf8_lossy(value)),
            ));
        }

        // nginx rejects a repeated header for anything it treats as unique
        // (`ngx_http_process_unique_header_line` in the header table).
        for name in UNIQUE_HEADERS {
            if headers.get_all(name).count() > 1 {
                return Err(HttpError::new(400, true));
            }
        }

        // ---- framing -----------------------------------------------------
        let mut chunked = false;
        if let Some(te) = headers.get("transfer-encoding") {
            let last = te.rsplit(',').next().unwrap_or("").trim();
            if !last.eq_ignore_ascii_case("chunked") {
                return Err(HttpError::new(501, true));
            }
            chunked = true;
        }

        let mut body_len = 0u64;
        let mut saw_len = false;
        for cl in headers.get_all("content-length") {
            let n: u64 = cl.trim().parse().map_err(|_| HttpError::new(400, true))?;
            if saw_len && n != body_len {
                return Err(HttpError::new(400, true));
            }
            body_len = n;
            saw_len = true;
        }
        if saw_len && chunked {
            return Err(HttpError::new(400, true));
        }

        // nginx validates the Host header strictly, even for HTTP/1.0:
        // an empty value, an empty name, or a stray colon after the port are
        // all 400 (see http_host.t).
        let raw_host = headers.get("host");
        if let Some(h) = raw_host {
            validate_host_header(h).map_err(|_| HttpError::new(400, true))?;
        } else if version_minor == 1 {
            return Err(HttpError::new(400, true));
        }

        // absolute-form (`GET http://host/path`) overrides the Host header for
        // $host, which is what nginx's http_absolute_path tests check.
        // Absolute-form: the authority is validated by the request-line rules.
        if is_absolute_form(&target_str) {
            let authority =
                absolute_form_authority(&target_str).ok_or_else(|| HttpError::new(400, true))?;
            validate_authority(authority).map_err(|_| HttpError::new(400, true))?;
        }
        let absolute_host = absolute_form_host(&target_str);
        // nginx's $host is normalized: lowercase, port and stray colon removed.
        let host = match (&absolute_host, raw_host) {
            (Some(a), _) => Some(InStr::new(&normalize_host(a))),
            (None, Some(h)) => Some(InStr::new(&normalize_host(h))),
            (None, None) => None,
        };

        let mut keepalive = version_minor == 1;
        if let Some(conn) = headers.get("connection") {
            for token in conn.split(',') {
                let t = token.trim();
                if t.eq_ignore_ascii_case("close") {
                    keepalive = false;
                } else if t.eq_ignore_ascii_case("keep-alive") {
                    keepalive = true;
                }
            }
        }

        let expect_continue = headers
            .get("expect")
            .map(|v| v.eq_ignore_ascii_case("100-continue"))
            .unwrap_or(false);

        Ok(Request {
            method,
            raw_target: target_str,
            version_minor,
            headers,
            body_len,
            chunked,
            keepalive,
            host,
            expect_continue,
            tls: None,
            started: std::time::Instant::now(),
        })
    }
}

/// Split on `\n` and drop a trailing `\r`.
///
/// nginx accepts bare LF as a line terminator (`ngx_http_parse_request_line`
/// treats it the same as CRLF), and several clients — including the official
/// test suite — send LF-only requests.
fn split_lines(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match memchr::memchr(b'\n', rest) {
            Some(i) => {
                let mut line = &rest[..i];
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                rest = &rest[i + 1..];
                Some(line)
            }
            None => {
                let mut line = rest;
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                rest = &[];
                Some(line)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Request, HttpError> {
        Request::parse(src.as_bytes(), 8192, 32768)
    }

    #[test]
    fn simple_get() {
        let r = parse("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.raw_target, "/index.html");
        assert_eq!(r.version_minor, 1);
        assert!(r.keepalive);
        assert_eq!(r.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn http10_default_close() {
        let r = parse("GET / HTTP/1.0\r\n\r\n").unwrap();
        assert!(!r.keepalive);
    }

    #[test]
    fn http10_keepalive() {
        let r = parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap();
        assert!(r.keepalive);
    }

    #[test]
    fn missing_host_is_400() {
        assert!(parse("GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn host_validation() {
        // empty and host-less values are 400, like nginx
        assert!(parse("GET / HTTP/1.0\r\nHost: \r\n\r\n").is_err());
        assert!(parse("GET / HTTP/1.0\r\nHost: :8080\r\n\r\n").is_err());
        assert!(parse("GET / HTTP/1.0\r\nHost: .\r\n\r\n").is_err());
        assert!(parse("GET / HTTP/1.0\r\nHost: ..example.com\r\n\r\n").is_err());
        assert!(parse("GET / HTTP/1.0\r\nHost: example.com/x\r\n\r\n").is_err());
        assert!(parse("GET http://com.exa-m.45..:/ HTTP/1.0\r\n\r\n").is_err());
        assert!(parse("GET http://example.com./ HTTP/1.0\r\n\r\n").is_ok());
        // nginx truncates at ':' and never validates the port
        assert!(parse("GET / HTTP/1.0\r\nHost: a:b\r\n\r\n").is_ok());
        assert!(parse("GET / HTTP/1.0\r\nHost: 1.2.3.4:9000:80\r\n\r\n").is_ok());
        assert!(parse("GET / HTTP/1.0\r\nHost: example.com:\r\n\r\n").is_ok());
        // a second Host header is refused
        assert!(parse("GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n").is_err());
    }

    #[test]
    fn absolute_form_authority_is_stricter() {
        // the request-line parser only allows digits in the port
        assert!(parse("GET http://1.2.3.4:9000:80/ HTTP/1.0\r\n\r\n").is_err());
        assert!(parse("GET http://[abcd::ef98:0:7654:321]. HTTP/1.0\r\n\r\n").is_err());
        assert!(parse("GET http://extra[abcd::ef98]/ HTTP/1.0\r\n\r\n").is_err());
        assert!(parse("GET http://[abcd::ef98/ HTTP/1.0\r\n\r\n").is_err());
        assert!(parse("GET http://[abcd::ef98]:80/ HTTP/1.0\r\n\r\n").is_ok());
    }

    #[test]
    fn absolute_form_host_wins() {
        let r = parse("GET http://l/ HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("l"));
    }

    #[test]
    fn empty_absolute_authority_is_400() {
        assert!(parse("GET http:/// HTTP/1.0\r\nHost: localhost\r\n\r\n").is_err());
    }

    #[test]
    fn host_is_normalized() {
        // lowercase, port removed, stray colon removed
        let r = parse("GET / HTTP/1.0\r\nHost: L\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("l"));
        let r = parse("GET / HTTP/1.0\r\nHost: Example.COM:8080\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("example.com"));
        let r = parse("GET / HTTP/1.0\r\nHost: abcd-ef.g02.xyz:\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("abcd-ef.g02.xyz"));
        let r = parse("GET / HTTP/1.0\r\nHost: 123.40.56.78:\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("123.40.56.78"));
    }

    #[test]
    fn trailing_dot_is_stripped() {
        // nginx drops the trailing dot, and a host of only dots is a 400
        let r = parse("GET / HTTP/1.0\r\nHost: www.abcd-ef.g02.xyz.\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("www.abcd-ef.g02.xyz"));
        let r = parse("GET / HTTP/1.0\r\nHost: abcd-ef.g02.xyz.:2\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("abcd-ef.g02.xyz"));
        assert!(parse("GET / HTTP/1.0\r\nHost: .\r\n\r\n").is_err());
    }

    #[test]
    fn duplicate_unique_headers_rejected() {
        for h in [
            "Content-Length",
            "If-Modified-Since",
            "If-Unmodified-Since",
            "If-Match",
            "If-None-Match",
            "If-Range",
            "Authorization",
            "Content-Range",
        ] {
            let req = format!("GET / HTTP/1.0\r\n{h}: a\r\n{h}: b\r\n\r\n");
            assert!(parse(&req).is_err(), "{h} should be rejected when repeated");
        }
        // ...but ordinary headers may repeat
        assert!(parse("GET / HTTP/1.0\r\nFoo: a\r\nFoo: b\r\n\r\n").is_ok());
        // Transfer-Encoding and Expect are unique too
        assert!(parse(
            "GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_err());
        assert!(
            parse("GET / HTTP/1.0\r\nExpect: 100-continue\r\nExpect: 100-continue\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn bare_lf_line_endings() {
        // nginx accepts LF-only requests; several clients send them.
        let head = b"GET / HTTP/1.1\nHost: example.com\n\n";
        let r = Request::parse(head, 8192, 32768).unwrap();
        assert_eq!(r.raw_target, "/");
        assert_eq!(r.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn mixed_line_endings() {
        let head = b"GET /x HTTP/1.1\r\nHost: a\nX-Test: 1\r\n\n";
        let r = Request::parse(head, 8192, 32768).unwrap();
        assert_eq!(r.headers.get("x-test"), Some("1"));
    }

    #[test]
    fn obs_fold_rejected() {
        assert!(parse("GET / HTTP/1.1\r\nHost: a\r\n X: y\r\n\r\n").is_err());
    }

    #[test]
    fn body_framing() {
        let r = parse("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(r.body_len, 5);
        assert!(!r.chunked);

        let r = parse("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert!(r.chunked);

        assert!(parse(
            "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
        )
        .is_err());
        assert!(parse("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n").is_err());
    }
}
