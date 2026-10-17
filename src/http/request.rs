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
}

impl Drop for Request {
    fn drop(&mut self) {
        recycle(std::mem::take(&mut self.headers.items));
    }
}

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

        let mut lines = split_crlf(head);
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
            let n: u64 = cl
                .trim()
                .parse()
                .map_err(|_| HttpError::new(400, true))?;
            if saw_len && n != body_len {
                return Err(HttpError::new(400, true));
            }
            body_len = n;
            saw_len = true;
        }
        if saw_len && chunked {
            return Err(HttpError::new(400, true));
        }

        let host = headers.get("host").map(InStr::new);
        if host.is_none() && version_minor == 1 {
            return Err(HttpError::new(400, true));
        }

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
            raw_target: String::from_utf8_lossy(t).to_string(),
            version_minor,
            headers,
            body_len,
            chunked,
            keepalive,
            host,
            expect_continue,
        })
    }
}

fn split_crlf(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match memchr::memmem::find(rest, b"\r\n") {
            Some(i) => {
                let line = &rest[..i];
                rest = &rest[i + 2..];
                Some(line)
            }
            None => {
                let line = rest;
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

        assert!(parse("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n").is_err());
        assert!(parse("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n").is_err());
    }
}
