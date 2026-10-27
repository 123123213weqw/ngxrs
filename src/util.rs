//! Small shared helpers: URI normalization, HTTP dates, status reasons.

pub const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        494 => "Request Header Too Large",
        495 => "SSL Certificate Error",
        496 => "No Required SSL Certificate",
        497 => "The Plain HTTP Request was sent to HTTPS port",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version Not Supported",
        _ => "Unknown Status",
    }
}

/// Status text used inside nginx's generated error pages. This is NOT always
/// the status line reason (e.g. 302's line says "Moved Temporarily" but its
/// error page says "Found"); both tables are copied from nginx 1.28.
pub fn error_page_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Authorization Required",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        other => reason(other),
    }
}

/// Statuses for which nginx drops keepalive (`ngx_http_special_response_handler`
/// clears `r->keepalive` for these).
pub fn force_close(status: u16) -> bool {
    // Exactly the list from ngx_http_special_response_handler: 405 is NOT here,
    // so a 405 keeps the connection alive.
    matches!(status, 400 | 413 | 414 | 495 | 496 | 497 | 500 | 501)
}

/// Statuses nginx has an entry for in `ngx_http_special_response.c`; only
/// these can be intercepted by `error_page` (a `return 418` is passed through).
pub fn is_special_status(status: u16) -> bool {
    matches!(
        status,
        301 | 302
            | 303
            | 307
            | 308
            | 400
            | 401
            | 402
            | 403
            | 404
            | 405
            | 406
            | 408
            | 409
            | 410
            | 411
            | 412
            | 413
            | 414
            | 415
            | 416
            | 421
            | 429
            | 494
            | 495
            | 496
            | 497
            | 500
            | 501
            | 502
            | 503
            | 504
            | 505
            | 507
    )
}

/// Percent-encode a path for a `Location` header (nginx's
/// `NGX_ESCAPE_URI`): unreserved and reserved characters are kept, everything
/// else — including a space — is escaped.
pub fn escape_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for b in path.bytes() {
        // nginx's ESCAPE_URI set: everything else (including ? % # \ ^ ` { | })
        // gets percent-encoded.
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`] (Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[inline]
fn push_2(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}

/// Format an IMF-fixdate directly into `out` without allocating.
pub fn push_http_date(out: &mut Vec<u8>, ts: i64) {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    // 1970-01-01 was a Thursday (weekday index 4 with Sunday = 0)
    let wd = (days.rem_euclid(7) + 4) % 7;
    out.extend_from_slice(WEEKDAYS[wd as usize].as_bytes());
    out.extend_from_slice(b", ");
    push_2(out, d);
    out.push(b' ');
    out.extend_from_slice(MONTHS[(m - 1) as usize].as_bytes());
    out.push(b' ');
    out.extend_from_slice(&y.to_string().as_bytes());
    out.push(b' ');
    push_2(out, (secs / 3600) as u32);
    out.push(b':');
    push_2(out, ((secs % 3600) / 60) as u32);
    out.push(b':');
    push_2(out, (secs % 60) as u32);
    out.extend_from_slice(b" GMT");
}

pub fn http_date(ts: i64) -> String {
    let mut out = Vec::with_capacity(29);
    push_http_date(&mut out, ts);
    // SAFETY: only ASCII digits/latin letters plus fixed punctuation.
    String::from_utf8(out).unwrap_or_default()
}

/// Append a `Date:` value, reusing a per-thread cache for the current second
/// (nginx keeps a single cached time string as well).
pub fn write_date_header(out: &mut Vec<u8>, now: i64) {
    use std::cell::RefCell;
    thread_local! {
        static CACHE: RefCell<(i64, Vec<u8>)> = const { RefCell::new((0, Vec::new())) };
    }
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != now {
            c.1.clear();
            push_http_date(&mut c.1, now);
            c.0 = now;
        }
        out.extend_from_slice(b"Date: ");
        out.extend_from_slice(&c.1);
        out.extend_from_slice(b"\r\n");
    });
}

pub fn log_time(ts: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    let off = tm.tm_gmtoff;
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    format!(
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} {}{:02}{:02}",
        tm.tm_mday,
        MONTHS[tm.tm_mon.clamp(0, 11) as usize],
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        sign,
        off / 3600,
        (off % 3600) / 60
    )
}

fn month_from(s: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(s))
        .map(|i| i as u32 + 1)
}

/// Parse IMF-fixdate, RFC 850 and asctime formats.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.trim().split_whitespace().collect();

    let hms = |t: &str| -> Option<i64> {
        let mut it = t.split(':');
        let h = it.next()?.parse::<i64>().ok()?;
        let m = it.next()?.parse::<i64>().ok()?;
        let sec = it.next()?.parse::<i64>().ok()?;
        Some(h * 3600 + m * 60 + sec)
    };

    // IMF-fixdate: "Sun, 18 Oct 2026 00:25:25 GMT"
    if parts.len() >= 5 && parts[0].ends_with(',') && parts[3].len() == 4 {
        let day = parts[1].parse::<u32>().ok()?;
        let mon = month_from(parts[2])?;
        let year = parts[3].parse::<i64>().ok()?;
        let secs = hms(parts[4])?;
        return Some(days_from_civil(year, mon, day) * 86400 + secs);
    }

    // RFC 850: "Sunday, 18-Oct-26 00:25:25 GMT"
    if parts.len() >= 3 && parts[0].ends_with(',') && parts[1].contains('-') {
        let bits: Vec<&str> = parts[1].split('-').collect();
        if bits.len() == 3 {
            let day = bits[0].parse::<u32>().ok()?;
            let mon = month_from(bits[1])?;
            let mut year = bits[2].parse::<i64>().ok()?;
            if year < 100 {
                year += if year >= 70 { 1900 } else { 2000 };
            }
            let secs = hms(parts[2])?;
            return Some(days_from_civil(year, mon, day) * 86400 + secs);
        }
    }

    // asctime: "Sun Oct 18 00:25:25 2026"
    if parts.len() >= 5 {
        let mon = month_from(parts[1])?;
        let day = parts[2].parse::<u32>().ok()?;
        let secs = hms(parts[3])?;
        let year = parts[4].parse::<i64>().ok()?;
        return Some(days_from_civil(year, mon, day) * 86400 + secs);
    }

    None
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a URI component. Rejects `%00` and bad escapes.
pub fn percent_decode(s: &str) -> Result<String, ()> {
    // No escapes is the common case; skip the copy entirely.
    if !s.as_bytes().contains(&b'%') {
        return Ok(s.to_string());
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return Err(());
                }
                let hi = hexval(b[i + 1]).ok_or(())?;
                let lo = hexval(b[i + 2]).ok_or(())?;
                let v = (hi << 4) | lo;
                if v == 0 {
                    return Err(());
                }
                out.push(v);
                i += 3;
            }
            c if c < 0x20 || c == 0x7f => return Err(()),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

/// Normalize a decoded absolute path: merge slashes, resolve `.` / `..`.
pub fn normalize_path(path: &str, merge_slashes: bool) -> Result<String, ()> {
    if !path.starts_with('/') {
        return Err(());
    }
    // Fast path: nothing to merge and no `.`/`..` segments, so the result is the
    // input. Avoids the segment Vec and the join for the overwhelmingly common
    // case (any path with no `//` and no `/./` or `/../`).
    if !path.contains("..")
        && (!merge_slashes || !path.contains("//"))
        && !path.contains("/./")
        && !path.ends_with("/.")
    {
        return Ok(path.to_string());
    }
    let trailing = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {
                if !merge_slashes && seg.is_empty() {
                    // nginx without merge_slashes keeps duplicate slashes; we
                    // still drop them here to keep path handling unambiguous.
                }
            }
            ".." => {
                if stack.pop().is_none() {
                    return Err(());
                }
            }
            s => stack.push(s),
        }
    }
    let mut out = String::with_capacity(path.len() + 1);
    out.push('/');
    out.push_str(&stack.join("/"));
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    Ok(out)
}

/// Split a raw request target into a normalized path and a raw query string.
pub fn parse_target(raw: &str) -> Result<(String, String), ()> {
    // absolute-form (`http://host/path`) is allowed in requests to proxies.
    // Everything up to the first `/` or `?` is the authority; a query directly
    // after the host (`http://host?a=1`) still belongs to the request.
    let rewritten = absolute_form_to_origin(raw);
    let target: &str = match &rewritten {
        Some(t) => t,
        None => raw,
    };

    if !target.starts_with('/') {
        return Err(());
    }

    // A fragment is never part of the request target: nginx drops everything
    // from `#` on (`$uri` and `$args` both exclude it).
    let target = match target.find('#') {
        Some(hash) => &target[..hash],
        None => target,
    };

    let (path_raw, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };

    let decoded = percent_decode(path_raw)?;
    let path = normalize_path(&decoded, true)?;
    Ok((path, query.to_string()))
}

/// Turn `http://host[/path][?query]` into an origin-form target, or `None` when
/// the input is already origin-form.
fn absolute_form_to_origin(raw: &str) -> Option<String> {
    // Case-insensitive prefix test without allocating: this ran for every
    // request and built an 8-byte lowercase String only to discard it (see
    // BENCH.md, "parse_target" cost).
    let head = raw.as_bytes();
    let matches = |want: &[u8]| {
        head.len() >= want.len()
            && head[..want.len()]
                .iter()
                .zip(want)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    };
    if !matches(b"http://") && !matches(b"https://") {
        return None;
    }
    let after = &raw[raw.find("://")? + 3..];
    Some(match after.find(['/', '?']) {
        // `host/path...`
        Some(0) => after.to_string(),
        // `host?query` — keep the query, the path is `/`
        Some(i) if after.as_bytes()[i] == b'?' => format!("/{}", &after[i..]),
        Some(i) => after[i..].to_string(),
        None => "/".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("/a//b/", true).unwrap(), "/a/b/");
        assert_eq!(normalize_path("/a/./b", true).unwrap(), "/a/b");
        assert_eq!(normalize_path("/a/b/../c", true).unwrap(), "/a/c");
        assert_eq!(normalize_path("/", true).unwrap(), "/");
        assert!(normalize_path("/../etc/passwd", true).is_err());
    }

    #[test]
    fn absolute_form_with_query() {
        // `http://host?args` must keep the query, not drop it
        assert_eq!(
            parse_target("http://localhost?args").unwrap(),
            ("/".to_string(), "args".to_string())
        );
        assert_eq!(
            parse_target("http://localhost:8080?args#frag").unwrap(),
            ("/".to_string(), "args".to_string())
        );
        assert_eq!(
            parse_target("http://localhost").unwrap(),
            ("/".to_string(), "".to_string())
        );
    }

    #[test]
    fn fragment_is_dropped() {
        assert_eq!(
            parse_target("/foo/bar/.#frag").unwrap(),
            ("/foo/bar/".to_string(), "".to_string())
        );
        assert_eq!(
            parse_target("/x?a=1#frag").unwrap(),
            ("/x".to_string(), "a=1".to_string())
        );
    }

    #[test]
    fn targets() {
        assert_eq!(
            parse_target("/a%20b?x=1").unwrap(),
            ("/a b".to_string(), "x=1".to_string())
        );
        assert_eq!(
            parse_target("http://example.com/x").unwrap(),
            ("/x".to_string(), "".to_string())
        );
        assert!(parse_target("/a%00b").is_err());
    }

    #[test]
    fn uri_escaping() {
        assert_eq!(escape_uri("/dir sp/"), "/dir%20sp/");
        assert_eq!(escape_uri("/a/b/"), "/a/b/");
        assert_eq!(escape_uri("/x?a=b"), "/x%3Fa=b");
        // nginx's ESCAPE_URI set: ? % # \ ^ ` { | } are all escaped
        assert_eq!(
            escape_uri("/\"#%<>?\\^`{|}/"),
            "/%22%23%25%3C%3E%3F%5C%5E%60%7B%7C%7D/"
        );
    }

    #[test]
    fn dates_roundtrip() {
        let t = 1_791_000_000; // arbitrary fixed instant
        let s = http_date(t);
        assert_eq!(parse_http_date(&s), Some(t), "date string was {s}");
    }

    #[test]
    fn parse_rfc850() {
        assert!(parse_http_date("Sunday, 18-Oct-26 00:25:25 GMT").is_some());
    }
}

/// Standard base64 with padding (RFC 4648 §4), as used by the mail AUTH
/// mechanisms.
pub fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64, ignoring whitespace and tolerating missing padding.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod base64_tests {
    use super::*;

    #[test]
    fn round_trips() {
        for s in [
            "",
            "f",
            "fo",
            "foo",
            "secret",
            "test@example.com",
            "\0user\0pass",
        ] {
            let e = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&e).unwrap(), s.as_bytes(), "{s}");
        }
    }

    #[test]
    fn known_values() {
        // The two challenges nginx sends for POP3/IMAP/SMTP LOGIN.
        assert_eq!(base64_encode(b"Username:"), "VXNlcm5hbWU6");
        assert_eq!(base64_encode(b"Password:"), "UGFzc3dvcmQ6");
    }
}

/// Append a decimal integer without going through `to_string`.
#[inline]
pub fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Append a lowercase hex integer without going through `format!`.
#[inline]
pub fn push_hex_u64(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    while v > 0 {
        let d = (v & 0xf) as u8;
        i -= 1;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Write lowercase hex into `buf`, returning the byte count.
#[inline]
pub fn write_hex_u64(buf: &mut [u8], mut v: u64) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut i = tmp.len();
    while v > 0 {
        let d = (v & 0xf) as u8;
        i -= 1;
        tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
    }
    let n = tmp.len() - i;
    buf[..n].copy_from_slice(&tmp[i..]);
    n
}

/// Owned hex rendering of one integer into caller-provided storage, so callers
/// can compare it as a `&str` without allocating.
#[inline]
pub fn hex_u64_into(buf: &mut [u8; 16], v: u64) -> &str {
    let mut tmp = Vec::new();
    push_hex_u64(&mut tmp, v);
    let n = tmp.len().min(buf.len());
    buf[..n].copy_from_slice(&tmp[..n]);
    std::str::from_utf8(&buf[..n]).unwrap_or("0")
}

/// Render `ts` (seconds since the epoch, UTC) using a `strftime`-style format.
///
/// Implements the subset of `strftime` that the SSI `config timefmt` directive
/// uses in practice: %A %a %B %b %d %e %H %I %j %M %m %p %S %U %w %Y %y %Z %%
/// Unknown specifiers are copied through verbatim, as glibc does not, but nginx
/// renders them literally rather than dropping them.
pub fn strftime_gmt(ts: i64, fmt: &str) -> String {
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // 1970-01-01 was a Thursday (4), with Sunday as 0.
    let wday = (days + 4).rem_euclid(7) as usize;
    let yday = days - days_from_civil(y, 1, 1) + 1;

    let mut out = String::with_capacity(fmt.len() + 16);
    let mut it = fmt.chars().peekable();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('A') => out.push_str(DAYS[wday]),
            Some('a') => out.push_str(&DAYS[wday][..3]),
            Some('B') => out.push_str(MONTHS[(m - 1) as usize]),
            Some('b') => out.push_str(&MONTHS[(m - 1) as usize][..3]),
            Some('d') => out.push_str(&format!("{d:02}")),
            Some('e') => out.push_str(&format!("{d:2}")),
            Some('H') => out.push_str(&format!("{hh:02}")),
            Some('I') => {
                let h12 = if hh % 12 == 0 { 12 } else { hh % 12 };
                out.push_str(&format!("{h12:02}"));
            }
            Some('j') => out.push_str(&format!("{yday:03}")),
            Some('M') => out.push_str(&format!("{mm:02}")),
            Some('m') => out.push_str(&format!("{m:02}")),
            Some('p') => out.push_str(if hh < 12 { "AM" } else { "PM" }),
            Some('S') => out.push_str(&format!("{ss:02}")),
            Some('Y') => out.push_str(&format!("{y}")),
            Some('y') => out.push_str(&format!("{:02}", y % 100)),
            Some('Z') => out.push_str("GMT"),
            Some('%') => out.push('%'),
            // Unsupported specifiers keep their literal form.
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// A `$request_id`: 16 random bytes as 32 lowercase hex digits.
///
/// nginx fills `ngx_http_request_t.request_id` from the RNG when the variable is
/// first asked for; generating it at parse time is equivalent and simpler.
pub fn new_request_id() -> String {
    let mut raw = [0u8; 16];
    // `ring` is already a dependency (it backs rustls), so this needs no new
    // crate. A failure would leave all-zero bytes; the id is only an
    // identifier, not a secret, but ask again once before giving up.
    use ring::rand::SecureRandom;
    if ring::rand::SystemRandom::new().fill(&mut raw).is_err() {
        let _ = ring::rand::SystemRandom::new().fill(&mut raw);
    }
    let mut out = String::with_capacity(32);
    for b in raw {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    out
}

/// `$time_iso8601`: `1970-09-28T12:00:00+06:00`, in the server's local zone
/// (`ngx_http_log_iso8601` formats `tm_gmtoff` as `+06:00`).
pub fn iso8601_time(ts: i64) -> String {
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let t = ts as libc::time_t;
        if libc::localtime_r(&t, &mut tm).is_null() {
            return String::new();
        }
        let off = tm.tm_gmtoff;
        let sign = if off < 0 { '-' } else { '+' };
        let abs = off.unsigned_abs();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            sign,
            abs / 3600,
            (abs % 3600) / 60
        )
    }
}
