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

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn http_date(ts: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        libc::gmtime_r(&t, &mut tm);
    }
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[tm.tm_wday.clamp(0, 6) as usize],
        tm.tm_mday,
        MONTHS[tm.tm_mon.clamp(0, 11) as usize],
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn log_time(ts: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    let off = unsafe { tm.tm_gmtoff };
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
    let mut target = raw;

    // absolute-form (http://host/path) is allowed in requests to proxies
    let lower = target.get(..8).unwrap_or("").to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let after = &target[target.find("://").unwrap() + 3..];
        match after.find('/') {
            Some(i) => target = &after[i..],
            None => target = "/",
        }
    }

    if !target.starts_with('/') {
        return Err(());
    }

    let (path_raw, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };

    let decoded = percent_decode(path_raw)?;
    let path = normalize_path(&decoded, true)?;
    Ok((path, query.to_string()))
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
    fn targets() {
        assert_eq!(parse_target("/a%20b?x=1").unwrap(), ("/a b".to_string(), "x=1".to_string()));
        assert_eq!(
            parse_target("http://example.com/x").unwrap(),
            ("/x".to_string(), "".to_string())
        );
        assert!(parse_target("/a%00b").is_err());
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
