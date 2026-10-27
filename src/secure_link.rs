//! `ngx_http_secure_link_module`: link signature checking.
//!
//! Two styles, both from nginx 1.28's `ngx_http_secure_link_module.c`:
//!
//! * **new** (`secure_link` + `secure_link_md5`): the value of `secure_link` is
//!   `<base64url(md5(secure_link_md5 value))>[,<expires>]`. `$secure_link` is
//!   `"1"` when the digest matches and the link has not expired, `"0"` when it
//!   matched but expired, and not-found (renders as the empty string) for
//!   anything else -- including a malformed value.
//! * **old** (`secure_link_secret`): the URI must be
//!   `/<prefix>/<32 hex md5>/<rest>`, where the digest is `md5(rest + secret)`.
//!   `$secure_link` is then `<rest>`.
//!
//! nginx exposes both as *variables with a get_handler*, so the work happens on
//! the first read -- which for every real config is the `if ($secure_link ...)`
//! in the rewrite phase. We compute it once, before the rewrite steps run, and
//! put the result into the per-request variable map: equivalent, and it means
//! `$secure_link` is also visible to `return`, `add_header` and the access log.

use crate::config::LocCfg;
use crate::http::request::Request;

/// `(secure_link, secure_link_expires)` as the two nginx variables.
///
/// `None` when the directive is not configured at all, in which case neither
/// variable exists (nginx leaves them not-found).
pub fn evaluate(loc: &LocCfg, req: &Request) -> Option<(String, String)> {
    if let Some(secret) = &loc.secure_link_secret {
        // `ngx_http_secure_link_old_variable` walks `r->unparsed_uri`, so the
        // query string is included in the text being hashed.
        return Some((old_style(&req.raw_target, secret), String::new()));
    }
    let (link_spec, md5_spec) = (loc.secure_link.as_ref()?, loc.secure_link_md5.as_ref()?);
    let value = expand(link_spec, req);
    let md5_input = expand(md5_spec, req);
    Some(new_style(&value, &md5_input))
}

/// `secure_link` values are complex (`$arg_hash,$arg_expires`), so the parts
/// nginx calls `ngx_http_complex_value` happen here. Only the variables that
/// make sense before the rewrite phase are resolved; anything else is left as
/// the empty string, which fails the check rather than passing it.
fn expand(spec: &str, req: &Request) -> String {
    let b = spec.as_bytes();
    let mut out = String::with_capacity(spec.len());
    let mut lit = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'$' {
            i += 1;
            continue;
        }
        let rest = &spec[i + 1..];
        let n = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        out.push_str(&spec[lit..i]);
        if n == 0 {
            out.push('$');
            i += 1;
        } else {
            out.push_str(&lookup(&rest[..n], req));
            i += 1 + n;
        }
        lit = i;
    }
    out.push_str(&spec[lit..]);
    out
}

fn lookup(name: &str, req: &Request) -> String {
    match name {
        "uri" | "document_uri" => req
            .raw_target
            .split('?')
            .next()
            .unwrap_or("")
            .to_string(),
        "request_uri" => req.raw_target.clone(),
        "args" | "query_string" => req
            .raw_target
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default(),
        "request_method" => req.method.as_str().to_string(),
        "host" | "http_host" => req.headers.get("host").unwrap_or("").to_string(),
        "remote_addr" => String::new(),
        _ => {
            if let Some(want) = name.strip_prefix("arg_") {
                let query = req.raw_target.split_once('?').map(|(_, q)| q).unwrap_or("");
                return query
                    .split('&')
                    .filter_map(|p| p.split_once('='))
                    .find(|(k, _)| k.eq_ignore_ascii_case(want))
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default();
            }
            if let Some(h) = name.strip_prefix("http_") {
                let key = h.replace('_', "-");
                return req.headers.get(&key).unwrap_or("").to_string();
            }
            String::new()
        }
    }
}

fn new_style(value: &str, md5_input: &str) -> (String, String) {
    // `hash[,expires]`
    let (hash_part, expires_part) = match value.split_once(',') {
        Some((h, e)) => (h, Some(e)),
        None => (value, None),
    };
    let mut expires: u64 = 0;
    if let Some(e) = expires_part {
        // `ngx_atotm`: digits only, and a value of 0 or a parse failure is a
        // not-found (not an "already expired" answer).
        match e.parse::<u64>() {
            Ok(v) if v > 0 => expires = v,
            _ => return (String::new(), String::new()),
        }
    }
    // nginx refuses anything longer than 24 characters before even decoding
    // (`ngx_decode_base64url` would accept trailing bytes otherwise).
    if hash_part.len() > 24 {
        return (String::new(), expires_part.unwrap_or("").to_string());
    }
    let Some(got) = base64url_decode(hash_part) else {
        return (String::new(), expires_part.unwrap_or("").to_string());
    };
    if got.len() != 16 {
        return (String::new(), expires_part.unwrap_or("").to_string());
    }
    let want = crate::md5::digest(md5_input.as_bytes());
    let ok = got.iter().zip(want.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    let displayed = expires_part.unwrap_or("").to_string();
    if !ok {
        return (String::new(), displayed);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verdict = if expires != 0 && expires < now { "0" } else { "1" };
    (verdict.to_string(), displayed)
}

fn old_style(unparsed_uri: &str, secret: &str) -> String {
    // `/prefix/<hash>/<rest>`: the hash is the run between the first and second
    // `/` after the leading one.
    let mut it = unparsed_uri.char_indices();
    // Skip the leading '/'.
    if !matches!(it.next(), Some((_, '/'))) {
        return String::new();
    }
    let Some((start, _)) = it.find(|(_, c)| *c == '/') else {
        return String::new();
    };
    let start = start + 1;
    let Some((end, _)) = unparsed_uri[start..]
        .char_indices()
        .find(|(_, c)| *c == '/')
        .map(|(p, c)| (start + p, c))
    else {
        return String::new();
    };
    let hash = &unparsed_uri[start..end];
    let rest = &unparsed_uri[end + 1..];
    if hash.len() != 32 || rest.is_empty() {
        return String::new();
    }
    let now = String::new();
    let _ = now;
    let mut input = Vec::with_capacity(rest.len() + secret.len());
    input.extend_from_slice(rest.as_bytes());
    input.extend_from_slice(secret.as_bytes());
    let want = crate::md5::hex(&crate::md5::digest(&input));
    // nginx compares hex digit by hex digit through `ngx_hextoi`, so `hash`
    // must be exactly the lowercase hex it computed.
    if hash.eq_ignore_ascii_case(&want) {
        rest.to_string()
    } else {
        String::new()
    }
}

/// base64url (RFC 4648 §5) without the `=` padding nginx's decoder implies.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            // Padding is only allowed at the end; nginx's base64url decoder
            // rejects it in the middle and stops at it.
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_python_helper_used_by_nginx_tests() {
        // encode_base64url(md5("secret/expires.html$expires")) for the fixed
        // vector in secure_link.t's sibling test: this is the digest of
        // "secret/test.html".
        let d = crate::md5::digest(b"secret/test.html");
        let mut s = String::new();
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for chunk in d.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
                | *chunk.get(2).unwrap_or(&0) as u32;
            for k in 0..4 {
                if k <= chunk.len() {
                    s.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
                }
            }
        }
        assert_eq!(base64url_decode(&s).unwrap(), d.to_vec());
        // Padding is accepted at the end and ignored.
        let padded = format!("{s}==");
        assert_eq!(base64url_decode(&padded).unwrap(), d.to_vec());
        assert!(base64url_decode("***").is_none());
    }

    #[test]
    fn new_style_verdicts() {
        // The vector from secure_link.t: md5("secret/test.html").
        let hash = "q-5vpkjBkRXXtkUMXiJVHA";
        assert_eq!(new_style(hash, "secret/test.html").0, "1");
        assert_eq!(new_style(hash, "secret/other.html").0, "");
        // Too long, wrong length, bad characters: not found, not "expired".
        assert_eq!(new_style(&format!("{hash}QQ"), "secret/test.html").0, "");
        assert_eq!(new_style("BADHASHLENGTH", "secret/test.html").0, "");
        assert_eq!(new_style("", "secret/test.html").0, "");
        // Expiry: a past epoch is "0", the future is "1", 0 is malformed.
        let past = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100)
            .to_string();
        let input = format!("secret/expires.html{past}");
        let d = crate::md5::digest(input.as_bytes());
        let mut s = String::new();
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for chunk in d.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
                | *chunk.get(2).unwrap_or(&0) as u32;
            for k in 0..4 {
                if k <= chunk.len() {
                    s.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
                }
            }
        }
        let (verdict, shown) = new_style(&format!("{s},{past}"), &input);
        assert_eq!(verdict, "0");
        assert_eq!(shown, past);
        assert_eq!(new_style(&format!("{s},0"), &input).0, "");
        assert_eq!(new_style(&format!("{s},abc"), &input).0, "");
    }

    #[test]
    fn old_style_extracts_the_tail() {
        let secret = "secret";
        let want = crate::md5::hex(&crate::md5::digest(b"test.htmlsecret"));
        let uri = format!("/p/{want}/test.html");
        assert_eq!(old_style(&uri, secret), "test.html");
        // Wrong digest, short hash, no hash, bad uri: all not found.
        assert_eq!(old_style("/p/deadbeefdeadbeefdeadbeefdeadbeef/test.html", secret), "");
        assert_eq!(old_style("/p/foo/test.html", secret), "");
        assert_eq!(old_style("/p/test.html", secret), "");
        assert_eq!(old_style("/p%2f", secret), "");
        assert_eq!(old_style("/p//x", secret), "");
    }
}
