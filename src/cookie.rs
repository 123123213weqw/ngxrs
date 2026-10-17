//! `proxy_cookie_domain` / `proxy_cookie_path` — rewrite `Set-Cookie`
//! attributes of an upstream response.
//!
//! Ported from `ngx_http_proxy_module.c`; see `rewrite_cookie` for the exact
//! quirks (leading-dot handling, always-caseless domain regexes, prefix
//! replacement for path).

/// One `proxy_cookie_domain <from> <to>` / `proxy_cookie_path <from> <to>`.
#[derive(Debug, Clone)]
pub struct CookieRewrite {
    /// `None` for regex patterns.
    pub exact: Option<String>,
    /// Regex source (without the leading `~` / `~*`).
    pub regex: Option<regex::Regex>,
    pub replacement: String,
}

impl CookieRewrite {
    /// Build from the directive operands.
    ///
    /// `is_domain` selects nginx's quirks:
    /// - domains strip a leading `.` from both operands and compile **every**
    ///   regex case-insensitively (`~` and `~*` behave the same);
    /// - paths keep the leading `.` and honour `~` vs `~*`.
    pub fn parse(from: &str, to: &str, is_domain: bool) -> Option<Self> {
        if let Some(rest) = from.strip_prefix('~') {
            let (src, caseless) = if let Some(r2) = rest.strip_prefix('*') {
                (r2, true)
            } else {
                (rest, is_domain)
            };
            let pat = if caseless {
                format!("(?i){src}")
            } else {
                src.to_string()
            };
            let re = regex::Regex::new(&pat).ok()?;
            return Some(CookieRewrite {
                exact: None,
                regex: Some(re),
                replacement: to.to_string(),
            });
        }

        let (from, to) = if is_domain {
            (from.strip_prefix('.').unwrap_or(from), to.strip_prefix('.').unwrap_or(to))
        } else {
            (from, to)
        };
        Some(CookieRewrite {
            exact: Some(from.to_string()),
            regex: None,
            replacement: to.to_string(),
        })
    }

    /// Apply to one attribute value.
    ///
    /// Returns `None` when the pattern does not match.
    pub fn apply(&self, value: &str, is_domain: bool, expand: &dyn Fn(&str) -> String) -> Option<String> {
        if let Some(re) = &self.regex {
            let caps = re.captures(value)?;
            let mut named: Vec<(usize, (usize, usize))> = Vec::new();
            for (i, _) in caps.iter().enumerate() {
                if let Some(m) = caps.get(i) {
                    named.push((i, (m.start(), m.end())));
                }
            }
            return Some(expand_caps(&self.replacement, &caps, &named));
        }

        // nginx compiles the pattern as a complex value, so `$server_name`
        // and friends are expanded per request.
        let pattern = expand(self.exact.as_deref()?);
        let pat = pattern.as_str();
        if is_domain {
            // nginx skips one leading dot before comparing, then puts it back.
            let (body, had_dot) = match value.strip_prefix('.') {
                Some(rest) => (rest, true),
                None => (value, false),
            };
            if !body.eq_ignore_ascii_case(pat) {
                return None;
            }
            let mut out = String::with_capacity(self.replacement.len() + 1);
            if had_dot {
                out.push('.');
            }
            out.push_str(&expand(&self.replacement));
            Some(out)
        } else {
            // Paths: prefix replacement.
            if !value.starts_with(pat) {
                return None;
            }
            let mut out = expand(&self.replacement);
            out.push_str(&value[pat.len()..]);
            Some(out)
        }
    }
}

fn expand_caps(spec: &str, caps: &regex::Captures<'_>, _named: &[(usize, (usize, usize))]) -> String {
    let mut out = String::with_capacity(spec.len());
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let n = (b[i + 1] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                out.push_str(m.as_str());
            }
            i += 2;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// One attribute of a `Set-Cookie` value.
struct Attr {
    key: String,
    value: Option<String>,
}

/// Split a `Set-Cookie` value the way `ngx_http_proxy_parse_cookie` does.
fn parse_cookie(v: &str) -> Vec<Attr> {
    let mut out = Vec::new();
    for part in v.split(';') {
        let part = part.trim_start_matches(' ');
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k, Some(v.trim_end_matches(' ').to_string())),
            None => (part, None),
        };
        out.push(Attr {
            key: key.trim_end_matches(' ').to_string(),
            value,
        });
    }
    out
}

/// Rewrite every `Set-Cookie` in a response head (header lines only).
///
/// `expand` resolves variables (`$server_name` etc.) in the replacement text;
/// regex captures are substituted before it is called.
pub fn rewrite_set_cookie(
    head: &[u8],
    domains: &[CookieRewrite],
    paths: &[CookieRewrite],
    expand: &dyn Fn(&str) -> String,
) -> Vec<u8> {
    if domains.is_empty() && paths.is_empty() {
        return head.to_vec();
    }

    let mut out = Vec::with_capacity(head.len() + 64);
    let mut pos = 0usize;
    while pos < head.len() {
        let end = memchr::memmem::find(&head[pos..], b"\r\n")
            .map(|i| pos + i)
            .unwrap_or(head.len());
        let line = &head[pos..end];
        out.extend_from_slice(&rewrite_line(line, domains, paths, expand));
        if end < head.len() {
            out.extend_from_slice(b"\r\n");
        }
        pos = end + 2;
    }
    out
}

fn rewrite_line(
    line: &[u8],
    domains: &[CookieRewrite],
    paths: &[CookieRewrite],
    expand: &dyn Fn(&str) -> String,
) -> Vec<u8> {
    const NAME: &[u8] = b"set-cookie:";
    if line.len() <= NAME.len() || !line[..NAME.len()].eq_ignore_ascii_case(NAME) {
        return line.to_vec();
    }
    let value_bytes = &line[NAME.len()..];
    let value = String::from_utf8_lossy(value_bytes);
    let value = value.trim_start();

    let attrs = parse_cookie(value);
    let mut changed = false;
    let rewritten: Vec<Attr> = attrs
        .into_iter()
        .map(|mut a| {
            let Some(v) = a.value.as_deref() else {
                return a;
            };
            let lower = a.key.to_ascii_lowercase();
            let (list, is_domain) = if lower == "domain" {
                (domains, true)
            } else if lower == "path" {
                (paths, false)
            } else {
                return a;
            };
            for rw in list {
                if let Some(new) = rw.apply(v, is_domain, expand) {
                    if new != v {
                        changed = true;
                    }
                    a.value = Some(new);
                    break;
                }
            }
            a
        })
        .collect();

    if !changed {
        return line.to_vec();
    }

    // Reassemble exactly like nginx: `key=value` joined with `"; "`.
    let mut body = String::with_capacity(value.len());
    for (i, a) in rewritten.iter().enumerate() {
        if i > 0 {
            body.push_str("; ");
        }
        body.push_str(&a.key);
        if let Some(v) = &a.value {
            body.push('=');
            body.push_str(v);
        }
    }

    let mut out = Vec::with_capacity(NAME.len() + 1 + body.len());
    out.extend_from_slice(&line[..NAME.len()]);
    out.push(b' ');
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_vars(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn domain_exact_drops_leading_dot() {
        let rw = CookieRewrite::parse("www.example.org", ".example.com", true).unwrap();
        assert_eq!(
            rw.apply("www.Example.org", true, &no_vars).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn domain_exact_keeps_original_leading_dot() {
        let rw = CookieRewrite::parse(".localhost.com", "en.localhost.org", true).unwrap();
        assert_eq!(
            rw.apply(".LocalHost.com", true, &no_vars).as_deref(),
            Some(".en.localhost.org")
        );
        assert_eq!(
            rw.apply("localhost.com", true, &no_vars).as_deref(),
            Some("en.localhost.org")
        );
    }

    #[test]
    fn domain_regex_is_caseless_but_captures_keep_case() {
        let rw = CookieRewrite::parse(r"~^(.+)\.com$", "$1.org", true).unwrap();
        assert_eq!(
            rw.apply("WWW.EXAMPLE.COM", true, &no_vars).as_deref(),
            Some("WWW.EXAMPLE.org")
        );
        // A leading dot is part of the regex input for domains.
        assert_eq!(
            rw.apply(".WWW.EXAMPLE.COM", true, &no_vars).as_deref(),
            Some(".WWW.EXAMPLE.org")
        );
    }

    #[test]
    fn path_exact_is_a_prefix_replacement() {
        let rw = CookieRewrite::parse("/path/", "/new/", false).unwrap();
        assert_eq!(
            rw.apply("/path/test.html", false, &no_vars).as_deref(),
            Some("/new/test.html")
        );
        assert_eq!(rw.apply("/other/", false, &no_vars), None);
    }

    #[test]
    fn path_regex_case_sensitivity() {
        let sensitive = CookieRewrite::parse(r"~^/regex/(.+)$", "/$1", false).unwrap();
        assert_eq!(
            sensitive.apply("/regex/test.html", false, &no_vars).as_deref(),
            Some("/test.html")
        );
        assert_eq!(sensitive.apply("/REGEX/test.html", false, &no_vars), None);

        let caseless = CookieRewrite::parse(r"~*^/caseless/(.+)$", "/$1", false).unwrap();
        assert_eq!(
            caseless.apply("/CASEless/test.html", false, &no_vars).as_deref(),
            Some("/test.html")
        );
    }

    #[test]
    fn pattern_variables_are_expanded() {
        let rw = CookieRewrite::parse(".$server_name.com", "en.$server_name.org", true).unwrap();
        let vars = |s: &str| s.replace("$server_name", "localhost");
        assert_eq!(
            rw.apply(".LocalHost.com", true, &vars).as_deref(),
            Some(".en.localhost.org")
        );

        let p = CookieRewrite::parse("/$server_name/", "/new/$server_name/", false).unwrap();
        assert_eq!(
            p.apply("/localhost/test.html", false, &vars).as_deref(),
            Some("/new/localhost/test.html")
        );
    }

    #[test]
    fn rewrites_only_the_named_attribute() {
        let domains = vec![CookieRewrite::parse("www.example.org", ".example.com", true).unwrap()];
        let paths = vec![CookieRewrite::parse("/path/", "/new/", false).unwrap()];
        let head = b"Set-Cookie: v=1; Domain=www.example.org; Path=/path/x\r\n";
        let out = rewrite_set_cookie(head, &domains, &paths, &no_vars);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Set-Cookie: v=1; Domain=example.com; Path=/new/x\r\n"
        );
    }
}
