//! `ngx_http_referer_module`: `valid_referers` and `$invalid_referer`.
//!
//! The matching order is nginx's (`ngx_http_referer_variable`):
//!
//! 1. an unconfigured module is always valid;
//! 2. a missing `Referer` is valid only with `none`;
//! 3. a value that is not `http://` / `https://` is valid only with `blocked`;
//! 4. the host part (up to `/` or `:`, lowercased) is looked up among the
//!    literal and wildcard names, and a name carrying a URI part additionally
//!    requires that prefix;
//! 5. `server_names` names are matched against the lowercased host;
//! 6. then the `~` regexes run against the whole reference *without* the
//!    scheme.
//!
//! `$invalid_referer` is `"1"` when invalid and empty otherwise — nginx sets
//! `ngx_http_variable_true_value` / `null_value`.

/// One `valid_referers` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefererRule {
    /// A literal name, `*.example.com` / `example.*` wildcard, or `name/uri`.
    Name { host: String, uri: Option<String> },
    /// `~regex`, matched case-insensitively against the scheme-less reference.
    Regex(String),
    /// `server_names`: this server's own names.
    ServerName(String),
    /// `server_names` entry that came from a regex `server_name`.
    ServerNameRegex(String),
}

#[derive(Debug, Clone, Default)]
pub struct ValidReferers {
    pub names: Vec<RefererRule>,
    pub no_referer: bool,
    pub blocked: bool,
}

impl ValidReferers {
    /// `valid_referers` with an already-parsed argument list.
    ///
    /// `server_names` expands to this server's names, so the caller passes them
    /// in; a regex name is recorded as `ServerNameRegex`.
    pub fn parse(args: &[String], server_names: &[String], server_regexes: &[String]) -> Self {
        let mut out = ValidReferers::default();
        for a in args {
            match a.as_str() {
                "none" => out.no_referer = true,
                "blocked" => out.blocked = true,
                "server_names" => {
                    for n in server_names {
                        if n.starts_with('~') {
                            continue;
                        }
                        out.names.push(RefererRule::ServerName(n.to_lowercase()));
                    }
                    for r in server_regexes {
                        out.names.push(RefererRule::ServerNameRegex(r.clone()));
                    }
                }
                other if other.starts_with('~') => {
                    out.names.push(RefererRule::Regex(other[1..].to_string()));
                }
                other => {
                    // nginx stores the host and, separately, the URI part of a
                    // `host/uri` entry (`ngx_http_referer_add` splits on the
                    // first `/`).
                    let lower = other.to_lowercase();
                    match lower.split_once('/') {
                        Some((host, uri)) => out.names.push(RefererRule::Name {
                            host: host.to_string(),
                            uri: Some(format!("/{uri}")),
                        }),
                        None => out.names.push(RefererRule::Name {
                            host: lower,
                            uri: None,
                        }),
                    }
                }
            }
        }
        out
    }

    /// `$invalid_referer`: `true` means the request is rejected.
    pub fn invalid(&self, referer: Option<&str>) -> bool {
        if self.names.is_empty() && !self.no_referer && !self.blocked {
            // Nothing configured: nginx jumps straight to `valid`.
            return false;
        }
        let Some(raw) = referer else {
            return !self.no_referer;
        };

        // nginx requires at least `sizeof("http://i.ru") - 1` bytes before it
        // will treat the value as a URL: `http://su` therefore falls through to
        // the `blocked` case rather than being parsed as a short host
        // (referer.t: "blocked short").
        if raw.len() < 12 {
            return !self.blocked;
        }
        let rest = if raw[..7].eq_ignore_ascii_case("http://") {
            &raw[7..]
        } else if raw[..8].eq_ignore_ascii_case("https://") {
            &raw[8..]
        } else {
            return !self.blocked;
        };

        // The host runs to the first `/` or `:`. nginx copies it into a 256-byte
        // buffer and jumps to `invalid` if it would overflow, so 256 is the
        // largest accepted host and a longer one is rejected outright — even
        // `~.*` must not rescue it (referer.t: "long hostname 257").
        let host_end = rest.find(['/', ':']).unwrap_or(rest.len());
        if host_end > 256 {
            return true;
        }
        let host = rest[..host_end].to_ascii_lowercase();
        let after_host = &rest[host_end..];

        for rule in &self.names {
            match rule {
                RefererRule::Name { host: want, uri } => {
                    if !wildcard_host_match(want, &host) {
                        continue;
                    }
                    let Some(uri) = uri else {
                        return false;
                    };
                    // nginx skips to the first `/` and compares the prefix.
                    let path = match after_host.find('/') {
                        Some(i) => &after_host[i..],
                        None => "",
                    };
                    if path.len() >= uri.len() && path.starts_with(uri.as_str()) {
                        return false;
                    }
                }
                RefererRule::ServerName(want) => {
                    if wildcard_host_match(want, &host) {
                        return false;
                    }
                }
                RefererRule::ServerNameRegex(re) => {
                    if regex_match(re, &host) {
                        return false;
                    }
                }
                RefererRule::Regex(re) => {
                    if regex_match(re, rest) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

/// nginx's wildcard semantics: `*.example.com` matches one or more leading
/// labels, `example.*` matches a trailing suffix, `*.` on both sides is allowed.
fn wildcard_host_match(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.example.com` needs at least one label before `example.com`.
        return host
            .strip_suffix(suffix)
            .map(|head| head.ends_with('.') && head.len() > 1)
            .unwrap_or(false);
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return host.starts_with(prefix) && host[prefix.len()..].starts_with('.');
    }
    pattern == host
}

/// Case-insensitive regex, as `valid_referers ~...` uses (`NGX_REGEX_CASELESS`
/// unless `(?-i)` overrides it).
fn regex_match(pattern: &str, haystack: &str) -> bool {
    // `valid_referers ~...` is caseless unless the pattern itself says
    // otherwise with `(?-i)`; `(?i)` is a flag the caller can turn off again.
    let translated = crate::config::typed::translate_pcre_public(pattern);
    let pat = format!("(?i:{translated})");
    match regex::Regex::new(&pat) {
        Ok(re) => re.is_match(haystack),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> ValidReferers {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        ValidReferers::parse(&owned, &[], &[])
    }

    #[test]
    fn unconfigured_module_accepts_everything() {
        assert!(!cfg(&[]).invalid(None));
        assert!(!cfg(&[]).invalid(Some("https://evil")));
    }

    #[test]
    fn none_allows_a_missing_referer() {
        assert!(cfg(&["www.example.org"]).invalid(None));
        assert!(!cfg(&["none", "www.example.org"]).invalid(None));
    }

    #[test]
    fn blocked_allows_a_non_http_referer() {
        assert!(cfg(&["www.example.org"]).invalid(Some("ftp://x/")));
        assert!(!cfg(&["blocked", "www.example.org"]).invalid(Some("ftp://x/")));
    }

    #[test]
    fn host_is_case_insensitive_and_stops_at_port_or_slash() {
        assert!(!cfg(&["www.example.org"]).invalid(Some("http://WWW.Example.ORG/x")));
        assert!(!cfg(&["www.example.org"]).invalid(Some("https://www.example.org:8080/")));
        assert!(cfg(&["www.example.org"]).invalid(Some("http://other.org/")));
    }

    #[test]
    fn uri_part_is_a_prefix() {
        // nginx compares only `uri->len` bytes, so a longer path still matches
        // (`referer.t`: "uri prefix" asserts www.example.org/urii is valid).
        let c = cfg(&["www.example.org/uri"]);
        assert!(!c.invalid(Some("http://www.example.org/uri")));
        assert!(!c.invalid(Some("http://www.example.org/urii")));
        // Too short, or differing inside the prefix: invalid.
        assert!(c.invalid(Some("http://www.example.org/ur")));
        assert!(c.invalid(Some("http://www.example.org/urd")));
        // A bare host has no path at all, so nothing can match.
        assert!(c.invalid(Some("http://www.example.org")));
    }

    #[test]
    fn wildcards_need_a_label() {
        let c = cfg(&["*.example.com", "www.example.*"]);
        assert!(!c.invalid(Some("http://a.example.com/")));
        assert!(!c.invalid(Some("http://a.b.example.com/")));
        // `example.com` alone is not `*.example.com`.
        assert!(c.invalid(Some("http://example.com/")));
        assert!(!c.invalid(Some("http://www.example.net/")));
    }

    #[test]
    fn regex_sees_the_scheme_less_value() {
        let c = cfg(&["~example.org"]);
        assert!(!c.invalid(Some("http://www.example.org/x")));
        // Anchored at the end: the path makes it fail.
        let c = cfg(&["~example.org$"]);
        assert!(c.invalid(Some("http://www.example.org/x")));
        assert!(!c.invalid(Some("http://www.example.org")));
    }
}
