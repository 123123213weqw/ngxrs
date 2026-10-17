//! `map {}` — build a variable from another variable by pattern matching.
//!
//! Semantics follow `ngx_http_map_module`: source value is looked up in the
//! map, first *exact* match wins, then the longest wildcard, then regexes in
//! declaration order, then `default`.

/// One entry of a `map {}` block.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Raw left-hand side as written in the config.
    pub key: String,
    pub value: String,
}

/// A parsed `map $source $result { ... }` block.
#[derive(Debug, Clone)]
pub struct MapDef {
    pub source: String,
    pub var: String,
    /// `hostnames;`: case-insensitive, trailing dot ignored, wildcards active.
    pub hostnames: bool,
    pub volatile: bool,
    pub default: Option<String>,
    pub entries: Vec<Entry>,
}

impl MapDef {
    /// Evaluate the map for `input` (the expanded `$source`).
    ///
    /// Returns the matched value template (variables are expanded by the
    /// caller, so chained maps keep working).
    pub fn lookup(&self, input: &str) -> Option<&str> {
        if self.hostnames {
            return self.lookup_hostnames(input);
        }
        // Plain map: exact (case-sensitive) first, then regexes.
        for e in &self.entries {
            if e.key.starts_with('~') {
                continue;
            }
            if e.key == input {
                return Some(&e.value);
            }
        }
        for e in &self.entries {
            if let Some(re) = compile_regex(&e.key) {
                if re.is_match(input) {
                    return Some(&e.value);
                }
            }
        }
        self.default.as_deref()
    }

    fn lookup_hostnames(&self, input: &str) -> Option<&str> {
        let needle = normalize_host(input);

        // 1. Exact match wins outright.
        for e in &self.entries {
            if e.key.starts_with('~') || e.key.contains('*') || e.key.starts_with('.') {
                continue;
            }
            if normalize_host(&e.key) == needle {
                return Some(&e.value);
            }
        }

        // 2. Wildcards: the longest matching key wins.
        let mut best: Option<(usize, &str)> = None;
        for e in &self.entries {
            if e.key.starts_with('~') {
                continue;
            }
            let Some(suffix_len) = wildcard_suffix_len(&e.key, &needle) else {
                continue;
            };
            if best.map_or(true, |(len, _)| suffix_len > len) {
                best = Some((suffix_len, &e.value));
            }
        }
        if let Some((_, v)) = best {
            return Some(v);
        }

        // 3. Regexes in declaration order. nginx matches them against the
        // original value, not the lowercased host, so `~` stays case-sensitive.
        let raw = input.trim_end_matches('.');
        for e in &self.entries {
            if let Some(re) = compile_regex(&e.key) {
                if re.is_match(raw) {
                    return Some(&e.value);
                }
            }
        }
        self.default.as_deref()
    }
}

/// Lowercase and drop a single trailing dot.
pub fn normalize_host(s: &str) -> String {
    let s = s.trim_end_matches('.');
    s.to_ascii_lowercase()
}

/// How specifically `key` matches `needle`, if it does.
fn wildcard_suffix_len(key: &str, needle: &str) -> Option<usize> {
    let key = normalize_host(key);

    if let Some(rest) = key.strip_prefix("*.") {
        // `*.example.com`: one or more labels in front.
        let suffix = format!(".{rest}");
        if needle.ends_with(&suffix) && needle.len() > suffix.len() {
            return Some(key.len());
        }
        return None;
    }
    if let Some(rest) = key.strip_prefix('.') {
        // `.example.com`: the bare name *or* any subdomain.
        if needle == rest || needle.ends_with(&format!(".{rest}")) {
            return Some(key.len());
        }
        return None;
    }
    if let Some(rest) = key.strip_suffix(".*") {
        // `example.*`: prefix match.
        if needle.starts_with(rest) && needle.len() > rest.len() {
            return Some(key.len());
        }
        return None;
    }
    None
}

fn compile_regex(key: &str) -> Option<regex::Regex> {
    let (pat, ci) = if let Some(p) = key.strip_prefix("~*") {
        (p.trim(), true)
    } else if let Some(p) = key.strip_prefix('~') {
        (p.trim(), false)
    } else {
        return None;
    };
    let pat = if ci { format!("(?i){pat}") } else { pat.to_string() };
    regex::Regex::new(&pat).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(hostnames: bool, entries: &[(&str, &str)], default: &str) -> MapDef {
        MapDef {
            source: "$args".into(),
            var: "$y".into(),
            hostnames,
            volatile: false,
            default: Some(default.to_string()),
            entries: entries
                .iter()
                .map(|(k, v)| Entry {
                    key: k.to_string(),
                    value: v.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn plain_exact_and_default() {
        let m = map(false, &[("foo", "bar"), ("foo2", "bar")], "0");
        assert_eq!(m.lookup("foo"), Some("bar"));
        assert_eq!(m.lookup("nope"), Some("0"));
    }

    #[test]
    fn hostnames_wildcards_and_case() {
        let m = map(
            true,
            &[
                ("example.com", "foo"),
                ("example.*", "right"),
                ("*.example.com", "left"),
                (".dot.example.com", "special"),
                (r"~^REGEX\.EXAMPLE\.ORG$", "regex"),
                (r"~*^www.regex.example\.org$", "regexi"),
            ],
            "0",
        );
        assert_eq!(m.lookup("example.com"), Some("foo"));
        assert_eq!(m.lookup("EXAMPLE.COM"), Some("foo"));
        assert_eq!(m.lookup("example.com."), Some("foo"));
        assert_eq!(m.lookup("example.org"), Some("right"));
        assert_eq!(m.lookup("foo.example.com"), Some("left"));
        assert_eq!(m.lookup("foo.example.com."), Some("left"));
        assert_eq!(m.lookup("dot.example.com"), Some("special"));
        assert_eq!(m.lookup("www.dot.example.com"), Some("special"));
        assert_eq!(m.lookup("REGEX.EXAMPLE.ORG"), Some("regex"));
        assert_eq!(m.lookup("regex.example.org"), Some("0"));
        assert_eq!(m.lookup("www.regex.example.org"), Some("regexi"));
        assert_eq!(m.lookup("WWW.REGEX.EXAMPLE.ORG"), Some("regexi"));
    }
}
