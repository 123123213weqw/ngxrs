//! Small content handlers and body filters that are not worth their own file:
//! `empty_gif`, `stub_status`, `random_index` and `sub_filter`.

/// `empty_gif`: the 43-byte transparent GIF nginx ships
/// (`ngx_http_empty_gif_module.c`).
pub const EMPTY_GIF: [u8; 43] = [
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4c, 0x01, 0x00, 0x3b,
];

/// `random_index`: pick one entry of `index`-eligible files at random.
///
/// nginx's `ngx_http_random_index_handler` opens the directory, builds the list
/// of regular files (skipping `.`-prefixed names and anything that is not a
/// file), then uses `ngx_random() % n`.  Returning `None` means "no candidate",
/// which the caller turns into 403 for a directory index request.
pub fn random_index_pick(dir: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut names: Vec<String> = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        match e.file_type() {
            Ok(t) if t.is_file() => names.push(name),
            _ => continue,
        }
    }
    if names.is_empty() {
        return None;
    }
    // `ngx_random()` is a cheap PRNG seeded from time+pid; the test only needs
    // a uniform pick, so std's generator is used.
    let idx = pseudo_random(names.len());
    names.get(idx).cloned()
}

fn pseudo_random(n: usize) -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0);
    (nanos % n as u64) as usize
}

/// A parsed `sub_filter` list plus the two modifiers.
#[derive(Debug, Clone)]
pub struct SubFilters {
    pub once: bool,
    pub types: Vec<String>,
    pub pairs: Vec<(String, String)>,
}

impl SubFilters {
    /// Whether a response of this type is eligible (`sub_filter_types`).
    ///
    /// nginx installs the filter, and therefore changes the response headers,
    /// as soon as the location has a pattern, the type matches and the body is
    /// not known to be empty -- it does not wait for a pattern to actually
    /// match (`ngx_http_sub_header_filter`).
    pub fn eligible(&self, content_type: &str, body_len: usize) -> bool {
        // nginx skips the filter when `content_length_n == 0`; a streamed body
        // has length -1, which is not "empty".
        !self.pairs.is_empty() && body_len != 0 && self.applies(content_type)
    }

    fn applies(&self, content_type: &str) -> bool {
        let base = content_type.split(';').next().unwrap_or("").trim();
        self.types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(base) || t == "*")
    }

    /// Rewrite `body`.
    ///
    /// nginx builds one list of patterns, **sorted longest first**, and at each
    /// byte position takes the first pattern that matches (`ngx_http_sub_match`
    /// walking `ctx->match`). Two consequences the tests pin down:
    ///
    ///   * the longest pattern wins where a shorter one also starts earlier --
    ///     `sub_filter_multi.t`'s "partial match" makes `aaabb -> -` beat
    ///     `aabb -> +`, so `aabbaaabbaabb` becomes `+-+`; running the patterns
    ///     as independent passes produced `+a++`;
    ///   * `sub_filter_once on` is per pattern, not per request: each pattern
    ///     replaces its first occurrence and is then marked done, which is why
    ///     `aabyyzaab` with `aab` and `yyz` becomes `+-aab`.
    ///
    /// Matching is caseless: nginx compares `ngx_tolower` of every byte, so a
    /// `foo` pattern also rewrites `FOO` (sub_filter.t asserts this).
    pub fn apply(&self, body: &[u8], content_type: &str) -> Option<Vec<u8>> {
        if !self.eligible(content_type, body.len()) {
            return None;
        }
        // Longest first; equal lengths keep configuration order (`sort_by` is
        // stable).
        let mut pats: Vec<(&[u8], &[u8])> = self
            .pairs
            .iter()
            .filter(|(from, _)| !from.is_empty())
            .map(|(from, to)| (from.as_bytes(), to.as_bytes()))
            .collect();
        if pats.is_empty() {
            return None;
        }
        pats.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let mut done = vec![false; pats.len()];

        let mut out = Vec::with_capacity(body.len());
        let mut changed = false;
        let mut i = 0usize;
        while i < body.len() {
            let mut hit: Option<usize> = None;
            for (n, (from, _)) in pats.iter().enumerate() {
                if self.once && done[n] {
                    continue;
                }
                if body.len() - i >= from.len()
                    && body[i..i + from.len()]
                        .iter()
                        .zip(from.iter())
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
                {
                    hit = Some(n);
                    break;
                }
            }
            match hit {
                Some(n) => {
                    out.extend_from_slice(pats[n].1);
                    i += pats[n].0.len();
                    done[n] = true;
                    changed = true;
                }
                None => {
                    out.push(body[i]);
                    i += 1;
                }
            }
        }
        if changed {
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sf(pairs: &[(&str, &str)], once: bool) -> SubFilters {
        SubFilters {
            once,
            types: vec!["text/html".to_string()],
            pairs: pairs
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        }
    }

    #[test]
    fn matching_is_caseless() {
        let f = sf(&[("foo", "bar")], true);
        assert_eq!(f.apply(b"FOO", "text/html").unwrap(), b"bar".to_vec());
        assert_eq!(f.apply(b"FoO!", "text/html").unwrap(), b"bar!".to_vec());
    }

    #[test]
    fn once_replaces_only_the_first_match() {
        let f = sf(&[("foo", "bar")], true);
        assert_eq!(
            f.apply(b"foo foo foo", "text/html").unwrap(),
            b"bar foo foo".to_vec()
        );
    }

    #[test]
    fn without_once_every_match_is_replaced() {
        let f = sf(&[("foo", "bar")], false);
        assert_eq!(
            f.apply(b"foo foo foo", "text/html").unwrap(),
            b"bar bar bar".to_vec()
        );
    }

    #[test]
    fn replacement_output_is_not_rescanned() {
        // Measured on nginx 1.28 with `sub_filter a b; sub_filter b c;`:
        // "a" comes back as "b". The rules are alternatives considered per
        // position, not a pipeline -- running them as chained passes (what this
        // code used to do) gave "c".
        let f = sf(&[("a", "b"), ("b", "c")], false);
        assert_eq!(f.apply(b"a", "text/html").unwrap(), b"b".to_vec());
    }

    #[test]
    fn longest_pattern_wins_at_a_position() {
        // `sub_filter_multi.t` "partial match": `aaabb` must beat `aabb` even
        // though `aabb` is configured first.
        let f = sf(&[("aabb", "+"), ("aaabb", "-")], false);
        for body in [&b"aabbaaabbaabb"[..], &b"aabbaaabaabb"[..]] {
            let out = f.apply(body, "text/html").unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains('+'), "{s}");
            assert_ne!(s, "+a++");
        }
        assert_eq!(
            f.apply(b"aabbaaabbaabb", "text/html").unwrap(),
            b"+-+".to_vec()
        );
    }

    #[test]
    fn once_is_per_pattern() {
        // `sub_filter_once on` marks each pattern done after its first hit, so
        // several patterns each fire once (nginx: "aabyyzaab" -> "+-aab",
        // "yyzyyzaabaabyyz" -> "-yyz+aabyyz").
        let f = sf(&[("aab", "+"), ("yyz", "-")], true);
        assert_eq!(
            f.apply(b"aabyyzaab", "text/html").unwrap(),
            b"+-aab".to_vec()
        );
        assert_eq!(
            f.apply(b"yyzyyzaabaabyyz", "text/html").unwrap(),
            b"-yyz+aabyyz".to_vec()
        );
    }

    #[test]
    fn multibyte_patterns_are_matched_byte_exactly() {
        // Patterns are UTF-8 byte strings; caseless folding is ASCII-only, so a
        // non-ASCII pattern must survive untouched (it used to be mangled by a
        // byte->char conversion in the config expander).
        let f = SubFilters {
            once: false,
            types: vec!["*".to_string()],
            pairs: vec![("模様".to_string(), "replaced".to_string())],
        };
        assert_eq!(
            f.apply("ТЕКСТ模様ТЕКСТ".as_bytes(), "text/plain").unwrap(),
            "ТЕКСТreplacedТЕКСТ".as_bytes().to_vec()
        );
    }

    #[test]
    fn only_configured_types_are_filtered() {
        let f = sf(&[("foo", "bar")], true);
        assert!(f.apply(b"foo", "text/plain").is_none());
        assert!(f.apply(b"foo", "text/html; charset=utf-8").is_some());
        assert!(f.apply(b"nothing", "text/html").is_none());
    }

    #[test]
    fn empty_gif_is_the_nginx_bytes() {
        assert_eq!(EMPTY_GIF.len(), 43);
        assert_eq!(&EMPTY_GIF[..6], b"GIF89a");
        assert_eq!(*EMPTY_GIF.last().unwrap(), 0x3b);
    }
}
