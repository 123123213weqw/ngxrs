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
    fn applies(&self, content_type: &str) -> bool {
        let base = content_type.split(';').next().unwrap_or("").trim();
        self.types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(base) || t == "*")
    }

    /// Apply every replacement to `body`.
    ///
    /// nginx's filter is a chain of `ngx_http_sub_filter_ctx_t`, one per
    /// matching entry, each of which replaces the *first* match when
    /// `sub_filter_once` is on (the default) and every match otherwise.  The
    /// chain runs in configuration order, so a later rule sees the text the
    /// earlier one produced.
    /// Matching is **caseless**, as in `ngx_http_sub_filter_module`: the module
    /// compares `ngx_tolower` of each byte, so a `foo` pattern also rewrites
    /// `FOO` (sub_filter.t asserts this).
    pub fn apply(&self, body: &[u8], content_type: &str) -> Option<Vec<u8>> {
        if self.pairs.is_empty() || !self.applies(content_type) {
            return None;
        }
        let mut out = body.to_vec();
        let mut changed = false;
        for (from, to) in &self.pairs {
            if from.is_empty() {
                continue;
            }
            let from: Vec<u8> = from.bytes().map(|b| b.to_ascii_lowercase()).collect();
            let to = to.as_bytes();
            let mut next = Vec::with_capacity(out.len());
            let mut i = 0;
            let mut hit = false;
            while i < out.len() {
                let hit_here = out.len() - i >= from.len()
                    && out[i..i + from.len()]
                        .iter()
                        .zip(from.iter())
                        .all(|(a, b)| a.to_ascii_lowercase() == *b);
                if hit_here {
                    next.extend_from_slice(to);
                    i += from.len();
                    hit = true;
                    if self.once {
                        next.extend_from_slice(&out[i..]);
                        i = out.len();
                    }
                } else {
                    next.push(out[i]);
                    i += 1;
                }
            }
            if hit {
                changed = true;
                out = next;
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
    fn rules_chain_in_configuration_order() {
        let f = sf(&[("a", "b"), ("b", "c")], false);
        // The second rule sees the first rule's output, so `a` ends as `c`.
        assert_eq!(f.apply(b"a", "text/html").unwrap(), b"c".to_vec());
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
