//! `ngx_http_charset_filter_module`.
//!
//! nginx keeps no built-in conversion tables: a charset is just a *name*, and
//! the only mappings that exist are the ones a `charset_map` block declares.
//! That is why `charset koi8-r; source_charset windows-1251;` without a matching
//! `charset_map` appends nothing -- `charsets[source].tables[charset]` is null
//! and the filter bails at `no_charset_map`
//! (`ngx_http_charset_filter_module.c`).

use std::collections::HashMap;

/// A registered charset. `utf8` decides how the mapping table is laid out.
#[derive(Debug, Clone, Default)]
pub struct Charset {
    pub name: String,
    pub utf8: bool,
    /// Average bytes per character, nginx's `charset->length`; used only to
    /// size the output buffer.
    pub length: usize,
}

/// One `charset_map`.
///
/// `src2dst` mirrors nginx's layout:
///   * destination not utf-8: 256 bytes, `src2dst[byte]` is the output byte;
///   * destination utf-8: 256 slots of [`UTF_LEN`] bytes, prefixed by a length.
#[derive(Debug, Clone)]
pub struct Map {
    pub src: usize,
    pub dst: usize,
    pub src2dst: Vec<u8>,
    /// Reverse direction. nginx keeps both arrays per declared table and
    /// registers them as `tables[src][dst] = src2dst` **and**
    /// `tables[dst][src] = dst2src` (`ngx_http_charset_postconfiguration`), so
    /// one `charset_map B A` serves B->A and A->B.
    ///
    /// For a single-byte destination this is 256 bytes; for a utf-8 source it is
    /// a two-level table indexed by the decoded code point.
    pub dst2src: Vec<u8>,
    pub dst2src_hi: Vec<[u8; 256]>,
    /// Reverse direction of a utf-8 map needs the code-point table above.
    pub dst2src_utf8: bool,
}

/// nginx's `NGX_UTF_LEN` (4 encoded bytes plus the length prefix).
pub const UTF_LEN: usize = 8;

/// Char sets, tables and lookups -- nginx's `ngx_http_charset_main_conf_t`.
#[derive(Debug, Clone, Default)]
pub struct Charsets {
    pub names: Vec<Charset>,
    pub maps: Vec<Map>,
}

impl Charsets {
    /// Index of `name`, registering it if needed (`ngx_http_get_charset`).
    pub fn get_or_add(&mut self, name: &str) -> usize {
        if let Some(i) = self
            .names
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
        {
            return i;
        }
        let utf8 = name.eq_ignore_ascii_case("utf-8");
        self.names.push(Charset {
            name: name.to_string(),
            utf8,
            // nginx starts at 0 and accumulates from the declared pairs.
            length: if utf8 { 4 } else { 0 },
        });
        self.names.len() - 1
    }

    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.names
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// The table between two charsets, if a `charset_map` declared one.
    pub fn table(&self, src: usize, dst: usize) -> Option<&Map> {
        self.maps.iter().find(|m| m.src == src && m.dst == dst)
    }
}

/// Parse a `charset_map <src> <dst> { ... }` body into a [`Map`].
///
/// `pairs` are `(src_hex, dst_hex)` as written; the destination side may be
/// several bytes when it is utf-8 (`58 59;` maps X to Y, `41 0410;` maps A to
/// U+0410).
pub fn build_map(src: usize, dst: usize, src_utf8: bool, dst_utf8: bool) -> Map {
    let _ = src_utf8;
    if dst_utf8 {
        let mut src2dst = vec![0u8; 256 * UTF_LEN];
        for i in 0..128usize {
            src2dst[i * UTF_LEN] = 1;
            src2dst[i * UTF_LEN + 1] = i as u8;
        }
        for i in 128..256usize {
            src2dst[i * UTF_LEN] = 1;
            src2dst[i * UTF_LEN + 1] = b'?';
        }
        Map {
            src,
            dst,
            src2dst,
            // utf-8 -> single byte: keyed by the decoded code point, so the
            // table is grown on demand by `add_pair`.
            dst2src: Vec::new(),
            dst2src_hi: Vec::new(),
            dst2src_utf8: true,
        }
    } else {
        // Single-byte destination: identity below 0x80, `?` above. nginx does
        // the same, so a byte with no declared mapping still comes out.
        let mut src2dst = vec![0u8; 256];
        for (i, slot) in src2dst.iter_mut().enumerate() {
            *slot = if i < 128 { i as u8 } else { b'?' };
        }
        let mut dst2src = vec![0u8; 256];
        for (i, slot) in dst2src.iter_mut().enumerate() {
            *slot = if i < 128 { i as u8 } else { b'?' };
        }
        Map {
            src,
            dst,
            src2dst,
            dst2src,
            dst2src_hi: Vec::new(),
            dst2src_utf8: false,
        }
    }
}

/// Apply one `58 59;` pair.
pub fn add_pair(map: &mut Map, dst_utf8: bool, src: u8, value: &[u8], charset_len: &mut usize) {
    if dst_utf8 {
        let at = src as usize * UTF_LEN;
        let n = value.len().min(UTF_LEN - 1);
        map.src2dst[at] = n as u8;
        map.src2dst[at + 1..at + 1 + n].copy_from_slice(&value[..n]);
        // Reverse table, indexed by the decoded code point.
        if let Some(cp) = decode_utf8(value) {
            let hi = (cp >> 8) as usize;
            let lo = (cp & 0xff) as usize;
            while map.dst2src_hi.len() <= hi {
                map.dst2src_hi.push([0xFFu8; 256]);
            }
            map.dst2src_hi[hi][lo] = src;
        }
        *charset_len += n;
    } else {
        let to = value.first().copied().unwrap_or(b'?');
        map.src2dst[src as usize] = to;
        // nginx mirrors the pair into the reverse table.
        map.dst2src[to as usize] = src;
        *charset_len += 1;
    }
}

fn decode_utf8(bytes: &[u8]) -> Option<u32> {
    match bytes.len() {
        1 if bytes[0] < 0x80 => Some(bytes[0] as u32),
        2 => Some((((bytes[0] & 0x1f) as u32) << 6) | (bytes[1] & 0x3f) as u32),
        3 => Some(
            (((bytes[0] & 0x0f) as u32) << 12)
                | (((bytes[1] & 0x3f) as u32) << 6)
                | (bytes[2] & 0x3f) as u32,
        ),
        4 => Some(
            (((bytes[0] & 0x07) as u32) << 18)
                | (((bytes[1] & 0x3f) as u32) << 12)
                | (((bytes[2] & 0x3f) as u32) << 6)
                | (bytes[3] & 0x3f) as u32,
        ),
        _ => None,
    }
}

/// Recode `body` through `map`.
///
/// `reverse` selects nginx's `dst2src` array, which is registered as the table
/// for the opposite pair (`ngx_http_charset_postconfiguration`).
pub fn recode(body: &[u8], map: &Map, src_utf8: bool, dst_utf8: bool, reverse: bool) -> Vec<u8> {
    if reverse {
        return if map.dst2src_utf8 {
            // utf-8 -> single byte, keyed by the decoded code point.
            let mut out = Vec::with_capacity(body.len());
            let mut i = 0;
            while i < body.len() {
                let b = body[i];
                if b < 0x80 {
                    out.push(b);
                    i += 1;
                    continue;
                }
                let n = match b {
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    0xF0..=0xF7 => 4,
                    _ => {
                        out.push(b'?');
                        i += 1;
                        continue;
                    }
                };
                if i + n > body.len() {
                    out.push(b'?');
                    break;
                }
                match decode_utf8(&body[i..i + n]) {
                    Some(cp) => {
                        let hi = (cp >> 8) as usize;
                        let lo = (cp & 0xff) as usize;
                        let m = map.dst2src_hi.get(hi).map(|row| row[lo]).unwrap_or(0xFF);
                        out.push(if m == 0xFF { b'?' } else { m });
                    }
                    None => out.push(b'?'),
                }
                i += n;
            }
            out
        } else {
            body.iter()
                .map(|&b| *map.dst2src.get(b as usize).unwrap_or(&b'?'))
                .collect()
        };
    }
    if dst_utf8 && !src_utf8 {
        // Single byte -> utf-8.
        let mut out = Vec::with_capacity(body.len() * 2);
        for &b in body {
            let at = b as usize * UTF_LEN;
            let n = map.src2dst[at] as usize;
            out.extend_from_slice(&map.src2dst[at + 1..at + 1 + n]);
        }
        return out;
    }
    if !dst_utf8 && src_utf8 {
        // utf-8 -> single byte through the declared reverse table.
        let mut out = Vec::with_capacity(body.len());
        let mut i = 0;
        while i < body.len() {
            let b = body[i];
            if b < 0x80 {
                out.push(b);
                i += 1;
                continue;
            }
            let n = match b {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => {
                    out.push(b'?');
                    i += 1;
                    continue;
                }
            };
            if i + n > body.len() {
                out.push(b'?');
                break;
            }
            match decode_utf8(&body[i..i + n]) {
                Some(cp) => {
                    let hi = (cp >> 8) as usize;
                    let lo = (cp & 0xff) as usize;
                    let m = map.dst2src_hi.get(hi).map(|row| row[lo]).unwrap_or(0xFF);
                    out.push(if m == 0xFF { b'?' } else { m });
                }
                None => out.push(b'?'),
            }
            i += n;
        }
        return out;
    }
    // Same width: a straight table lookup.
    body.iter().map(|&b| map.src2dst[b as usize]).collect()
}

/// `charset_map` blocks keyed by their two names, for the config parser.
#[derive(Debug, Clone, Default)]
pub struct MapDefs {
    /// `(src, dst)` lower-cased pair -> declared pairs.
    pub defs: HashMap<(String, String), Vec<(u8, Vec<u8>)>>,
    /// Declaration order, because nginx rejects a duplicate pair either way.
    pub order: Vec<(String, String)>,
}

/// nginx's default `charset_types`.
pub const DEFAULT_TYPES: &[&str] = &[
    "text/html",
    "text/xml",
    "text/plain",
    "text/vnd.wap.wml",
    "application/javascript",
    "application/rss+xml",
];

/// The outcome of the charset header filter for one response.
pub enum Decision {
    /// Append nothing and recode nothing.
    Skip,
    /// Declare this charset, no body change.
    Declare(String),
    /// Declare this charset and recode the body through `map`.
    Recode(String, Map, bool),
}

/// `ngx_http_charset_header_filter`, in nginx's own order.
///
/// The order is the whole point: a response that needs recoding but already has
/// a `Content-Encoding` is left completely alone -- no charset is appended --
/// which is what `charset_gzip_static.t`'s "recode gzip" asserts. A response
/// whose source charset is `off` gets the charset appended regardless.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    set: &Charsets,
    content_type: &str,
    has_encoding: bool,
    dest: &crate::config::CharsetSpec,
    source: &crate::config::CharsetSpec,
    types: Option<&[String]>,
    override_charset: bool,
    var: impl Fn(&str) -> Option<String>,
) -> Decision {
    use crate::config::CharsetSpec;

    if content_type.is_empty() {
        return Decision::Skip;
    }

    // The media type without parameters, and the charset it already declares.
    let (media, declared) = split_content_type(content_type);

    // `ngx_http_destination_charset`.
    let dest_name = match dest {
        CharsetSpec::Off => return Decision::Skip,
        CharsetSpec::Name(n) => n.clone(),
        CharsetSpec::Var(v) => match var(v) {
            Some(n) if !n.is_empty() => n,
            _ => return Decision::Skip,
        },
    };
    if declared.is_some() && !override_charset {
        return Decision::Skip;
    }
    if declared.is_none() {
        let allowed = match types {
            Some(list) if list.len() == 1 && list[0] == "*" => true,
            Some(list) => list.iter().any(|t| t.eq_ignore_ascii_case(media)),
            None => DEFAULT_TYPES.iter().any(|t| t.eq_ignore_ascii_case(media)),
        };
        if !allowed {
            return Decision::Skip;
        }
    }

    // `ngx_http_source_charset`: a charset the response already carries wins
    // over `source_charset`.
    let source_name = match declared {
        Some(c) => Some(c),
        None => match source {
            CharsetSpec::Off => None,
            CharsetSpec::Name(n) => Some(n.clone()),
            CharsetSpec::Var(v) => var(v).filter(|n| !n.is_empty()),
        },
    };

    let dest_idx = set.index_of(&dest_name);
    let Some(dest_idx) = dest_idx else {
        // `charset foo` with no `charset_map` mentioning it: nginx registers the
        // name but has no table, so this is the `no_charset_map` path.
        return match source_name {
            None => Decision::Declare(dest_name),
            Some(src) if src.eq_ignore_ascii_case(&dest_name) => Decision::Declare(dest_name),
            Some(_) => Decision::Skip,
        };
    };

    let Some(src_name) = source_name else {
        // `source_charset off`: declare and stop, encoding or not.
        return Decision::Declare(dest_name);
    };
    let src_idx = set.index_of(&src_name);

    if src_name.eq_ignore_ascii_case(&dest_name) {
        return Decision::Declare(dest_name);
    }

    // "source_charset != charset": an encoded body cannot be recoded.
    if has_encoding {
        return Decision::Skip;
    }

    let Some(si) = src_idx else {
        return Decision::Skip;
    };
    let clone = |m: &Map| Map {
        src: m.src,
        dst: m.dst,
        src2dst: m.src2dst.clone(),
        dst2src: m.dst2src.clone(),
        dst2src_hi: m.dst2src_hi.clone(),
        dst2src_utf8: m.dst2src_utf8,
    };
    // nginx registers one declared table under both `(src, dst)` and
    // `(dst, src)`, so a single `charset_map B A` serves both directions.
    if let Some(m) = set.table(si, dest_idx) {
        return Decision::Recode(dest_name, clone(m), false);
    }
    if let Some(m) = set.table(dest_idx, si) {
        return Decision::Recode(dest_name, clone(m), true);
    }
    // No `charset_map` between them.
    Decision::Skip
}

/// `text/html; charset=utf-8` -> (`text/html`, Some("utf-8")).
pub fn split_content_type(ct: &str) -> (&str, Option<String>) {
    let media = ct.split(';').next().unwrap_or("").trim();
    let mut charset = None;
    for part in ct.split(';').skip(1) {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("charset=") {
            charset = Some(v.trim_matches('"').to_string());
        } else if part.to_ascii_lowercase().starts_with("charset=") {
            charset = Some(part[8..].trim_matches('"').to_string());
        }
    }
    (media, charset)
}
