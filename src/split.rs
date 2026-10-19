//! `split_clients`: deterministic bucketing of a variable into one of N values.
//!
//! Both `http` and `stream` use it, so this file holds the shared parts: the
//! hash and the bucket search.
//!
//! The percentages are turned into **cumulative** boundaries at configuration
//! time (`ngx_conf_split_clients_block`):
//!
//! ```text
//! last += percent * 0xffffffff / 10000;   // percent is percent*100
//! ```
//!
//! and then the first bucket whose boundary is above the hash wins, with a `*`
//! bucket (stored as 0) terminating the list.  Getting this wrong is easy and
//! silent: a non-cumulative comparison makes every bucket after the first
//! unreachable.

/// `ngx_murmur_hash2`, byte for byte (`src/core/ngx_murmurhash.c`).
///
/// This is *not* the well-known MurmurHash2 with a seed — nginx uses
/// `h = 0 ^ len` and a different tail, so an off-the-shelf crate would produce
/// different buckets.
pub fn murmur_hash2(data: &[u8]) -> u32 {
    let mut h: u32 = data.len() as u32;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        let mut k = c[0] as u32;
        k |= (c[1] as u32) << 8;
        k |= (c[2] as u32) << 16;
        k |= (c[3] as u32) << 24;
        k = k.wrapping_mul(0x5bd1_e995);
        k ^= k >> 24;
        k = k.wrapping_mul(0x5bd1_e995);
        h = h.wrapping_mul(0x5bd1_e995);
        h ^= k;
    }
    let tail = chunks.remainder();
    match tail.len() {
        3 => {
            h ^= (tail[2] as u32) << 16;
            h ^= (tail[1] as u32) << 8;
            h ^= tail[0] as u32;
            h = h.wrapping_mul(0x5bd1_e995);
        }
        2 => {
            h ^= (tail[1] as u32) << 8;
            h ^= tail[0] as u32;
            h = h.wrapping_mul(0x5bd1_e995);
        }
        1 => {
            h ^= tail[0] as u32;
            h = h.wrapping_mul(0x5bd1_e995);
        }
        _ => {}
    }
    h ^= h >> 13;
    h = h.wrapping_mul(0x5bd1_e995);
    h ^= h >> 15;
    h
}

/// One configured bucket. `bound` is the cumulative boundary; the `*` bucket
/// stores 0 and therefore always matches.
#[derive(Debug, Clone)]
pub struct Part {
    pub bound: u32,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct SplitClients {
    pub source: String,
    pub var: String,
    pub parts: Vec<Part>,
}

impl SplitClients {
    /// Build from `(percent_text, value)` pairs in configuration order.
    ///
    /// `percent_text` is `"51.2%"` or `"*"`.  Returns the error nginx reports
    /// when the percentages add up to more than 100.
    pub fn parse(source: &str, var: &str, entries: &[(String, String)]) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut sum: u32 = 0;
        let mut last: u64 = 0;
        for (pct, value) in entries {
            let p = if pct.trim() == "*" {
                0
            } else {
                let text = pct.trim().trim_end_matches('%');
                let scaled = parse_percent(text)?;
                sum = sum.saturating_add(scaled as u32);
                if sum > 10000 {
                    return Err("percent total is greater than 100%".to_string());
                }
                scaled
            };
            if p > 0 {
                // `last += part->percent * (uint64_t) 0xffffffff / 10000`
                last += p as u64 * 0xffff_ffffu64 / 10_000;
                parts.push(Part {
                    bound: last as u32,
                    value: value.clone(),
                });
            } else {
                // A `*` entry does not advance the boundary.
                parts.push(Part {
                    bound: 0,
                    value: value.clone(),
                });
            }
        }
        Ok(SplitClients {
            source: source.to_string(),
            var: var.to_string(),
            parts,
        })
    }

    /// Look the value up, exactly as `ngx_http_split_clients_variable` does.
    pub fn pick(&self, value: &str) -> Option<&str> {
        let hash = murmur_hash2(value.as_bytes());
        for p in &self.parts {
            if hash < p.bound || p.bound == 0 {
                return Some(p.value.as_str());
            }
        }
        None
    }
}

/// `ngx_atofp(text, len, 2)`: a decimal with at most two places, returned as
/// hundredths (`"51.2"` -> `5120`).
fn parse_percent(text: &str) -> Result<u64, String> {
    let (int_part, frac_part) = match text.split_once('.') {
        Some((a, b)) => (a, b),
        None => (text, ""),
    };
    if frac_part.len() > 2 {
        return Err(format!("invalid percent value \"{text}\""));
    }
    let int: u64 = int_part
        .parse()
        .map_err(|_| format!("invalid percent value \"{text}\""))?;
    let mut frac: u64 = if frac_part.is_empty() {
        0
    } else {
        frac_part
            .parse()
            .map_err(|_| format!("invalid percent value \"{text}\""))?
    };
    if frac_part.len() == 1 {
        frac *= 10;
    }
    Ok(int * 100 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur_matches_nginx() {
        // Ground truth: nginx 1.28's `ngx_murmur_hash2` compiled standalone and
        // run on these inputs on the V100.
        assert_eq!(murmur_hash2(b""), 0);
        assert_eq!(murmur_hash2(b"1"), 1_228_156_847);
        assert_eq!(murmur_hash2(b"2"), 772_897_149);
        assert_eq!(murmur_hash2(b"3"), 2_292_183_779);
        assert_eq!(murmur_hash2(b"127.0.0.1"), 3_054_706_065);
        assert_eq!(murmur_hash2(b"abc"), 324_500_635);
    }

    #[test]
    fn percent_scaling_is_hundredths() {
        assert_eq!(parse_percent("51.2").unwrap(), 5120);
        assert_eq!(parse_percent("10").unwrap(), 1000);
        assert_eq!(parse_percent("0.5").unwrap(), 50);
        assert_eq!(parse_percent("100").unwrap(), 10000);
        assert!(parse_percent("1.234").is_err());
    }

    #[test]
    fn boundaries_are_cumulative() {
        let e = vec![
            ("51.2%".to_string(), ".one".to_string()),
            ("10%".to_string(), ".two".to_string()),
            ("*".to_string(), ".three".to_string()),
        ];
        let sc = SplitClients::parse("$connection", "variant", &e).unwrap();
        assert_eq!(sc.parts[0].bound, (5120u64 * 0xffff_ffff / 10_000) as u32);
        // The second bucket is above the first, which is what makes it reachable.
        assert!(sc.parts[1].bound > sc.parts[0].bound);
        assert_eq!(sc.parts[2].bound, 0);
    }

    #[test]
    fn over_one_hundred_percent_is_an_error() {
        let e = vec![
            ("60%".to_string(), "a".to_string()),
            ("50%".to_string(), "b".to_string()),
        ];
        assert!(SplitClients::parse("$x", "v", &e).is_err());
    }

    #[test]
    fn each_hash_lands_in_exactly_one_bucket() {
        let e = vec![
            ("51.2%".to_string(), ".one".to_string()),
            ("10%".to_string(), ".two".to_string()),
            ("*".to_string(), ".three".to_string()),
        ];
        let sc = SplitClients::parse("$connection", "variant", &e).unwrap();
        for i in 0..2000u32 {
            let v = i.to_string();
            assert!(sc.pick(&v).is_some(), "no bucket for {v}");
        }
    }
}
