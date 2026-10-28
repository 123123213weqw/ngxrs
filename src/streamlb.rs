//! `ngx_stream_upstream_*` peer selection.
//!
//! Selection is stateful, exactly like nginx: `current_weight` and
//! `effective_weight` drive a smooth weighted round-robin, and `fails`/
//! `checked` implement `max_fails`/`fail_timeout`. A peer is skipped when it is
//! `down`, temporarily disabled by `max_fails`, or already at `max_conns`; when
//! every primary is skipped the `backup` pool is tried, and only then does the
//! connection fail (`NGX_BUSY`, which the proxy turns into a closed client
//! connection).

use std::sync::Mutex;

use crate::config::{LbMethod, UpstreamServer};

pub struct PeerSet {
    pub servers: Vec<UpstreamServer>,
    pub method: LbMethod,
    /// `hash <key>` template (empty for the other balancers).
    pub hash_key: String,
    /// Consistent-hash ring, sorted by hash with duplicates removed: the same
    /// shape `ngx_stream_upstream_update_chash` builds.
    pub chash: Vec<(u32, usize)>,
    /// Per-peer balancer state, guarded as a whole because one selection mutates
    /// several peers (nginx holds `peers->lock` for the same reason).
    state: Mutex<Vec<PeerState>>,
}

/// nginx's `ngx_stream_upstream_rr_peer_t` bookkeeping the balancer needs.
#[derive(Debug, Clone, Copy)]
struct PeerState {
    current: i64,
    effective: i64,
    fails: u32,
    checked: i64,
    conns: u32,
}

/// One live connection to `idx` of the set; the slot is released on drop.
pub struct Guard {
    set: std::sync::Arc<PeerSet>,
    pub idx: usize,
}

impl Guard {
    pub fn addr(&self) -> std::net::SocketAddr {
        self.set.addr(self.idx)
    }
    pub fn name(&self) -> &str {
        self.set.name(self.idx)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // The peer answered, which is nginx's "mark peer live" branch of
        // `free_round_robin_peer`: clear `fails` and restore the weight.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.set.release(self.idx, true, now);
    }
}

impl std::fmt::Debug for PeerSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSet")
            .field("servers", &self.servers.len())
            .field("method", &self.method)
            .finish()
    }
}

impl PeerSet {
    pub fn new(servers: Vec<UpstreamServer>, method: LbMethod, hash_key: String) -> std::sync::Arc<Self> {
        let chash = if matches!(method, LbMethod::Hash { consistent: true, .. }) {
            crate::config::typed::build_chash_points(&servers)
        } else {
            Vec::new()
        };
        let state = servers
            .iter()
            .map(|s| PeerState {
                current: 0,
                effective: i64::from(s.weight),
                fails: 0,
                checked: 0,
                conns: 0,
            })
            .collect();
        std::sync::Arc::new(PeerSet {
            servers,
            method,
            hash_key,
            chash,
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<PeerState>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Whether peer `i` may be selected right now (nginx's three `continue`s).
    fn usable(&self, st: &[PeerState], i: usize, now: i64) -> bool {
        let s = &self.servers[i];
        if s.down {
            return false;
        }
        if s.max_fails != 0
            && st[i].fails >= s.max_fails
            && now - st[i].checked <= s.fail_timeout.as_secs() as i64
        {
            return false;
        }
        if s.max_conns != 0 && st[i].conns >= s.max_conns {
            return false;
        }
        true
    }

    /// nginx's `get_*_peer`: one peer, or `None` when every candidate has been
    /// tried. `tried` is the per-connection bitmap (nginx's `rrp->tried`).
    pub fn pick(&self, tried: &mut [bool], key: Option<&str>, now: i64) -> Option<usize> {
        if let Some(i) = self.pick_pool(tried, key, now, false) {
            return Some(i);
        }
        // "backup servers": the backup pool starts with a clean `tried`, which
        // is what makes a backup reachable after every primary was rejected.
        if self.servers.iter().any(|s| s.backup) {
            for t in tried.iter_mut() {
                *t = false;
            }
            if let Some(i) = self.pick_pool(tried, key, now, true) {
                return Some(i);
            }
        }
        None
    }

    fn pick_pool(
        &self,
        tried: &mut [bool],
        key: Option<&str>,
        now: i64,
        backup: bool,
    ) -> Option<usize> {
        let mut st = self.lock();
        let pool: Vec<usize> = (0..self.servers.len())
            .filter(|&i| self.servers[i].backup == backup)
            .collect();
        // `peers->single`: a pool with exactly one peer takes it directly and
        // -- this is the part that is easy to get wrong -- **ignores
        // `max_fails` entirely**, checking only `down` and `max_conns`
        // (`ngx_stream_upstream_get_round_robin_peer`'s `peers->single`
        // branch). Honouring `max_fails` here leaves a single-peer group
        // stuck on its backup for `fail_timeout` after the peer comes back
        // ("recovery" in `stream_upstream.t` expects 30/30 on the primary).
        if pool.len() == 1 && !tried[pool[0]] {
            let i = pool[0];
            let s = &self.servers[i];
            if s.down || (s.max_conns != 0 && st[i].conns >= s.max_conns) {
                return None;
            }
            tried[i] = true;
            st[i].conns += 1;
            return Some(i);
        }

        let live: Vec<usize> = pool
            .iter()
            .copied()
            .filter(|&i| !tried[i] && self.usable(&st, i, now))
            .collect();
        if live.is_empty() {
            return None;
        }

        let chosen = match &self.method {
            LbMethod::Hash { consistent, .. } => {
                match key.filter(|k| !k.is_empty()).and_then(|k| {
                    if *consistent {
                        self.chash_start(k)
                    } else {
                        self.hash_start(k, &st)
                    }
                }) {
                    // nginx hashes, then rejects that peer only if it is
                    // unusable and rehashes; picking from the live set directly
                    // is the same thing for a single attempt.
                    Some(c) if live.contains(&c) => Some(c),
                    Some(_) => smooth(&self.servers, &mut st, &live),
                    // Empty key, one primary, or an empty ring: plain RR.
                    None => smooth(&self.servers, &mut st, &live),
                }
            }
            LbMethod::LeastConn => least_conn(&self.servers, &mut st, &live),
            LbMethod::RoundRobin | LbMethod::IpHash | LbMethod::Random { .. } => {
                smooth(&self.servers, &mut st, &live)
            }
        }?;

        tried[chosen] = true;
        st[chosen].conns += 1;
        if now - st[chosen].checked > self.servers[chosen].fail_timeout.as_secs() as i64 {
            st[chosen].checked = now;
        }
        Some(chosen)
    }

    /// `ngx_stream_upstream_free_round_robin_peer`.
    ///
    /// A failed attempt raises `fails`, cuts `effective_weight` by
    /// `weight / max_fails` and re-stamps `checked`, which is what disables the
    /// peer for `fail_timeout` once `fails >= max_fails`. A successful one
    /// clears `fails` if it happened after the last check.
    pub fn release(&self, idx: usize, ok: bool, now: i64) {
        let mut st = self.lock();
        if !ok {
            st[idx].fails += 1;
            st[idx].checked = now;
            if self.servers[idx].max_fails != 0 {
                let step = i64::from(self.servers[idx].weight)
                    / i64::from(self.servers[idx].max_fails);
                st[idx].effective -= step;
                if st[idx].effective < 0 {
                    st[idx].effective = 0;
                }
            }
        } else if st[idx].checked > 0 && st[idx].fails > 0 {
            // `accessed < checked` in nginx; here a success after the peer was
            // marked means it is live again.
            st[idx].fails = 0;
            st[idx].effective = i64::from(self.servers[idx].weight);
        }
        st[idx].conns = st[idx].conns.saturating_sub(1);
    }

    /// Hand a slot taken by [`pick`] to a guard that frees it when the session
    /// ends. `pick` already counted the connection, so this does not.
    pub fn guard(self: &std::sync::Arc<Self>, idx: usize) -> Guard {
        Guard {
            set: std::sync::Arc::clone(self),
            idx,
        }
    }

    pub fn addr(&self, idx: usize) -> std::net::SocketAddr {
        self.servers[idx].addr
    }

    pub fn name(&self, idx: usize) -> &str {
        &self.servers[idx].name
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// First peer of the *consistent* ring, or `None` when nginx would fall
    /// back to round-robin.
    ///
    /// `ngx_stream_upstream_init_chash_peer` hashes the key once with
    /// `ngx_crc32_long` and takes the first ring point at or after that hash.
    fn chash_start(&self, key: &str) -> Option<usize> {
        if key.is_empty() || self.chash.is_empty() {
            return None;
        }
        let h = crate::config::typed::crc32(key.as_bytes());
        let at = self.chash.partition_point(|&(p, _)| p < h);
        Some(self.chash[at % self.chash.len()].1)
    }

    /// First peer of the plain `hash` balancer, or `None` for round-robin.
    ///
    /// `ngx_stream_upstream_get_hash_peer` accumulates
    /// `((crc32([REHASH] KEY) >> 16) & 0x7fff)` into a running value and takes
    /// it modulo the total weight -- the Cache::Memcached expression. Hashing
    /// the key once, without the fold or the accumulation, picks a different
    /// peer ("hash" in `stream_upstream_hash.t`).
    fn hash_start(&self, key: &str, st: &[PeerState]) -> Option<usize> {
        if key.is_empty() {
            return None;
        }
        let configured = self.servers.iter().filter(|s| !s.backup).count();
        if configured < 2 {
            return None;
        }
        let total: u64 = self
            .servers
            .iter()
            .filter(|s| !s.backup)
            .map(|s| u64::from(s.weight))
            .sum();
        if total == 0 {
            return None;
        }
        let _ = st;
        let mut hash: u32 = 0;
        let mut rehash: u32 = 0;
        loop {
            if rehash > 100 {
                return None;
            }
            let mut crc = 0u32;
            if rehash > 0 {
                crc = crate::config::typed::crc32_update(crc, rehash.to_string().as_bytes());
            }
            crc = crate::config::typed::crc32_update(crc, key.as_bytes());
            hash = hash.wrapping_add((crc >> 16) & 0x7fff);
            rehash += 1;
            let mut w = u64::from(hash) % total;
            for (i, s) in self.servers.iter().enumerate() {
                if s.backup {
                    continue;
                }
                if w < u64::from(s.weight) {
                    return Some(i);
                }
                w -= u64::from(s.weight);
            }
        }
    }

    /// Display string for the `proxy to` log line.
    pub fn describe(&self) -> String {
        match self.servers.first() {
            Some(s) if self.servers.len() == 1 => s.addr.to_string(),
            Some(s) => format!("{} ({} peers)", s.name, self.servers.len()),
            None => "-".to_string(),
        }
    }
}

/// `ngx_stream_upstream_get_peer`: smooth weighted round-robin over `live`.
fn smooth(servers: &[UpstreamServer], st: &mut [PeerState], live: &[usize]) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut total: i64 = 0;
    for &i in live {
        st[i].current += st[i].effective;
        total += st[i].effective;
        if st[i].effective < i64::from(servers[i].weight) {
            st[i].effective += 1;
        }
        match best {
            Some(b) if st[b].current >= st[i].current => {}
            _ => best = Some(i),
        }
    }
    if let Some(b) = best {
        st[b].current -= total;
    }
    best
}

/// `ngx_stream_upstream_get_least_conn_peer`.
///
/// The comparison is `conns * other_weight` against `best_conns * weight`, so a
/// heavier peer is allowed proportionally more connections. Ties fall through to
/// a second pass that runs the smooth weighted round-robin over the tied peers.
fn least_conn(servers: &[UpstreamServer], st: &mut [PeerState], live: &[usize]) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut many = false;
    for &i in live {
        match best {
            None => {
                best = Some(i);
                many = false;
            }
            Some(b) => {
                let lhs = i64::from(st[i].conns) * i64::from(servers[b].weight);
                let rhs = i64::from(st[b].conns) * i64::from(servers[i].weight);
                if lhs < rhs {
                    best = Some(i);
                    many = false;
                } else if lhs == rhs {
                    many = true;
                }
            }
        }
    }
    let best = best?;
    if !many {
        return Some(best);
    }
    // nginx iterates from `best` to the end of the list, so only the tied peers
    // at or after `best` take part.
    let from = live.iter().position(|&i| i == best)?;
    let tied: Vec<usize> = live[from..]
        .iter()
        .copied()
        .filter(|&i| {
            i64::from(st[i].conns) * i64::from(servers[best].weight)
                == i64::from(st[best].conns) * i64::from(servers[i].weight)
        })
        .collect();
    smooth(servers, st, &tied).or(Some(best))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LbMethod;
    use std::time::Duration;

    fn peer(name: &str, weight: u32, max_conns: u32, backup: bool) -> UpstreamServer {
        UpstreamServer {
            addr: name.parse().unwrap(),
            weight,
            backup,
            down: false,
            name: name.to_string(),
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
            max_conns,
        }
    }

    fn set(servers: Vec<UpstreamServer>, method: LbMethod) -> std::sync::Arc<PeerSet> {
        PeerSet::new(servers, method, String::new())
    }

    /// `weight=2` takes twice the connections of `weight=1`: the whole point of
    /// the smooth weighted round-robin, and what `stream_upstream.t`'s "weight"
    /// assertion measures (10/20 over 30 connections).
    #[test]
    fn weights_are_honoured() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 2, 0, false),
            ],
            LbMethod::RoundRobin,
        );
        let mut counts = [0usize; 2];
        for _ in 0..30 {
            let mut tried = vec![false; 2];
            let i = s.pick(&mut tried, None, 0).expect("a peer");
            counts[i] += 1;
            s.release(i, true, 0);
        }
        assert_eq!(counts, [10, 20], "20/30 must go to the heavier peer");
    }

    /// A peer at `max_conns` is skipped for the next connection; when every
    /// primary is full the backup pool takes over, and when that is full too the
    /// connection fails (`NGX_BUSY`).
    #[test]
    fn max_conns_falls_through_to_backup() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 2, false),
                peer("127.0.0.1:2", 1, 3, true),
            ],
            LbMethod::RoundRobin,
        );
        let mut held = Vec::new();
        for _ in 0..5 {
            let mut tried = vec![false; 2];
            let i = s.pick(&mut tried, None, 0).expect("a peer");
            held.push(s.guard(i));
        }
        let addr: Vec<String> = held.iter().map(|g| g.addr().to_string()).collect();
        assert_eq!(
            addr,
            vec![
                "127.0.0.1:1",
                "127.0.0.1:1",
                "127.0.0.1:2",
                "127.0.0.1:2",
                "127.0.0.1:2"
            ],
            "two on the primary, then three on the backup"
        );
        let mut tried = vec![false; 2];
        assert!(s.pick(&mut tried, None, 0).is_none(), "all full -> NGX_BUSY");

        // Releasing a slot makes exactly that peer available again.
        held.pop();
        let mut tried = vec![false; 2];
        assert_eq!(s.pick(&mut tried, None, 0), Some(1));
    }

    /// A peer whose last attempt failed is skipped for `fail_timeout`, and comes
    /// back afterwards.
    #[test]
    fn max_fails_disables_then_recovers() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 1, 0, false),
            ],
            LbMethod::RoundRobin,
        );
        let mut tried = vec![false; 2];
        let first = s.pick(&mut tried, None, 100).expect("a peer");
        s.release(first, false, 100);
        // Same instant: the failed peer is out, so the other one is chosen.
        for _ in 0..4 {
            let mut tried = vec![false; 2];
            assert_eq!(s.pick(&mut tried, None, 101), Some(1 - first));
        }
        // After fail_timeout it is a candidate again.
        let mut tried = vec![false; 2];
        let mut seen = [false; 2];
        for _ in 0..4 {
            let mut t = vec![false; 2];
            if let Some(i) = s.pick(&mut t, None, 200) {
                seen[i] = true;
                s.release(i, true, 200);
            }
        }
        assert!(seen[first], "the peer must come back after fail_timeout");
        let _ = &mut tried;
    }

    /// A single-peer pool ignores `max_fails`, exactly like nginx's
    /// `peers->single` branch -- otherwise a group with one primary stays on its
    /// backup for a whole `fail_timeout` after the primary recovers.
    #[test]
    fn single_peer_pool_ignores_max_fails() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 1, 0, true),
            ],
            LbMethod::RoundRobin,
        );
        let mut tried = vec![false; 2];
        let i = s.pick(&mut tried, None, 100).expect("a peer");
        assert_eq!(i, 0);
        s.release(i, false, 100);
        // Still the primary, despite `fails >= max_fails` inside fail_timeout.
        let mut tried = vec![false; 2];
        assert_eq!(s.pick(&mut tried, None, 101), Some(0));
    }

    /// `least_conn` prefers the peer with fewer connections, comparing
    /// `conns * weight` so a heavier peer is allowed proportionally more.
    #[test]
    fn least_conn_prefers_the_idle_peer() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 1, 0, false),
            ],
            LbMethod::LeastConn,
        );
        let mut tried = vec![false; 2];
        let busy = s.pick(&mut tried, None, 0).expect("a peer");
        let guard = s.guard(busy);
        for _ in 0..4 {
            let mut tried = vec![false; 2];
            let i = s.pick(&mut tried, None, 0).expect("a peer");
            assert_ne!(i, busy, "the busy peer must not be chosen");
            s.release(i, true, 0);
        }
        drop(guard);
    }

    /// An empty `hash` key falls back to round-robin and really rotates
    /// (`stream_upstream_hash.t`, "empty key").
    #[test]
    fn empty_hash_key_round_robins() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 1, 0, false),
            ],
            LbMethod::Hash {
                key: "$proxy_protocol_addr".to_string(),
                consistent: false,
            },
        );
        let mut counts = [0usize; 2];
        for _ in 0..4 {
            let mut tried = vec![false; 2];
            let i = s.pick(&mut tried, Some(""), 0).expect("a peer");
            counts[i] += 1;
            s.release(i, true, 0);
        }
        assert_eq!(counts, [2, 2]);
    }

    /// A non-empty key pins every connection to the same peer, and the constant
    /// hash uses the folded Cache::Memcached expression.
    #[test]
    fn hash_key_is_stable() {
        let s = set(
            vec![
                peer("127.0.0.1:1", 1, 0, false),
                peer("127.0.0.1:2", 1, 0, false),
            ],
            LbMethod::Hash {
                key: "$remote_addr".to_string(),
                consistent: false,
            },
        );
        let first = {
            let mut tried = vec![false; 2];
            s.pick(&mut tried, Some("127.0.0.1"), 0).expect("a peer")
        };
        for _ in 0..9 {
            let mut tried = vec![false; 2];
            let i = s.pick(&mut tried, Some("127.0.0.1"), 0).expect("a peer");
            assert_eq!(i, first);
            s.release(i, true, 0);
        }
    }
}
