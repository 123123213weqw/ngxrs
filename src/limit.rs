//! `limit_req` (leaky bucket) and `limit_conn` state.
//!
//! Both modules keep one shared table per `zone=NAME:SIZE`, exactly like nginx:
//! state is per worker in nginx, but our workers are threads in one process, so
//! a process-wide table is the natural equivalent.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One `limit_req_zone` / `limit_conn_zone`.
pub struct ReqZone {
    /// Requests per second.
    pub rate: f64,
    /// `$key` -> leaky-bucket state.
    pub nodes: Mutex<HashMap<String, Node>>,
}

#[derive(Clone, Copy)]
pub struct Node {
    /// Time the last permitted request was accounted for.
    pub last: Instant,
    /// Excess requests currently queued (0 .. burst).
    pub excess: u32,
}

impl ReqZone {
    pub fn new(rate: f64) -> Self {
        ReqZone {
            rate,
            nodes: Mutex::new(HashMap::new()),
        }
    }

    /// Account one request for `key`.
    ///
    /// Returns `None` when the request must be rejected, `Some(delay)` when it
    /// may proceed (`delay` is how long nginx would hold it).
    pub fn account(&self, key: &str, burst: u32, nodelay: bool) -> Option<Duration> {
        let now = Instant::now();
        let interval = if self.rate > 0.0 {
            Duration::from_secs_f64(1.0 / self.rate)
        } else {
            Duration::ZERO
        };
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let node = nodes.entry(key.to_string()).or_insert(Node {
            last: now,
            excess: 0,
        });

        // Leak: every interval that elapsed since `last` frees one slot.
        if !interval.is_zero() {
            let elapsed = now.saturating_duration_since(node.last);
            let leaked = (elapsed.as_nanos() / interval.as_nanos().max(1)) as u32;
            if leaked > 0 {
                node.excess = node.excess.saturating_sub(leaked);
                // `last` advances only by the intervals actually consumed.
                node.last += interval * leaked;
            }
        }

        // `burst=N` allows N requests *on top of* the base rate slot.
        if node.excess > burst {
            // Over the limit: nginx does not count rejected requests.
            return None;
        }
        node.excess += 1;

        if nodelay || node.excess == 1 {
            // The first request in a burst still occupies `interval`, so push
            // `last` forward to keep the bucket leaking correctly.
            if node.excess == 1 {
                let next = now + interval;
                if next > node.last {
                    node.last = next;
                }
            }
            return Some(Duration::ZERO);
        }

        // Delay this request until the bucket frees enough slots.
        let wait = interval * node.excess;
        Some(wait)
    }
}

/// One `limit_conn_zone`.
pub struct ConnZone {
    pub counts: Mutex<HashMap<String, u32>>,
}

impl ConnZone {
    pub fn new() -> Self {
        ConnZone {
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Try to take a slot. Returns a guard that releases it on drop.
    pub fn acquire(self: &std::sync::Arc<Self>, key: &str, limit: u32) -> Option<ConnGuard> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let c = counts.entry(key.to_string()).or_insert(0);
        // nginx replaces the key when it is empty (no accounting at all).
        if key.is_empty() {
            return Some(ConnGuard {
                zone: self.clone(),
                key: String::new(),
                counted: false,
            });
        }
        if *c >= limit {
            return None;
        }
        *c += 1;
        Some(ConnGuard {
            zone: self.clone(),
            key: key.to_string(),
            counted: true,
        })
    }
}

impl Default for ConnZone {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConnGuard {
    zone: std::sync::Arc<ConnZone>,
    key: String,
    counted: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut counts = self.zone.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = counts.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_reject() {
        let z = ReqZone::new(2.0); // 500 ms interval
                                   // burst=1 means one in flight plus one queued: two accepted.
        assert!(z.account("k", 1, true).is_some());
        assert!(z.account("k", 1, true).is_some());
        assert!(z.account("k", 1, true).is_none());
    }

    #[test]
    fn leaked_slot_is_reusable() {
        let z = ReqZone::new(100.0); // 10 ms interval
        assert!(z.account("k", 1, true).is_some());
        assert!(z.account("k", 1, true).is_some());
        assert!(z.account("k", 1, true).is_none());
        std::thread::sleep(Duration::from_millis(30));
        assert!(z.account("k", 1, true).is_some());
    }

    #[test]
    fn conn_limit_counts_and_releases() {
        let z = std::sync::Arc::new(ConnZone::new());
        let g1 = z.acquire("k", 2);
        assert!(g1.is_some());
        let g2 = z.acquire("k", 2);
        assert!(g2.is_some());
        assert!(z.acquire("k", 2).is_none());
        drop(g1);
        assert!(z.acquire("k", 2).is_some());
    }
}
