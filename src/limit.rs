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

/// nginx keeps the bucket state in milli-requests: 1000 is one request, and
/// `rate` is milli-requests per second. Working in the same units matters --
/// the delay a request receives is `(excess - delay * 1000) / rate`, which only
/// matches nginx's timings when nothing is rounded early.
#[derive(Clone, Copy)]
pub struct Node {
    /// Time of the last accounted request.
    pub last: Instant,
    /// Excess in milli-requests. A fresh node starts at -1000 so the first
    /// request lands exactly on 0 (`ngx_http_limit_req_lookup`).
    pub excess: i64,
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
    /// Returns `None` when the request must be rejected, otherwise how long
    /// nginx would hold it before answering (`Some(ZERO)` = answer now).
    ///
    /// `nodelay` answers immediately for anything within `burst`; `delay=N`
    /// answers the first N excess requests immediately and delays the rest.
    pub fn account(
        &self,
        key: &str,
        burst: u32,
        nodelay: bool,
        delay: Option<u32>,
    ) -> Option<Duration> {
        let now = Instant::now();
        let per_sec = self.rate * 1000.0; // milli-requests per second
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let node = nodes.entry(key.to_string()).or_insert(Node {
            last: now,
            excess: -1000,
        });

        let ms = now.saturating_duration_since(node.last).as_millis() as i64;
        let mut excess = node.excess - (per_sec * ms as f64 / 1000.0) as i64 + 1000;
        if excess < 0 {
            excess = 0;
        }
        if excess > burst as i64 * 1000 {
            // Rejected requests are not accounted (nginx returns NGX_BUSY
            // before storing the new excess).
            return None;
        }
        node.excess = excess;
        node.last = now;

        if nodelay {
            return Some(Duration::ZERO);
        }
        let threshold = delay.unwrap_or(0) as i64 * 1000;
        if excess > threshold && per_sec > 0.0 {
            let secs = (excess - threshold) as f64 / per_sec;
            return Some(Duration::from_secs_f64(secs));
        }
        Some(Duration::ZERO)
    }
}

/// One `limit_conn_zone`.
pub struct ConnZone {
    /// `$key` -> the slots currently held, each tied to the client connection
    /// that owns it. The descriptor lets a *later* request notice that a
    /// holder's client has gone away and reclaim the slot on the spot.
    pub slots: Mutex<HashMap<String, Vec<Slot>>>,
}

/// One held `limit_conn` slot.
#[derive(Clone, Copy)]
pub struct Slot {
    pub id: u64,
    /// Client socket of the request holding the slot (`None` when the caller
    /// could not supply one, e.g. TLS).
    pub fd: Option<std::os::unix::io::RawFd>,
}

impl ConnZone {
    pub fn new() -> Self {
        ConnZone {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Try to take a slot. Returns a guard that releases it on drop.
    ///
    /// When the limit is reached, holders whose client has already closed are
    /// reclaimed first. nginx learns about the close from epoll and releases
    /// immediately (`ngx_http_limit_conn_cleanup`); without shared memory we
    /// only see it from this side, so the check is done where it is decided.
    pub fn acquire(
        self: &std::sync::Arc<Self>,
        key: &str,
        limit: u32,
        fd: Option<std::os::unix::io::RawFd>,
    ) -> Option<ConnGuard> {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        // nginx replaces the key when it is empty (no accounting at all).
        if key.is_empty() {
            return Some(ConnGuard {
                zone: self.clone(),
                key: String::new(),
                id: 0,
                counted: false,
            });
        }
        let list = slots.entry(key.to_string()).or_default();
        if list.len() as u32 >= limit {
            let before = list.len();
            list.retain(|s| match s.fd {
                Some(fd) => !peer_gone(fd),
                None => true,
            });
            if list.len() == before || list.len() as u32 >= limit {
                return None;
            }
        }
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        list.push(Slot { id, fd });
        Some(ConnGuard {
            zone: self.clone(),
            key: key.to_string(),
            id,
            counted: true,
        })
    }
}

/// Has the peer of `fd` closed? `recv(MSG_PEEK)` reports end-of-stream without
/// consuming data and behaves the same on Linux and macOS.
fn peer_gone(fd: std::os::unix::io::RawFd) -> bool {
    let mut b = [0u8; 1];
    let n = unsafe {
        libc::recv(
            fd,
            b.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    n == 0 || (n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock)
}

impl Default for ConnZone {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConnGuard {
    zone: std::sync::Arc<ConnZone>,
    key: String,
    id: u64,
    counted: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut slots = self.zone.slots.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = slots.get_mut(&self.key) {
            list.retain(|s| s.id != self.id);
            if list.is_empty() {
                slots.remove(&self.key);
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
        assert!(z.account("k", 1, true, None).is_some());
        assert!(z.account("k", 1, true, None).is_some());
        assert!(z.account("k", 1, true, None).is_none());
    }

    #[test]
    fn leaked_slot_is_reusable() {
        let z = ReqZone::new(100.0); // 10 ms interval
        assert!(z.account("k", 1, true, None).is_some());
        assert!(z.account("k", 1, true, None).is_some());
        assert!(z.account("k", 1, true, None).is_none());
        std::thread::sleep(Duration::from_millis(30));
        assert!(z.account("k", 1, true, None).is_some());
    }

    #[test]
    fn delay_one_allows_the_second_request_immediately() {
        // Measured against nginx 1.28 with `rate=30r/m delay=1 burst=2`:
        // requests 1 and 2 answer at once, requests 3 and 4 wait one interval
        // each (2 s), and nothing is rejected.
        let z = ReqZone::new(0.5);
        assert_eq!(z.account("k", 2, false, Some(1)), Some(Duration::ZERO));
        assert_eq!(z.account("k", 2, false, Some(1)), Some(Duration::ZERO));
        let d = z.account("k", 2, false, Some(1)).unwrap();
        assert!(
            d.abs_diff(Duration::from_secs(2)) < Duration::from_millis(50),
            "{d:?}"
        );
    }

    #[test]
    fn without_delay_every_excess_request_waits_one_interval() {
        let z = ReqZone::new(0.5);
        assert_eq!(z.account("k", 2, false, None), Some(Duration::ZERO));
        let d = z.account("k", 2, false, None).unwrap();
        assert!(
            d.abs_diff(Duration::from_secs(2)) < Duration::from_millis(50),
            "{d:?}"
        );
    }

    #[test]
    fn nodelay_never_waits_and_burst_is_inclusive() {
        // nginx answers burst+1 requests to an idle bucket, then rejects.
        let z = ReqZone::new(0.5);
        for _ in 0..3 {
            assert_eq!(z.account("k", 2, true, None), Some(Duration::ZERO));
        }
        assert_eq!(z.account("k", 2, true, None), None);
    }

    #[test]
    fn conn_limit_counts_and_releases() {
        let z = std::sync::Arc::new(ConnZone::new());
        let g1 = z.acquire("k", 2, None);
        assert!(g1.is_some());
        let g2 = z.acquire("k", 2, None);
        assert!(g2.is_some());
        assert!(z.acquire("k", 2, None).is_none());
        drop(g1);
        assert!(z.acquire("k", 2, None).is_some());
    }

    #[test]
    fn closed_client_frees_its_slot() {
        use std::os::unix::io::AsRawFd;
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let z = std::sync::Arc::new(ConnZone::new());
        let g = z.acquire("k", 1, Some(a.as_raw_fd())).unwrap();
        assert!(z.acquire("k", 1, None).is_none());
        // The holder's client goes away; the next request reclaims the slot
        // the way nginx does when epoll reports the close.
        drop(b);
        assert!(z.acquire("k", 1, None).is_some());
        drop(g);
    }
}
