//! Opt-in per-request CPU profiler (`NGXRS_PROF=1`).
//!
//! `perf` is not usable on the benchmark host (`perf_event_paranoid=4`, no
//! root), and `/proc` counters only give whole-process totals. This measures
//! *thread* CPU time around specific regions instead, so a phase that burns
//! userspace CPU can be told apart from one that is merely blocked.
//!
//! `CLOCK_THREAD_CPUTIME_ID` excludes blocked time, which is what makes it the
//! right clock here: a `sendfile` that waits for the socket is not CPU.
//!
//! Cost is one `clock_gettime` per marker (~60 ns, it is a real syscall, unlike
//! the vDSO clocks) so this is only correct to use for measurement runs.
//! Everything is behind `enabled()`, which is a cached non-atomic load.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

pub const NBUCKETS: usize = 8;

pub const NAMES: [&str; NBUCKETS] = [
    "parse",    // read + parse the request head
    "route",    // URL/location resolution, rewrite, access phase
    "content",  // content handler (static file, proxy, ...)
    "write",    // response writing
    "finalize", // header assembly / filters / error_page
    "body",     // body production inside a content handler
    "other",    // anything else inside dispatch
    "idle",     // waiting for the next request
];

pub static BUCKET: [AtomicU64; NBUCKETS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub static REQUESTS: AtomicU64 = AtomicU64::new(0);

static ON: OnceLock<bool> = OnceLock::new();

#[inline]
pub fn enabled() -> bool {
    *ON.get_or_init(|| std::env::var_os("NGXRS_PROF").is_some())
}

/// Thread CPU time in nanoseconds.
#[inline]
pub fn now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec.
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[inline]
pub fn add(bucket: usize, ns: u64) {
    BUCKET[bucket].fetch_add(ns, Ordering::Relaxed);
}

/// Start a region. Returns 0 when profiling is off so the paired `record` is a
/// single predictable branch.
#[inline]
pub fn start() -> u64 {
    if enabled() {
        now()
    } else {
        0
    }
}

#[inline]
pub fn record(bucket: usize, started: u64) {
    if started != 0 {
        add(bucket, now().saturating_sub(started));
    }
}

/// `name=value` pairs, each in microseconds, plus the request count.
pub fn dump(reset: bool) -> String {
    let requests = REQUESTS.load(Ordering::Relaxed);
    let mut out = format!("requests {requests}\n");
    let mut total = 0u64;
    for (i, name) in NAMES.iter().enumerate() {
        let v = BUCKET[i].load(Ordering::Relaxed);
        total += v;
        let per = if requests > 0 {
            v as f64 / requests as f64 / 1000.0
        } else {
            0.0
        };
        out.push_str(&format!("{name} {per:.2}us\n"));
    }
    let per_total = if requests > 0 {
        total as f64 / requests as f64 / 1000.0
    } else {
        0.0
    };
    out.push_str(&format!("accounted {per_total:.2}us\n"));
    if reset {
        for b in BUCKET.iter() {
            b.store(0, Ordering::Relaxed);
        }
        REQUESTS.store(0, Ordering::Relaxed);
    }
    out
}
