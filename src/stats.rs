//! Connection counters behind `stub_status`.
//!
//! nginx's numbers come from the shared `ngx_stat_*` fields:
//!
//! * `accepts`  — `accept()` calls that succeeded;
//! * `handled`  — connections that got as far as a request;
//! * `requests` — HTTP requests received (pipelining counts each one);
//! * `active`   — open connections, i.e. `accepts - closed`;
//! * `reading`  — connections currently parsing a request header;
//! * `writing`  — connections currently writing a response;
//! * `waiting`  — `active - reading - writing`, the idle keepalive conns.
//!
//! The per-connection flags live in thread-locals. That is safe here because the
//! HTTP workers run a `new_current_thread` runtime: one task per thread, and a
//! task never migrates between worker threads.
//!
//! `reading` and `writing` are per-connection states that nginx flips as it
//! enters the read and write event handlers, so a connection is "waiting" only
//! while neither is true.  The counters are global here for the same reason they
//! are shared in nginx: `stub_status` reports the whole server, not one worker.

use std::sync::atomic::{AtomicU64, Ordering};

pub static ACCEPTS: AtomicU64 = AtomicU64::new(0);
pub static HANDLED: AtomicU64 = AtomicU64::new(0);
pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE: AtomicU64 = AtomicU64::new(0);
/// Connection serial number for `$connection`; nginx starts at 1.
pub static CONNECTION: AtomicU64 = AtomicU64::new(0);
pub static READING: AtomicU64 = AtomicU64::new(0);
pub static WRITING: AtomicU64 = AtomicU64::new(0);

pub fn debug_dump(tag: &str) {
    if std::env::var_os("NGXRS_STAT_DEBUG").is_some() {
        eprintln!(
            "{tag}: accepts={} active={} reading={} writing={} requests={}",
            ACCEPTS.load(Ordering::Relaxed),
            ACTIVE.load(Ordering::Relaxed),
            READING.load(Ordering::Relaxed),
            WRITING.load(Ordering::Relaxed),
            REQUESTS.load(Ordering::Relaxed),
        );
    }
}

pub fn accepted() -> u64 {
    ACCEPTS.fetch_add(1, Ordering::Relaxed);
    HANDLED.fetch_add(1, Ordering::Relaxed);
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    CONNECTION.fetch_add(1, Ordering::Relaxed) + 1
}

tokio::task_local! {
    /// `$connection` for the connection being served by this task.
    ///
    /// A task-local rather than a thread-local: several connections are served
    /// concurrently on one runtime thread, and a single slot is clobbered by
    /// whichever task runs last. That is invisible until a server proxies to
    /// itself in the same process, where the upstream's `$connection` then
    /// reports the *client* connection's number.
    static CONN_SERIAL: std::cell::Cell<u64>;
}

/// Run one connection's future with its serial bound.
pub fn scope_conn_serial<F>(n: u64, f: F) -> impl std::future::Future<Output = F::Output>
where
    F: std::future::Future,
{
    CONN_SERIAL.scope(std::cell::Cell::new(n), f)
}

/// `$connection` for the current connection (0 outside one).
pub fn conn_serial() -> u64 {
    CONN_SERIAL.try_with(|v| v.get()).unwrap_or(0)
}

pub fn closed() {
    // Saturating: a connection whose accept was never counted (e.g. a unix
    // socket accepted through another path) must not wrap `active`.
    let _ = ACTIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

/// A request line/header arrived: nginx counts it in `requests`
/// (`ngx_stat_requests`, bumped in `ngx_http_process_request_line`).
pub fn request_started() {
    REQUESTS.fetch_add(1, Ordering::Relaxed);
}

/// Bytes for a request have arrived but the header is not complete.
///
/// nginx increments `ngx_stat_reading` in the read handler once `recv` returns
/// data, so a client that connected but sent nothing counts as **waiting**, not
/// reading (`stub_status.t` asserts exactly that).
///
/// The flags are per *connection*, not per thread: one worker thread multiplexes
/// many connections, so a thread-local would let two clients share one flag.
pub fn reading_delta(on: bool) {
    if on {
        READING.fetch_add(1, Ordering::Relaxed);
    } else {
        let _ = READING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }
}

pub fn writing_delta(on: bool) {
    if on {
        WRITING.fetch_add(1, Ordering::Relaxed);
    } else {
        let _ = WRITING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }
}

/// Body of a `stub_status` response.
pub fn stub_status_body() -> String {
    let active = ACTIVE.load(Ordering::Relaxed);
    let reading = READING.load(Ordering::Relaxed);
    let writing = WRITING.load(Ordering::Relaxed);
    let waiting = active.saturating_sub(reading + writing);
    // nginx's format string, including the trailing space on each counter line.
    format!(
        "Active connections: {active} \n\
         server accepts handled requests\n {} {} {} \n\
         Reading: {reading} Writing: {writing} Waiting: {waiting} \n",
        ACCEPTS.load(Ordering::Relaxed),
        HANDLED.load(Ordering::Relaxed),
        REQUESTS.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_shape_matches_nginx() {
        let b = stub_status_body();
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 4, "{b:?}");
        assert!(lines[0].starts_with("Active connections: "), "{b:?}");
        assert_eq!(lines[1], "server accepts handled requests");
        assert!(
            lines[2].starts_with(' ') && lines[2].split(' ').filter(|p| !p.is_empty()).count() == 3,
            "{b:?}"
        );
        assert!(lines[2].ends_with(' '));
        assert!(lines[3].starts_with("Reading: "), "{b:?}");
        assert!(lines[3].contains(" Writing: ") && lines[3].contains(" Waiting: "));
        // Every counter line ends with a space, as nginx emits them.
        assert!(lines[0].ends_with(' '));
        assert!(lines[3].ends_with(' '));
    }

    #[test]
    fn waiting_is_active_minus_reading_and_writing() {
        // Uses the real atomics, so it only checks the arithmetic.
        let base_active = ACTIVE.load(Ordering::Relaxed);
        let base_reading = READING.load(Ordering::Relaxed);
        let base_writing = WRITING.load(Ordering::Relaxed);
        ACTIVE.store(5, Ordering::Relaxed);
        READING.store(1, Ordering::Relaxed);
        WRITING.store(2, Ordering::Relaxed);
        assert!(stub_status_body().contains("Waiting: 2 "));
        ACTIVE.store(base_active, Ordering::Relaxed);
        READING.store(base_reading, Ordering::Relaxed);
        WRITING.store(base_writing, Ordering::Relaxed);
    }
}
