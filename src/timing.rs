//! Per-request upstream attempt timings: `$upstream_connect_time`,
//! `$upstream_header_time` and `$upstream_response_time`.
//!
//! nginx keeps a list of attempts (`u->state` chained through
//! `u->state->next`) and prints them comma-separated, with `-` for a value the
//! attempt never reached. A retried request therefore reads like `0.001, 0.000`
//! and a failed first attempt shows `-` for its header time. The values are
//! evaluated at header-send time, so the attempt answering the request still
//! has no response time -- which is exactly what `proxy.t` asserts.
//!
//! The list lives in a task-local because a request is served entirely inside
//! one connection task, and the value is needed both deep in the proxy code and
//! in the access logger with no shared plumbing between them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Default, Debug)]
pub struct Attempt {
    pub connect: Option<f64>,
    pub header: Option<f64>,
    pub response: Option<f64>,
}

tokio::task_local! {
    static ATTEMPTS: Arc<Mutex<Vec<Attempt>>>;
}

pub fn new_state() -> Arc<Mutex<Vec<Attempt>>> {
    Arc::new(Mutex::new(Vec::new()))
}

/// Run `f` with a fresh attempt list for the request it serves.
pub async fn scope<F: std::future::Future>(state: Arc<Mutex<Vec<Attempt>>>, f: F) -> F::Output {
    ATTEMPTS.scope(state, f).await
}

fn with<R>(f: impl FnOnce(&mut Vec<Attempt>) -> R) -> Option<R> {
    ATTEMPTS
        .try_with(|s| {
            let mut list = s.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut list)
        })
        .ok()
}

/// Forget the previous request's attempts (keepalive reuses the task).
pub fn reset() {
    with(|list| list.clear());
}

/// Start a new attempt and return its index.
pub fn begin() -> usize {
    with(|list| {
        list.push(Attempt::default());
        list.len() - 1
    })
    .unwrap_or(0)
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

pub fn set_connect(idx: usize, d: Duration) {
    with(|list| {
        if let Some(a) = list.get_mut(idx) {
            a.connect = Some(secs(d));
        }
    });
}

pub fn set_header(idx: usize, d: Duration) {
    with(|list| {
        if let Some(a) = list.get_mut(idx) {
            a.header = Some(secs(d));
        }
    });
}

pub fn set_response(idx: usize, d: Duration) {
    with(|list| {
        if let Some(a) = list.get_mut(idx) {
            a.response = Some(secs(d));
        }
    });
}

/// nginx prints seconds with millisecond resolution, and `-` for a value that
/// was never set.
fn render(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.3}"),
        None => "-".to_string(),
    }
}

/// `$upstream_connect_time` / `$upstream_header_time` / `$upstream_response_time`
/// for every attempt so far, comma-separated. Empty when nothing was attempted.
pub fn variable(name: &str) -> Option<String> {
    let list = with(|l| l.clone())?;
    if list.is_empty() {
        return None;
    }
    let pick = |a: &Attempt| match name {
        "upstream_connect_time" => a.connect,
        "upstream_header_time" => a.header,
        "upstream_response_time" => a.response,
        _ => None,
    };
    Some(
        list.iter()
            .map(|a| render(pick(a)))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Replace every `$upstream_*_time` in `spec`. Unknown variables are left for
/// the caller's other expanders.
pub fn expand(spec: &str) -> String {
    if !spec.contains("$upstream_") {
        return spec.to_string();
    }
    let mut out = spec.to_string();
    for name in [
        "upstream_connect_time",
        "upstream_header_time",
        "upstream_response_time",
    ] {
        let needle = format!("${name}");
        if out.contains(&needle) {
            if let Some(v) = variable(name) {
                out = out.replace(&needle, &v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attempts_render_comma_separated_with_dashes() {
        let st = new_state();
        scope(st, async {
            let a = begin();
            set_connect(a, Duration::from_millis(1));
            set_response(a, Duration::from_millis(1100));
            let b = begin();
            set_connect(b, Duration::ZERO);
            set_header(b, Duration::ZERO);
            assert_eq!(variable("upstream_connect_time").unwrap(), "0.001, 0.000");
            assert_eq!(variable("upstream_header_time").unwrap(), "-, 0.000");
            assert_eq!(variable("upstream_response_time").unwrap(), "1.100, -");
        })
        .await;
    }

    #[tokio::test]
    async fn expand_replaces_only_known_names() {
        let st = new_state();
        scope(st, async {
            let a = begin();
            set_header(a, Duration::from_millis(250));
            assert_eq!(expand("h=$upstream_header_time z=$zone"), "h=0.250 z=$zone");
        })
        .await;
    }
}
