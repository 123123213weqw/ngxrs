//! Buffered access-log writer.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// nginx's severity ordering: `debug` is the lowest, `emerg` the highest.
/// A sink configured with level L receives every message with severity >= L.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Crit,
    Alert,
    Emerg,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "debug" => Level::Debug,
            "info" => Level::Info,
            "notice" => Level::Notice,
            "warn" => Level::Warn,
            "error" => Level::Error,
            "crit" => Level::Crit,
            "alert" => Level::Alert,
            "emerg" => Level::Emerg,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Notice => "notice",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::Crit => "crit",
            Level::Alert => "alert",
            Level::Emerg => "emerg",
        }
    }

    /// syslog severity: emerg=0 ... debug=7 (the reverse of nginx's ordering).
    fn syslog_severity(self) -> u8 {
        match self {
            Level::Emerg => 0,
            Level::Alert => 1,
            Level::Crit => 2,
            Level::Error => 3,
            Level::Warn => 4,
            Level::Notice => 5,
            Level::Info => 6,
            Level::Debug => 7,
        }
    }
}

/// Where one `error_log` destination writes.
pub enum Dest {
    File(std::sync::Mutex<std::fs::File>),
    Stderr,
    /// `syslog:server=host:port[,facility=...,tag=...]`.
    Syslog {
        socket: std::sync::Mutex<std::net::UdpSocket>,
        facility: u8,
        tag: String,
    },
}

/// One `error_log <dest> <level>` destination.
pub struct Sink {
    level: Level,
    dest: Dest,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.dest {
            Dest::File(_) => "file",
            Dest::Stderr => "stderr",
            Dest::Syslog { .. } => "syslog",
        };
        write!(f, "Sink({kind}, {:?})", self.level)
    }
}

impl Sink {
    pub fn file(path: &Path, level: Level) -> std::io::Result<Arc<Sink>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Arc::new(Sink {
            level,
            dest: Dest::File(std::sync::Mutex::new(f)),
        }))
    }

    pub fn stderr(level: Level) -> Arc<Sink> {
        Arc::new(Sink {
            level,
            dest: Dest::Stderr,
        })
    }

    pub fn syslog(
        addr: std::net::SocketAddr,
        facility: u8,
        tag: String,
        level: Level,
    ) -> std::io::Result<Arc<Sink>> {
        // Bind an ephemeral local port; the connect() makes send() cheap.
        let bind: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.connect(addr)?;
        Ok(Arc::new(Sink {
            level,
            dest: Dest::Syslog {
                socket: std::sync::Mutex::new(socket),
                facility,
                tag,
            },
        }))
    }

    pub fn level(&self) -> Level {
        self.level
    }

    fn write(&self, level: Level, msg: &str) {
        if level < self.level {
            return;
        }
        let (stamp, mon, mday, hms) = now_parts();
        let pid = std::process::id();
        let line = format!("{stamp} [{}] {pid}#{pid}: {msg}", level.name());
        match &self.dest {
            Dest::File(f) => {
                if let Ok(mut f) = f.lock() {
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }
            }
            Dest::Stderr => {
                eprintln!("{line}");
            }
            Dest::Syslog {
                socket,
                facility,
                tag,
            } => {
                let pri = (facility & 0x07) * 8 + level.syslog_severity();
                // RFC 3164. nginx repeats the full error line after the tag,
                // which is why the syslog body carries the same `[level]`
                // token as the file destinations.
                let host = crate::config::typed::hostname().to_ascii_lowercase();
                let packet = format!("<{pri}>{mon} {mday} {hms} {host} {tag}: {line}");
                if let Ok(s) = socket.lock() {
                    let _ = s.send(packet.as_bytes());
                }
            }
        }
    }
}

/// `(YYYY/MM/DD HH:MM:SS, Mon, DD, HH:MM:SS)` in local time.
fn now_parts() -> (String, String, String, String) {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    let mon = MONTHS[tm.tm_mon.clamp(0, 11) as usize];
    // syslog pads a single-digit day with a space, not a zero.
    let stamp = format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );
    let mday = format!("{:2}", tm.tm_mday);
    let hms = format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec);
    (stamp, mon.to_string(), mday, hms)
}

static GLOBAL: std::sync::OnceLock<std::sync::Mutex<Vec<Arc<Sink>>>> = std::sync::OnceLock::new();

fn global() -> &'static std::sync::Mutex<Vec<Arc<Sink>>> {
    GLOBAL.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Install the sinks that belong to the configuration's main context.
pub fn set_global(sinks: Vec<Arc<Sink>>) {
    if let Ok(mut g) = global().lock() {
        *g = sinks;
    }
}

/// Make a copy of the main-context sinks so a server can inherit them.
pub fn global_sinks() -> Vec<Arc<Sink>> {
    global().lock().map(|g| g.clone()).unwrap_or_default()
}

pub fn log_global(level: Level, msg: &str) {
    if let Ok(g) = global().lock() {
        for sink in g.iter() {
            sink.write(level, msg);
        }
    }
}

/// Write to an explicit set of sinks (a `server {}` that has its own
/// `error_log`, which in nginx *adds* to — not replaces — the inherited ones).
pub fn log_to(sinks: &[Arc<Sink>], level: Level, msg: &str) {
    for sink in sinks {
        sink.write(level, msg);
    }
}

static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<Sink>>>> =
    std::sync::OnceLock::new();

/// Open (once) the sink described by an `error_log` directive.
///
/// Location-level directives are only known after routing, and opening the file
/// on every request would be wasteful, so sinks are cached by destination and
/// level. A destination appearing twice in the config still produces the same
/// shared sink — the *caller* writes once per configured directive, which is
/// what makes a duplicate `error_log` emit two lines.
pub fn sink_cached(dest: &str, level: Level) -> Option<Arc<Sink>> {
    let key = format!("{dest}\x00{}", level.name());
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Ok(c) = cache.lock() {
        if let Some(s) = c.get(&key) {
            return Some(s.clone());
        }
    }
    let sink = if dest == "stderr" {
        Sink::stderr(level)
    } else if let Some(rest) = dest.strip_prefix("syslog:") {
        crate::config::typed::open_syslog_pub(rest, level)?
    } else {
        Sink::file(Path::new(dest), level).ok()?
    };
    if let Ok(mut c) = cache.lock() {
        c.insert(key, sink.clone());
    }
    Some(sink)
}

/// Compatibility wrapper for the call sites that only know a level name.
pub fn error_log(level: &str, msg: &str) {
    let lv = Level::parse(level).unwrap_or(Level::Error);
    log_global(lv, msg);
}

pub struct Logger {
    tx: Option<Sender<Record>>,
    handle: Option<JoinHandle<()>>,
}

/// One line to append, with the `open_log_file_cache` in force for it.
pub struct Record {
    pub path: PathBuf,
    pub line: String,
    pub cache: crate::config::OpenFileCache,
}

/// One entry of `open_log_file_cache`.
struct Cached {
    writer: Option<BufWriter<File>>,
    created: Instant,
    last_used: Instant,
    /// How often this path has been logged, for `min_uses`.
    uses: u32,
    /// This log's `inactive`, so the sweep does not need a global policy.
    inactive: Duration,
}

impl Logger {
    pub fn new() -> std::io::Result<Self> {
        let (tx, rx) = channel::<Record>();
        let handle = std::thread::Builder::new()
            .name("ngxrs-log".to_string())
            .spawn(move || {
                let mut files: HashMap<PathBuf, Cached> = HashMap::new();
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(Record { path, line, cache }) => {
                            append_line(&mut files, &path, &line, cache);
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            for w in files.values_mut() {
                                if let Some(b) = w.writer.as_mut() {
                                    let _ = b.flush();
                                }
                            }
                            // `inactive`: an entry unused for that long is
                            // dropped, closing its handle.
                            files.retain(|_, e| e.last_used.elapsed() < e.inactive);
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                for w in files.values_mut() {
                    if let Some(b) = w.writer.as_mut() {
                        let _ = b.flush();
                    }
                }
            })?;
        Ok(Logger {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    pub fn access(&self, path: &Path, line: String) {
        self.access_cached(path, line, crate::config::OpenFileCache::default());
    }

    /// Append with an explicit `open_log_file_cache` policy.
    pub fn access_cached(
        &self,
        path: &Path,
        line: String,
        cache: crate::config::OpenFileCache,
    ) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Record {
                path: path.to_path_buf(),
                line,
                cache,
            });
        }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Append one log line, honouring `open_log_file_cache`.
///
/// The observable rules, all three of which `access_log.t` pins down by renaming
/// a directory out from under the log files:
///
///   * a handle that is cached and still within `valid` keeps receiving lines
///     even after the path disappears -- the writes go to the inode;
///   * a path logged fewer than `min_uses` times is opened and closed per line,
///     so it breaks the moment the path is gone;
///   * `max` bounds the number of *entries*, so a fourth path evicts the
///     least-recently-used one and its lines then fail the same way.
fn append_line(
    files: &mut HashMap<PathBuf, Cached>,
    path: &Path,
    line: &str,
    cache: crate::config::OpenFileCache,
) {
    let now = Instant::now();
    if cache.max == 0 {
        // `open_log_file_cache off`: every line opens and closes the file, which
        // is also what nginx does without the directive.
        if let Some(mut f) = open_log(path) {
            let _ = f.write_all(line.as_bytes());
            let _ = f.write_all(b"\n");
            let _ = f.flush();
        }
        return;
    }

    if let Some(e) = files.get_mut(path) {
        e.uses += 1;
        e.last_used = now;
        let still_valid = now.duration_since(e.created) < cache.valid;
        if let Some(w) = e.writer.as_mut().filter(|_| still_valid) {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            return;
        }
        // Either the entry never kept a handle (`min_uses` not reached) or its
        // validity expired: reopen by path. A failure drops the line.
        e.writer = None;
        if let Some(f) = open_log(path) {
            let mut w = BufWriter::with_capacity(64 * 1024, f);
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            if e.uses >= cache.min_uses {
                e.writer = Some(w);
                e.created = now;
            } else {
                let _ = w.flush();
            }
        }
        return;
    }

    // First line for this path.
    let mut entry = Cached {
        writer: None,
        created: now,
        last_used: now,
        uses: 1,
        inactive: cache.inactive,
    };
    if let Some(f) = open_log(path) {
        let mut w = BufWriter::with_capacity(64 * 1024, f);
        let _ = w.write_all(line.as_bytes());
        let _ = w.write_all(b"\n");
        if entry.uses >= cache.min_uses {
            entry.writer = Some(w);
        } else {
            let _ = w.flush();
        }
    }
    files.insert(path.to_path_buf(), entry);

    // Evict least-recently-used entries beyond `max`.
    while files.len() > cache.max {
        let Some(oldest) = files
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(p, _)| p.clone())
        else {
            break;
        };
        if let Some(mut e) = files.remove(&oldest) {
            if let Some(b) = e.writer.as_mut() {
                let _ = b.flush();
            }
        }
    }
}

fn open_log(path: &Path) -> Option<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}
