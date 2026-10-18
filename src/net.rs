//! Listener setup, accept loops and process lifecycle.
//!
//! Thread-per-core model: each worker owns its own SO_REUSEPORT listener and a
//! single-threaded runtime, so connections never migrate between cores (the
//! same shape as nginx's worker processes, without the fork/IPC).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::conn::{Conn, Stream};
use crate::http::{self, Ctx};
use crate::log::Logger;

/// Two accept strategies, chosen with NGXRS_ACCEPT=shared|reuseport.
/// - reuseport (default): every worker owns a SO_REUSEPORT socket. No locking,
///   but the kernel's 4-tuple hash can leave workers idle (measured: up to 20%
///   throughput loss with 1k connections).
/// - shared: one listener, one acceptor thread, round-robin handoff. Predictable
///   balance at the cost of one queue hop per connection.
fn accept_mode() -> &'static str {
    static MODE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    MODE.get_or_init(|| match std::env::var("NGXRS_ACCEPT").as_deref() {
        Ok("shared") => "shared",
        _ => "reuseport",
    })
}

/// Pipe used to tell the original process that the daemon wrote its pid file.
/// Without this handshake the parent can exit before the pid file exists, and
/// `nginx-tests` treats that as a failed start.
static READY_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

fn notify_parent_ready() {
    let fd = READY_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            let byte = [1u8];
            libc::write(fd, byte.as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }
}

/// nginx's `daemon on` default: fork, detach from the session, redirect the
/// standard descriptors, and let the parent exit once we are ready.
fn daemonize(pid_path: Option<&std::path::Path>, error_log: Option<&std::path::Path>) -> io::Result<()> {
    let mut fds = [0i32; 2];
    let have_pipe = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;

    unsafe {
        match libc::fork() {
            -1 => return Err(io::Error::last_os_error()),
            0 => {
                // child: keep going, close the read end
                if have_pipe {
                    libc::close(fds[0]);
                    READY_FD.store(fds[1], Ordering::SeqCst);
                }
            }
            _ => {
                // parent: wait for readiness so callers can rely on the pid file
                if have_pipe {
                    libc::close(fds[1]);
                    let mut byte = [0u8; 1];
                    libc::read(fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1);
                    libc::close(fds[0]);
                }
                std::process::exit(0);
            }
        }
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        // Second fork so the daemon can never reacquire a controlling tty.
        match libc::fork() {
            -1 => return Err(io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            if error_log.is_none() {
                libc::dup2(devnull, 2);
            }
            if devnull > 2 {
                libc::close(devnull);
            }
        }
        let _ = pid_path;
    }
    Ok(())
}

pub fn serve(cfg: Config) -> io::Result<()> {
    // `daemon on` is nginx's default and what the official test suite expects.
    if cfg.daemon && std::env::var_os("NGXRS_NO_DAEMON").is_none() {
        daemonize(cfg.pid.as_deref(), cfg.error_log.as_deref())?;
    }

    let workers = if cfg.worker_processes == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    } else {
        cfg.worker_processes
    }
    .max(1);

    // Install the main-context `error_log` sinks. Without explicit directives
    // nginx logs to `<prefix>/logs/error.log` at `error` level; we keep `info`
    // so nothing previously written is lost.
    {
        let mut sinks = crate::config::typed::open_sinks(&cfg.error_logs);
        if sinks.is_empty() {
            if let Some(path) = cfg.error_log.as_deref() {
                if let Ok(s) = crate::log::Sink::file(path, crate::log::Level::Info) {
                    sinks.push(s);
                }
            }
        }
        crate::log::set_global(sinks);
    }
    // nginx announces its build in the error log at `notice`.
    crate::log::log_global(crate::log::Level::Notice, "using the \"epoll\" event method");
    crate::log::log_global(
        crate::log::Level::Notice,
        &format!(
            "{ngxrs} (nginx/{ver} compatible)",
            ngxrs = crate::VERSION,
            ver = crate::COMPAT_VERSION
        ),
    );
    let logger = Arc::new(Logger::new()?);
    let cfg = Arc::new(cfg);

    // nginx writes the pid file only after its listening sockets exist, and
    // `nginx-tests` relies on that: the file appearing means "ready to serve".
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let pid_path = cfg.pid.clone();

    // Build one TLS config per listening socket that has `ssl` enabled.
    let mut tls_by_group: Vec<Option<Arc<rustls::ServerConfig>>> =
        Vec::with_capacity(cfg.http.groups.len());
    for group in &cfg.http.groups {
        if !group.ssl {
            tls_by_group.push(None);
            continue;
        }
        if !group.servers.iter().any(|&i| cfg.http.server(i).ssl_certificate.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no ssl_certificate configured for {}", group.addr),
            ));
        }
        match crate::tls::build_config(&cfg.http, &group.servers) {
            Ok(c) => tls_by_group.push(Some(c)),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("TLS setup for {} failed: {e}", group.addr),
                ))
            }
        }
    }

    let ctx = Arc::new(Ctx {
        config: std::sync::RwLock::new(cfg.clone()),
        logger,
        tls: Arc::new(tls_by_group),
    });
    let (shutdown_tx, _shutdown_rx_probe) = watch::channel(false);
    let shutdown_rx = _shutdown_rx_probe.clone();
    let stopping = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(workers + 1);
    let shared = accept_mode() == "shared";

    // A `mail {}`-only (or `stream {}`-only) config has no HTTP listeners at
    // all. Spawning HTTP workers for it makes worker 0 find zero sockets and
    // abort the process, so the HTTP side is skipped and the readiness
    // handshake completes immediately.
    let has_http = !cfg.http.groups.is_empty();

    if !has_http {
        let _ = ready_tx.send(());
    } else if shared {
        let mut senders = Vec::with_capacity(workers);
        let mut receivers = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel::<Handoff>(8192);
            senders.push(tx);
            receivers.push(rx);
        }
        let groups: Vec<SocketAddr> = cfg.http.groups.iter().map(|g| g.addr).collect();
        {
            let stopping = stopping.clone();
            let ready = ready_tx.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("ngxrs-accept".to_string())
                    .spawn(move || acceptor_main(&groups, senders, stopping, ready))?,
            );
        }
        for (wid, rx) in receivers.into_iter().enumerate() {
            let ctx = ctx.clone();
            let shutdown = shutdown_rx.clone();
            let stopping = stopping.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(format!("ngxrs-w{wid}"))
                    .spawn(move || shared_worker_main(wid, ctx, rx, shutdown, stopping))?,
            );
        }
    } else {
        for wid in 0..workers {
            let ctx = ctx.clone();
            let shutdown = shutdown_rx.clone();
            let stopping = stopping.clone();
            let ready = if wid == 0 { Some(ready_tx.clone()) } else { None };
            let handle = std::thread::Builder::new()
                .name(format!("ngxrs-w{wid}"))
                .spawn(move || worker_main(wid, ctx, shutdown, stopping, ready))?;
            threads.push(handle);
        }
    }

    crate::tls::init_crypto();

    // Resolve `stream {}` backends (names -> upstream blocks) once.
    let mut stream_cfg = crate::stream::StreamConfig {
        servers: Vec::new(),
    };
    for sc in &cfg.stream.servers {
        let mut backends = Vec::new();
        if let Some(pp) = &sc.proxy_pass {
            if let Some(up) = cfg.stream.upstreams.iter().find(|u| &u.name == pp) {
                backends = up.backends.clone();
            } else if let Some(addr) = parse_stream_addr(pp) {
                backends.push(addr);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("stream proxy_pass \"{pp}\" is neither an upstream nor host:port"),
                ));
            }
        }
        stream_cfg.servers.push(crate::stream::StreamServer {
            listen: sc.listen,
            udp: sc.udp,
            backends,
            proxy_timeout: sc.proxy_timeout,
            proxy_connect_timeout: sc.proxy_connect_timeout,
            sinks: crate::config::typed::open_sinks(&sc.error_logs),
        });
    }
    let stream_cfg = Arc::new(stream_cfg);
    let mut mail_servers = cfg.mail_servers.clone();
    // A mail `server {}` with its own `error_log` adds destinations; the file is
    // opened here, not during `-t`, so a config test creates nothing.
    for srv in &mut mail_servers {
        srv.sinks = crate::config::typed::open_sinks(&srv.error_logs);
    }
    crate::proxy::init(&cfg.http);
    crate::proxy::init_keepalive(&cfg.http);

    // Wait until the listeners exist (worker 0 signals after binding).
    let _ = ready_rx.recv_timeout(Duration::from_secs(10));

    if let Some(pid_path) = &pid_path {
        if let Some(parent) = pid_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pid_path, format!("{}\n", std::process::id()));
    }
    // The original process (daemon parent) is blocked waiting for this.
    notify_parent_ready();

    eprintln!(
        "ngxrs: started {workers} workers, prefix {}",
        cfg.prefix.display()
    );

    // nginx runs stream and http side by side; give stream its own thread.
    // The sender must stay alive for the lifetime of the process: dropping it
    // makes `changed()` return immediately and the listeners exit at once.
    let mut stream_thread = None;
    let mut stream_tx: Option<watch::Sender<bool>> = None;
    if !stream_cfg.is_empty() {
        let cfg = stream_cfg.clone();
        let (tx, rx) = watch::channel(false);
        stream_tx = Some(tx);
        stream_thread = Some(
            std::thread::Builder::new()
                .name("ngxrs-stream".to_string())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            eprintln!("ngxrs: stream runtime failed: {e}");
                            return;
                        }
                    };
                    rt.block_on(crate::stream::serve(cfg, rx));
                })?,
        );
    }

    // `mail {}` listeners get their own thread, like stream.
    let mut mail_thread = None;
    let mut mail_tx: Option<watch::Sender<bool>> = None;
    if !mail_servers.is_empty() {
        let servers = mail_servers.clone();
        let (tx, rx) = watch::channel(false);
        mail_tx = Some(tx);
        mail_thread = Some(
            std::thread::Builder::new()
                .name("ngxrs-mail".to_string())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            eprintln!("ngxrs: mail runtime failed: {e}");
                            return;
                        }
                    };
                    rt.block_on(crate::mail::serve(servers, rx));
                })?,
        );
    }

    let reloader = Arc::new(Reloader {
        ctx: ctx.clone(),
        conf: cfg.conf_path.clone(),
        prefix: cfg.prefix.clone(),
    });
    block_on_shutdown(Some(reloader));

    eprintln!("ngxrs: shutting down");
    // Stop accepting first, then let in-flight requests finish (nginx's
    // graceful shutdown). Bounded so a stuck client cannot block exit.
    // Flipping this makes already-running responses advertise `Connection: close`.
    crate::http::SHUTTING_DOWN.store(true, Ordering::SeqCst);
    stopping.store(true, Ordering::SeqCst);
    let _ = shutdown_tx.send(true);
    for t in threads {
        let _ = t.join();
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while crate::http::ACTIVE_CONNS.load(Ordering::Relaxed) > 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let left = crate::http::ACTIVE_CONNS.load(Ordering::Relaxed);
    if left > 0 {
        eprintln!("ngxrs: {left} connection(s) still active after 30s, exiting anyway");
    }
    if let Some(tx) = stream_tx {
        let _ = tx.send(true);
    }
    if let Some(t) = stream_thread {
        let _ = t.join();
    }
    Ok(())
}

/// `host:port` or `port` in stream context (no scheme).
fn parse_stream_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Some(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return Some(SocketAddr::new(ip, port));
            }
        }
    }
    None
}

fn worker_main(
    wid: usize,
    ctx: Arc<Ctx>,
    shutdown: watch::Receiver<bool>,
    stopping: Arc<AtomicBool>,
    ready: Option<std::sync::mpsc::Sender<()>>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ngxrs: worker {wid} failed to start runtime: {e}");
            return;
        }
    };

    rt.block_on(async move {
        let cfg = ctx.cfg();
        let mut listeners: Vec<(Arc<TcpListener>, usize)> = Vec::new();
        for (gi, group) in cfg.http.groups.iter().enumerate() {
            match bind(group.addr, true) {
                Ok(l) => {
                    if wid == 0 {
                        eprintln!(
                            "ngxrs: listening on {} ({} server{})",
                            group.addr,
                            group.servers.len(),
                            if group.servers.len() == 1 { "" } else { "s" }
                        );
                    }
                    listeners.push((Arc::new(l), gi));
                }
                Err(e) => {
                    if wid == 0 {
                        eprintln!("ngxrs: cannot bind {}: {e}", group.addr);
                    }
                }
            }
        }

        if wid == 0 && listeners.is_empty() {
            std::process::exit(1);
        }
        if let Some(tx) = ready {
            let _ = tx.send(());
        }

        let mut tasks = Vec::new();
        for (listener, gi) in listeners {
            let ctx = ctx.clone();
            let stopping = stopping.clone();
            let shutdown = shutdown.clone();
            tasks.push(tokio::spawn(async move {
                accept_loop(listener, gi, ctx, shutdown, stopping).await;
            }));
        }
        for t in tasks {
            let _ = t.await;
        }

        // Graceful shutdown: the accept loops have stopped, but requests that
        // are already in flight keep running. Dropping the runtime here would
        // cancel them mid-response, so wait for the counter to drain.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while crate::http::ACTIVE_CONNS.load(Ordering::Relaxed) > 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

fn bind(addr: SocketAddr, reuse_port: bool) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if reuse_port {
        // Linux and macOS both support SO_REUSEPORT.
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
    }
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(65535)?;
    TcpListener::from_std(sock.into())
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    group_idx: usize,
    ctx: Arc<Ctx>,
    mut shutdown: watch::Receiver<bool>,
    stopping: Arc<AtomicBool>,
) {
    loop {
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            // Snapshot once: a reload swaps the Arc, and this
                            // connection keeps the configuration it started on.
                            let cfg = ctx.cfg();
                            let tls = ctx.tls.get(group_idx).cloned().flatten();
                            match tls {
                                None => {
                                    // h2c with prior knowledge: the client opens
                                    // with the HTTP/2 connection preface. Only
                                    // take that path when the group actually has
                                    // `http2 on`, mirroring nginx.
                                    let mut head = [0u8; 24];
                                    let is_h2c = matches!(
                                        stream.peek(&mut head).await,
                                        Ok(n) if n == 24
                                            && &head[..] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                                    ) && cfg.http.groups[group_idx]
                                        .servers
                                        .iter()
                                        .any(|s| cfg.http.server(*s).http2);
                                    if is_h2c {
                                        let group = &cfg.http.groups[group_idx];
                                        crate::h2server::serve(
                                            stream,
                                            &group.servers,
                                            group.default_server,
                                            &cfg.http,
                                            cfg.http.server(group.default_server).server_tokens,
                                        )
                                        .await;
                                        return;
                                    }
                                    let conn = Conn::new(
                                        Stream::Plain(stream),
                                        peer,
                                        cfg.http.tcp_nopush,
                                    );
                                    http::handle_conn(conn, cfg, group_idx, &ctx).await;
                                }
                                Some(tls_cfg) => {
                                    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                                    let tls_stream = match tokio::time::timeout(
                                        Duration::from_secs(10),
                                        acceptor.accept(stream),
                                    )
                                    .await
                                    {
                                        Ok(Ok(s)) => s,
                                        // nginx logs and drops failed handshakes
                                        _ => return,
                                    };
                                    if tls_stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                                        let group = &cfg.http.groups[group_idx];
                                        let _ = peer;
                                        crate::h2server::serve(
                                            tls_stream,
                                            &group.servers,
                                            group.default_server,
                                            &cfg.http,
                                            cfg.http.server(group.default_server).server_tokens,
                                        )
                                        .await;
                                        return;
                                    }
                                    let conn = Conn::new(
                                        Stream::Tls(Box::new(tls_stream)),
                                        peer,
                                        cfg.http.tcp_nopush,
                                    );
                                    http::handle_conn(conn, cfg, group_idx, &ctx).await;
                                }
                            }
                        });
                    }
                    Err(e) => match e.kind() {
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => continue,
                        _ => tokio::time::sleep(Duration::from_millis(10)).await,
                    },
                }
            }
        }
    }
}

/// What a SIGHUP needs in order to re-read the configuration.
struct Reloader {
    ctx: Arc<Ctx>,
    conf: std::path::PathBuf,
    prefix: std::path::PathBuf,
}

impl Reloader {
    /// Re-parse the configuration and install it. Listeners are left alone:
    /// nginx also keeps listening sockets across a reload unless `listen`
    /// changed, and rebuilding them here would drop live connections.
    fn reload(&self) {
        crate::log::error_log("notice", "reconfiguring");
        match crate::config::load_full(&self.conf, Some(&self.prefix)) {
            Ok(mut new_cfg) => {
                // Keep the original pid/daemon settings even if the file
                // changed its mind: we are already running.
                let old = self.ctx.cfg();
                new_cfg.pid = old.pid.clone();
                new_cfg.daemon = old.daemon;
                self.ctx.set_cfg(Arc::new(new_cfg));
                crate::log::error_log("notice", "reconfiguring done");
            }
            Err(e) => {
                // nginx keeps the old configuration and logs the failure.
                crate::log::error_log(
                    "emerg",
                    &format!("reconfiguring failed, keeping old config: {e}"),
                );
            }
        }
    }
}

fn block_on_shutdown(reloader: Option<Arc<Reloader>>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            std::thread::sleep(Duration::from_secs(3600));
            return;
        }
    };
    rt.block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            // SIGQUIT is nginx's graceful shutdown; SIGTERM/SIGINT also stop.
            let quit = signal(SignalKind::quit());
            let mut quit = match quit {
                Ok(s) => s,
                Err(_) => {
                    tokio::select! {
                        _ = term.recv() => {}
                        _ = int.recv() => {}
                    }
                    return;
                }
            };
            // SIGHUP reloads the configuration (`nginx -s reload`).
            let mut hup = signal(SignalKind::hangup()).ok();
            loop {
                tokio::select! {
                    _ = term.recv() => return,
                    _ = int.recv() => return,
                    _ = quit.recv() => return,
                    _ = async {
                        match hup.as_mut() {
                            Some(h) => {
                                h.recv().await;
                            }
                            // No SIGHUP support: never resolve.
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        if let Some(r) = &reloader {
                            r.reload();
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    });
}


// ---------------------------------------------------------------------------
// Shared-listener mode
// ---------------------------------------------------------------------------

struct Handoff {
    stream: std::net::TcpStream,
    peer: SocketAddr,
    group: usize,
}

fn bind_std(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(65535)?;
    Ok(sock.into())
}

fn acceptor_main(
    groups: &[SocketAddr],
    senders: Vec<mpsc::Sender<Handoff>>,
    stopping: Arc<AtomicBool>,
    ready: std::sync::mpsc::Sender<()>,
) {
    let mut listeners: Vec<(std::net::TcpListener, usize)> = Vec::new();
    for (gi, addr) in groups.iter().enumerate() {
        match bind_std(*addr) {
            Ok(l) => {
                eprintln!("ngxrs: listening on {} (shared)", l.local_addr().unwrap_or(*addr));
                listeners.push((l, gi));
            }
            Err(e) => {
                eprintln!("ngxrs: cannot bind {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    let _ = ready.send(());

    let mut pollfds: Vec<libc::pollfd> = listeners
        .iter()
        .map(|(l, _)| libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(l),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    let mut next = 0usize;
    let n = senders.len();
    while !stopping.load(Ordering::Relaxed) {
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 100) };
        if rc <= 0 {
            continue;
        }
        for i in 0..listeners.len() {
            if pollfds[i].revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                match listeners[i].0.accept() {
                    Ok((stream, peer)) => {
                        if stream.set_nonblocking(true).is_err() {
                            continue;
                        }
                        let h = Handoff {
                            stream,
                            peer,
                            group: listeners[i].1,
                        };
                        let mut slot = Some(h);
                        for _ in 0..n {
                            let idx = next % n;
                            next = next.wrapping_add(1);
                            match senders[idx].try_send(slot.take().expect("slot")) {
                                Ok(()) => break,
                                Err(e) => slot = Some(e.into_inner()),
                            }
                        }
                        if let Some(h) = slot {
                            let _ = senders[0].blocking_send(h);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
    }
}

fn shared_worker_main(
    wid: usize,
    ctx: Arc<Ctx>,
    mut rx: mpsc::Receiver<Handoff>,
    mut shutdown: watch::Receiver<bool>,
    stopping: Arc<AtomicBool>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ngxrs: worker {wid} failed to start runtime: {e}");
            return;
        }
    };

    rt.block_on(async move {
        loop {
            if stopping.load(Ordering::Relaxed) {
                return;
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                item = rx.recv() => {
                    let Some(h) = item else { return };
                    let stream = match TcpStream::from_std(h.stream) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = stream.set_nodelay(true);
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let cfg = ctx.cfg();
                        let tls = ctx.tls.get(h.group).cloned().flatten();
                        match tls {
                            None => {
                                let conn = Conn::new(
                                    Stream::Plain(stream),
                                    h.peer,
                                    cfg.http.tcp_nopush,
                                );
                                http::handle_conn(conn, cfg, h.group, &ctx).await;
                            }
                            Some(tls_cfg) => {
                                let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                                let tls_stream = match tokio::time::timeout(
                                    Duration::from_secs(10),
                                    acceptor.accept(stream),
                                )
                                .await
                                {
                                    Ok(Ok(s)) => s,
                                    _ => return,
                                };
                                if tls_stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                                    let group = &cfg.http.groups[h.group];
                                    crate::h2server::serve(
                                        tls_stream,
                                        &group.servers,
                                        group.default_server,
                                        &cfg.http,
                                        cfg.http.server(group.default_server).server_tokens,
                                    )
                                    .await;
                                    return;
                                }
                                let conn = Conn::new(
                                    Stream::Tls(Box::new(tls_stream)),
                                    h.peer,
                                    cfg.http.tcp_nopush,
                                );
                                http::handle_conn(conn, cfg, h.group, &ctx).await;
                            }
                        }
                    });
                }
            }
        }
    });
}



