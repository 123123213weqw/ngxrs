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
use crate::conn::Conn;
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

pub fn serve(cfg: Config) -> io::Result<()> {
    let workers = if cfg.worker_processes == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    } else {
        cfg.worker_processes
    }
    .max(1);

    let logger = Arc::new(Logger::new()?);
    let cfg = Arc::new(cfg);

    if let Some(pid_path) = &cfg.pid {
        if let Some(parent) = pid_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pid_path, format!("{}\n", std::process::id()));
    }

    let ctx = Arc::new(Ctx {
        config: cfg.clone(),
        logger,
    });
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let stopping = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(workers + 1);
    let shared = accept_mode() == "shared";

    if shared {
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
            threads.push(
                std::thread::Builder::new()
                    .name("ngxrs-accept".to_string())
                    .spawn(move || acceptor_main(&groups, senders, stopping))?,
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
            let handle = std::thread::Builder::new()
                .name(format!("ngxrs-w{wid}"))
                .spawn(move || worker_main(wid, ctx, shutdown, stopping))?;
            threads.push(handle);
        }
    }

    crate::proxy::init(&cfg.http);
    crate::proxy::init_keepalive(&cfg.http);

    eprintln!(
        "ngxrs: started {workers} workers, prefix {}",
        cfg.prefix.display()
    );

    block_on_shutdown();

    eprintln!("ngxrs: shutting down");
    stopping.store(true, Ordering::SeqCst);
    let _ = shutdown_tx.send(true);
    for t in threads {
        let _ = t.join();
    }
    Ok(())
}

fn worker_main(wid: usize, ctx: Arc<Ctx>, shutdown: watch::Receiver<bool>, stopping: Arc<AtomicBool>) {
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
        let mut listeners: Vec<(Arc<TcpListener>, usize)> = Vec::new();
        for (gi, group) in ctx.config.http.groups.iter().enumerate() {
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
                            let conn = Conn::new(stream, peer, ctx.config.http.tcp_nopush);
                            http::handle_conn(conn, &ctx.config.http.groups[group_idx], &ctx).await;
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

fn block_on_shutdown() {
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
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
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
                        let conn = Conn::new(stream, h.peer, ctx.config.http.tcp_nopush);
                        http::handle_conn(conn, &ctx.config.http.groups[h.group], &ctx).await;
                    });
                }
            }
        }
    });
}
