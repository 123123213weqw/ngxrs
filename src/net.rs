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
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::Config;
use crate::conn::Conn;
use crate::http::{self, Ctx};
use crate::log::Logger;

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
    let mut threads = Vec::with_capacity(workers);

    for wid in 0..workers {
        let ctx = ctx.clone();
        let shutdown = shutdown_rx.clone();
        let stopping = stopping.clone();
        let handle = std::thread::Builder::new()
            .name(format!("ngxrs-w{wid}"))
            .spawn(move || worker_main(wid, ctx, shutdown, stopping))?;
        threads.push(handle);
    }

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
