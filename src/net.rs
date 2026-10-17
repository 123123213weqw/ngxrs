//! Listener setup, accept loops and process lifecycle.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("ngxrs")
        .build()?;

    let ctx = Arc::new(Ctx {
        config: cfg.clone(),
        logger,
    });

    rt.block_on(async move {
        let mut listeners = Vec::new();
        for (gi, group) in cfg.http.groups.iter().enumerate() {
            let listener = bind(group.addr)?;
            eprintln!(
                "ngxrs: listening on {} ({} server{})",
                group.addr,
                group.servers.len(),
                if group.servers.len() == 1 { "" } else { "s" }
            );
            listeners.push((Arc::new(listener), gi));
        }
        eprintln!(
            "ngxrs: started {} worker threads, prefix {}",
            workers,
            cfg.prefix.display()
        );

        for (listener, gi) in listeners {
            for _ in 0..2 {
                let listener = listener.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    accept_loop(listener, gi, ctx).await;
                });
            }
        }

        wait_for_shutdown().await;
        eprintln!("ngxrs: shutting down");
        Ok::<(), io::Error>(())
    })
}

fn bind(addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(65535)?;
    TcpListener::from_std(sock.into())
}

async fn accept_loop(listener: Arc<TcpListener>, group_idx: usize, ctx: Arc<Ctx>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let conn = Conn::new(stream, peer);
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

async fn wait_for_shutdown() {
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
}
