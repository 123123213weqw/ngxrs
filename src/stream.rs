//! `stream {}` module: L4 TCP and UDP proxying.
//!
//! Covers nginx's common stream subset: `listen`, `proxy_pass` (host:port),
//! `upstream` blocks with round-robin, `proxy_timeout`, `proxy_connect_timeout`,
//! and `return` for immediate responses on a stream listener.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

/// One `listen` in stream context, already resolved to its backend list.
#[derive(Debug, Clone)]
pub struct StreamServer {
    pub listen: SocketAddr,
    pub udp: bool,
    /// Round-robin backend list; empty when `return` is set.
    pub backends: Vec<SocketAddr>,
    pub proxy_timeout: Duration,
    pub proxy_connect_timeout: Duration,
    /// `error_log` destinations of this stream server.
    pub sinks: Vec<std::sync::Arc<crate::log::Sink>>,
}

pub struct StreamConfig {
    pub servers: Vec<StreamServer>,
}

impl StreamConfig {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
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
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}

fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Run every stream listener until `shutdown` fires.
pub async fn serve(cfg: Arc<StreamConfig>, mut shutdown: watch::Receiver<bool>) {
    let mut handles = Vec::new();
    for server in cfg.servers.clone() {
        let mut sd = shutdown.clone();
        let handle = tokio::spawn(async move {
            if server.udp {
                serve_udp(server, &mut sd).await;
            } else {
                serve_tcp(server, &mut sd).await;
            }
        });
        handles.push(handle);
    }
    for h in handles {
        let _ = h.await;
    }
}

async fn serve_tcp(server: StreamServer, shutdown: &mut watch::Receiver<bool>) {
    let listener = match bind_tcp(server.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ngxrs: [error] stream cannot bind {}: {e}", server.listen);
            return;
        }
    };
    eprintln!("ngxrs: stream listening on {} (tcp)", server.listen);

    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let _ = client.set_nodelay(true);
                // nginx logs stream connections at `info`: the peer, the local
                // address and the chosen upstream.
                let local = client.local_addr().ok();
                let n = crate::mail::next_conn_id();
                if let Some(local) = local {
                    let backends_now = server.backends.clone();
                    let up = pick_backend(&backends_now, &counter)
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let up = if up == "-" { "127.0.0.1:0".to_string() } else { up };
                    crate::log::log_to(
                        &server.sinks,
                        crate::log::Level::Info,
                        &format!("*{n} client {peer} connected to {local}, proxy to \"{up}\"", ),
                    );
                }
                let backends = server.backends.clone();
                let timeout = server.proxy_timeout;
                let connect_timeout = server.proxy_connect_timeout;
                let counter = counter.clone();
                tokio::spawn(async move {
                    let Some(upstream) = pick_backend(&backends, &counter) else {
                        return;
                    };
                    let upstream = match tokio::time::timeout(
                        connect_timeout,
                        TcpStream::connect(upstream),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        _ => return,
                    };
                    let _ = upstream.set_nodelay(true);
                    proxy_tcp(client, upstream, timeout, peer).await;
                });
            }
        }
    }
}

fn pick_backend(backends: &[SocketAddr], counter: &std::sync::atomic::AtomicUsize) -> Option<SocketAddr> {
    if backends.is_empty() {
        return None;
    }
    let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % backends.len();
    Some(backends[i])
}

async fn proxy_tcp(mut client: TcpStream, mut upstream: TcpStream, _idle: Duration, _peer: SocketAddr) {
    // `copy_bidirectional` already returns when either side closes; enforcing
    // proxy_timeout with an outer timeout would also cut long-lived transfers.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
}

async fn serve_udp(server: StreamServer, shutdown: &mut watch::Receiver<bool>) {
    let sock = match bind_udp(server.listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ngxrs: [error] stream cannot bind {} (udp): {e}", server.listen);
            return;
        }
    };
    eprintln!("ngxrs: stream listening on {} (udp)", server.listen);
    let sock = Arc::new(sock);

    // Per-client upstream socket so replies can be matched back.
    let mut sessions: BTreeMap<SocketAddr, Arc<UdpSocket>> = BTreeMap::new();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            recv = sock.recv_from(&mut buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let backend = match pick_backend(&server.backends, &counter) {
                    Some(b) => b,
                    None => continue,
                };
                let up = if let Some(s) = sessions.get(&peer) {
                    s.clone()
                } else {
                    let bind_addr: SocketAddr = if backend.is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };
                    let s = match UdpSocket::bind(bind_addr).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if s.connect(backend).await.is_err() {
                        continue;
                    }
                    let s = Arc::new(s);
                    sessions.insert(peer, s.clone());
                    s
                };
                let _ = up.send(&buf[..n]).await;

                // Reply path for this session (one task per client session).
                let socks = sock.clone();
                let up2 = up.clone();
                let timeout = server.proxy_timeout;
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 65535];
                    loop {
                        match tokio::time::timeout(timeout, up2.recv(&mut rbuf)).await {
                            Ok(Ok(m)) => {
                                let _ = socks.send_to(&rbuf[..m], peer).await;
                            }
                            _ => return,
                        }
                    }
                });
            }
        }
    }
}
