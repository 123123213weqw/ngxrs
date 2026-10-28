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
/// `limit_conn_zone` storage. nginx keeps zones in shared memory so every
/// worker sees the same counters; one process means a plain map is equivalent.
static ZONES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<crate::limit::ConnZone>>>,
> = std::sync::OnceLock::new();

/// Create (or reuse) the zone named `name` and register `key` against it.
pub fn zone_for(name: &str, key: &str) -> std::sync::Arc<crate::limit::ConnZone> {
    let m = ZONES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    let _ = key;
    g.entry(name.to_string())
        .or_insert_with(|| std::sync::Arc::new(crate::limit::ConnZone::new()))
        .clone()
}

#[derive(Clone)]
pub struct StreamServer {
    pub listen: SocketAddr,
    /// `allow` / `deny`: a denied peer is closed before anything is sent
    /// (`ngx_stream_access_module`, evaluated in the ACCESS phase).
    pub access: Vec<crate::config::typed::AccessRule>,
    /// `limit_conn <zone> <n>`: at most `n` simultaneous sessions per key.
    pub limit_conns: Vec<(String, u32)>,
    /// `proxy_next_upstream_tries <n>`: peers to try, 0 = unlimited.
    pub next_upstream_tries: u32,
    /// `proxy_pass` with a variable: expanded per connection and resolved with
    /// `resolver`.
    pub proxy_pass_var: Option<String>,
    /// `resolver`, for the case above.
    pub resolver: Option<std::sync::Arc<crate::resolver::Resolver>>,
    /// `proxy_download_rate` / `proxy_upload_rate`, bytes per second; 0 is
    /// unlimited (`ngx_stream_proxy_module`).
    pub proxy_download_rate: u64,
    pub proxy_upload_rate: u64,
    /// `set_real_ip_from`: trusted peers whose PROXY header rewrites
    /// `$remote_addr` (`ngx_stream_realip_module`). `realip_from_unix` covers
    /// `set_real_ip_from unix:`, which has no address to match.
    pub realip_from: Vec<(std::net::IpAddr, u8)>,
    pub realip_from_unix: bool,
    /// `listen unix:/path`: bind a unix socket instead of `listen`.
    pub listen_unix: Option<std::sync::Arc<std::path::PathBuf>>,
    pub udp: bool,
    /// Peers and balancer for `proxy_pass`; empty when `return` is set.
    pub peers: std::sync::Arc<crate::streamlb::PeerSet>,
    pub proxy_timeout: Duration,
    pub proxy_connect_timeout: Duration,
    /// `error_log` destinations of this stream server.
    pub sinks: Vec<std::sync::Arc<crate::log::Sink>>,
    /// Termination config when `listen ... ssl` is set.
    pub tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// `return <text>`: answer with this text instead of proxying.
    pub return_text: Option<String>,
    /// `proxy_ssl on`: speak TLS to the upstream.
    pub proxy_ssl: bool,
    /// `proxy_ssl_session_reuse`: hand the client config to the resumption
    /// cache so a second connection can resume.
    pub proxy_ssl_session_reuse: bool,
    /// `proxy_ssl_name`: SNI for the upstream (defaults to `localhost`).
    pub proxy_ssl_name: Option<String>,
    /// `ssl_verify_client`: 0 off, 1 on, 2 optional, 3 optional_no_ca.
    pub client_verify: u8,
    /// `ssl_client_certificate`: trust anchors for `$ssl_client_verify`.
    pub client_ca: Option<std::path::PathBuf>,
    /// `ssl_trusted_certificate`: extra chain-building certificates.
    pub trusted_ca: Option<std::path::PathBuf>,
    /// `access_log` of this stream server.
    pub access_logs: Vec<crate::config::AccessLog>,
    /// Shared writer for `access_log`.
    pub logger: std::sync::Arc<crate::log::Logger>,
    /// `proxy_protocol on`: prefix the upstream connection with a PROXY header.
    pub proxy_protocol: bool,
    /// `listen ... proxy_protocol`: consume such a header from the client first.
    pub listen_proxy_protocol: bool,
    /// `geo` / `map` / `split_clients` blocks from `stream {}`. Shared rather
    /// than copied: they are read-only and evaluated per connection.
    pub geos: std::sync::Arc<Vec<crate::geo::GeoDef>>,
    pub maps: std::sync::Arc<Vec<crate::mapping::MapDef>>,
    pub splits: std::sync::Arc<Vec<crate::split::SplitClients>>,
    /// `set $name value`, evaluated in order before `return`. nginx runs `set`
    /// in the rewrite phase and `return` from the content phase, so the textual
    /// order in the config does not matter -- `stream_set.t` puts `return`
    /// first and expects the `set`s to have run.
    pub sets: Vec<(String, String)>,
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

/// A stream client connection: TCP, or a unix socket (`stream_geo_unix.t`).
/// The session body is shared, so only accept and the couple of socket-specific
/// calls differ.
enum ClientIo {
    Tcp(TcpStream),
    Unix(tokio::net::UnixStream),
}

impl ClientIo {
    fn set_nodelay(&self) {
        if let ClientIo::Tcp(s) = self {
            let _ = s.set_nodelay(true);
        }
    }
    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            ClientIo::Tcp(s) => s.local_addr().ok(),
            // A unix socket has no address; nginx reports `unix:` for
            // `$remote_addr` and nothing for `$remote_port`.
            ClientIo::Unix(_) => None,
        }
    }
}

impl tokio::io::AsyncRead for ClientIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ClientIo::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ClientIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientIo::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ClientIo::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            ClientIo::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ClientIo::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

enum Lsn {
    Tcp(tokio::net::TcpListener),
    Unix(tokio::net::UnixListener),
}

/// Bind a stream listener: `listen unix:/path` or a TCP address.
fn bind_stream(server: &StreamServer) -> std::io::Result<Lsn> {
    if let Some(path) = &server.listen_unix {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // nginx unlinks a stale socket file before binding.
        let _ = std::fs::remove_file(path.as_ref());
        let l = std::os::unix::net::UnixListener::bind(path.as_ref())?;
        l.set_nonblocking(true)?;
        return Ok(Lsn::Unix(tokio::net::UnixListener::from_std(l)?));
    }
    Ok(Lsn::Tcp(bind_tcp(server.listen)?))
}

struct Accepted {
    client: ClientIo,
    peer: SocketAddr,
    peer_unix: bool,
    local: Option<SocketAddr>,
}

async fn accept_stream(l: &Lsn) -> std::io::Result<Accepted> {
    match l {
        Lsn::Tcp(listener) => {
            let (s, peer) = listener.accept().await?;
            let local = s.local_addr().ok();
            Ok(Accepted {
                client: ClientIo::Tcp(s),
                peer,
                peer_unix: false,
                local,
            })
        }
        Lsn::Unix(listener) => {
            let (s, _addr) = listener.accept().await?;
            // Placeholder peer: `$remote_addr` renders as `unix:` because
            // `peer_unix` is set, so the value itself is never shown.
            Ok(Accepted {
                client: ClientIo::Unix(s),
                peer: SocketAddr::from(([0, 0, 0, 0], 0)),
                peer_unix: true,
                local: None,
            })
        }
    }
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
    let label = match &server.listen_unix {
        Some(p) => format!("unix:{}", p.display()),
        None => server.listen.to_string(),
    };
    let listener = match bind_stream(&server) {
        Ok(l) => l,
        Err(e) => {
            crate::log::log_global(
                crate::log::Level::Emerg,
                &format!("stream cannot bind {label}: {e}"),
            );
            return;
        }
    };
    crate::log::log_global(
        crate::log::Level::Notice,
        &format!("stream listening on {label} (tcp)"),
    );

    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = accept_stream(&listener) => {
                let Accepted { client, peer, peer_unix, local: acc_local } = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // The address the *client* connected to, which is what the
                // PROXY header advertises as the destination. Taking the
                // upstream's local address instead produced a mixed-family
                // pair (127.0.0.1 -> [::1]) and therefore `PROXY UNKNOWN`.
                let client_local = acc_local;
                client.set_nodelay();
                // nginx logs stream connections at `info`: the peer, the local
                // address and the chosen upstream.
                let local = client_local;
                let n = crate::mail::next_conn_id();
                if let Some(local) = local {
                    // Only *describe* the peer: picking here would take a
                    // `max_conns` slot that the real selection then cannot use.
                    let up = server.peers.describe();
                    crate::log::log_to(
                        &server.sinks,
                        crate::log::Level::Info,
                        &format!("*{n} client {peer} connected to {local}, proxy to \"{up}\"", ),
                    );
                }
                let peers = server.peers.clone();
                let timeout = server.proxy_timeout;
                let tls = server.tls.clone();
                let connect_timeout = server.proxy_connect_timeout;
                let counter = counter.clone();
                let return_text = server.return_text.clone();
                let proxy_ssl = server.proxy_ssl;
                let reuse = server.proxy_ssl_session_reuse;
                let sni = server.proxy_ssl_name.clone();
                let write_pp = server.proxy_protocol;
                let geos = server.geos.clone();
                let maps = server.maps.clone();
                let splits = server.splits.clone();
                let sets = server.sets.clone();
                let listen_pp = server.listen_proxy_protocol;
                let realip_from = server.realip_from.clone();
                let realip_unix = server.realip_from_unix;
                let access = server.access.clone();
                let dl_rate = server.proxy_download_rate;
                let ul_rate = server.proxy_upload_rate;
                let resolver = server.resolver.clone();
                let next_upstream_tries = server.next_upstream_tries;
                let proxy_pass_var = server.proxy_pass_var.clone();
                let verify_mode = server.client_verify;
                let client_ca = server.client_ca.clone();
                let trusted_ca = server.trusted_ca.clone();
                // One log line per connection, written when the task ends.
                let mut alog = StreamAccessLog::new(&server, peer, "stream");
                tokio::spawn(async move {
                    // `ngx_stream_access_module` runs in the ACCESS phase, before
                    // `return` or `proxy_pass`; a denied peer has its connection
                    // closed with no bytes at all.
                    if !access.is_empty() {
                        let denied = if peer_unix {
                            crate::config::typed::access_denied_for(
                                &access,
                                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                true,
                            )
                        } else {
                            crate::config::typed::access_denied_for(&access, peer.ip(), false)
                        };
                        if denied {
                            // nginx answers nothing at all: the connection is
                            // simply closed, and `$status` reports 403.
                            if let Some(a) = alog.as_mut() {
                                a.status = 403;
                            }
                            drop(alog);
                            return;
                        }
                    }
                    // `listen ... proxy_protocol`: the header arrives before
                    // anything else, TLS included, and `$proxy_protocol_*`
                    // depends on it (`stream_proxy_protocol2_tlv.t`).
                    let mut client = client;
                    let pp = if listen_pp {
                        match crate::proxyproto::read_from(&mut client).await {
                            Ok(p) => Some(std::sync::Arc::new(p)),
                            Err(_) => {
                                let _ = client.shutdown().await;
                                drop(alog);
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    // `set_real_ip_from`: a trusted peer's PROXY header rewrites
                    // `$remote_addr`/`$remote_port`, and `$realip_remote_*` then
                    // keeps the original peer (`ngx_stream_realip_set_addr`
                    // saves c->addr_text before overwriting it). An untrusted
                    // peer leaves both pointing at the peer, which is why the
                    // "no match" assertions expect the two to be equal.
                    let eff = realip_addr(
                        &pp,
                        peer,
                        peer_unix,
                        &realip_from,
                        realip_unix,
                    );
                    // `return <text>` answers without touching an upstream.
                    if let Some(text) = return_text {
                        let local_addr = client_local.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                        let mut base = base_vars(
                            peer, peer_unix, eff, local_addr, &maps, &geos, &splits,
                        );
                        base.proxy_protocol = pp.as_deref();
                        // `set` values may reference earlier `set`s, so they are
                        // expanded one at a time into an accumulating map.
                        let mut custom = std::collections::HashMap::new();
                        for (name, value) in &sets {
                            // A fresh view each round, so the borrow of `custom`
                            // ends before it is extended.
                            let expanded = {
                                let mut view = crate::streamvars::Vars {
                                    custom: &custom,
                                    ..base
                                };
                                view.custom = &custom;
                                view.expand(value)
                            };
                            custom.insert(name.clone(), expanded);
                        }
                        base.custom = &custom;
                        answer_stream_return(
                            client,
                            tls,
                            &text,
                            verify_mode,
                            &client_ca,
                            &trusted_ca,
                            alog.as_mut(),
                            &base,
                        )
                        .await;
                        drop(alog);
                        return;
                    }
                    // `max_conns` and `backup` decide the candidate order; a
                    // failed connect moves on to the next peer, which is what
                    // nginx's default `proxy_next_upstream on` does while
                    // nothing has been sent yet.
                    let hash_key = if peers.hash_key.is_empty() {
                        None
                    } else {
                        Some(
                            crate::streamvars::Vars {
                                peer,
                                peer_unix,
                                eff,
                                local: client_local.unwrap_or(peer),
                                udp: false,
                                maps: &maps,
                                geos: &geos,
                                ssl: None,
                                proxy_protocol: None,
                                custom: &NO_CUSTOM,
                                splits: &splits,
                                connection: crate::stats::accepted(),
                            }
                            .expand(&peers.hash_key),
                        )
                    };
                    // nginx's `pc->tries` starts at the primary count and each
                    // attempt marks a peer tried, so the loop below is the
                    // `max_fails`-aware equivalent of one `get_peer` per try.
                    let now = || {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0)
                    };
                    let var_target = proxy_pass_var.clone();
                    let var_resolver = resolver.clone();
                    // `proxy_pass $var`: expand and resolve here, because the
                    // value only exists per connection (`stream_resolver.t`).
                    // ngx_stream_proxy_module does the same in its init handler.
                    let mut var_peer: Option<(SocketAddr, String)> = None;
                    if let Some(spec) = var_target.as_ref() {
                        let text = {
                            let mut vb =
                                base_vars(
                                    peer,
                                    peer_unix,
                                    eff,
                                    local.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                                    &maps,
                                    &geos,
                                    &splits,
                                );
                            vb.proxy_protocol = pp.as_deref();
                            vb.expand(spec)
                        };
                        match resolve_var_peer(&text, var_resolver.as_ref(), connect_timeout).await {
                            Ok((addr, label)) => var_peer = Some((addr, label)),
                            Err(e) => {
                                crate::log::log_global(
                                    crate::log::Level::Error,
                                    &format!("stream {e}"),
                                );
                            }
                        }
                    }
                    let mut tried = vec![false; peers.len()];
                    let mut chosen: Option<crate::streamlb::Guard> = None;
                    let mut upstream = None;
                    let mut attempts = 0usize;
                    // A variable target bypasses the balancer entirely: nginx
                    // resolves it to one address and there is nothing to retry.
                    if let Some((addr, label)) = var_peer.take() {
                        if let Some(l) = alog.as_mut() {
                            l.start_attempt(&label);
                        }
                        let attempt = match tokio::time::timeout(
                            connect_timeout,
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            Ok(Ok(t)) => Ok(UpConn::Tcp(t)),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connect timed out",
                            )),
                        };
                        match attempt {
                            Ok(s) => {
                                if let UpConn::Tcp(t) = &s {
                                    let _ = t.set_nodelay(true);
                                }
                                upstream = Some(s);
                            }
                            Err(e) => {
                                if let Some(l) = alog.as_mut() {
                                    l.finish_attempt(0, 0);
                                }
                                crate::log::log_global(
                                    crate::log::Level::Error,
                                    &format!("stream connect to {label} failed: {e}"),
                                );
                            }
                        }
                    }
                    let max_attempts = if next_upstream_tries == 0 {
                        peers.len().max(1) * 2
                    } else {
                        (next_upstream_tries as usize).min(peers.len().max(1))
                    };
                    while upstream.is_none() && attempts < max_attempts {
                        let Some(idx) = peers.pick(&mut tried, hash_key.as_deref(), now()) else {
                            break;
                        };
                        attempts += 1;
                        if let Some(l) = alog.as_mut() {
                            l.start_attempt(&peers.addr(idx).to_string());
                        }
                        // A unix peer has no address; connect over the socket
                        // (`stream { server unix:/path; }`, `stream_unix.t`).
                        let attempt = match peers.unix(idx) {
                            Some(path) => {
                                match tokio::time::timeout(
                                    connect_timeout,
                                    tokio::net::UnixStream::connect(path),
                                )
                                .await
                                {
                                    Ok(Ok(s)) => Ok(UpConn::Unix(s)),
                                    Ok(Err(e)) => Err(e),
                                    Err(_) => Err(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "connect timed out",
                                    )),
                                }
                            }
                            None => match tokio::time::timeout(
                                connect_timeout,
                                TcpStream::connect(peers.addr(idx)),
                            )
                            .await
                            {
                                Ok(Ok(s)) => Ok(UpConn::Tcp(s)),
                                Ok(Err(e)) => Err(e),
                                Err(_) => Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "connect timed out",
                                )),
                            },
                        };
                        match attempt {
                            Ok(s) => {
                                if let UpConn::Tcp(t) = &s {
                                    let _ = t.set_nodelay(true);
                                }
                                // `pick` already counted the connection; the
                                // guard owns that slot from here on.
                                chosen = Some(peers.guard(idx));
                                upstream = Some(s);
                                break;
                            }
                            // A refused or timed-out connect is `NGX_PEER_FAILED`:
                            // it counts against `max_fails` and the next peer is
                            // tried (`proxy_next_upstream on`).
                            _ => peers.release(idx, false, now()),
                        }
                    }
                    let (Some(upstream), Some(_guard)) = (upstream, chosen) else {
                        // Every peer was at `max_conns`, refused or disabled:
                        // nginx closes the client connection (`NGX_BUSY`).
                        return;
                    };
                    // `proxy_ssl on`: speak TLS to the upstream, then splice.
                    if proxy_ssl {
                        // `proxy_ssl_name` is a complex value (`proxy_ssl_name
                        // x${server_port}x`), so it is expanded once per
                        // connection rather than used verbatim
                        // (`stream_proxy_ssl_name_complex.t`).
                        let sni = sni.map(|raw| {
                            crate::streamvars::Vars {
                                peer,
                                peer_unix,
                                eff,
                                local: client_local.unwrap_or(peer),
                                udp: false,
                                maps: &maps,
                                geos: &geos,
                                ssl: None,
                                proxy_protocol: None,
                                custom: &NO_CUSTOM,
                                splits: &splits,
                                connection: crate::stats::accepted(),
                            }
                            .expand(&raw)
                        });
                        // `proxy_protocol on` writes the header before the TLS
                        // handshake (`stream_proxy_protocol_ssl.t`, "protocol
                        // on"): the upstream expects PROXY bytes first, then
                        // ClientHello.
                        let mut upstream = upstream;
                        if write_pp {
                            use tokio::io::AsyncWriteExt;
                            let local = client_local
                                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                            if upstream
                                .write_all(&crate::proxyproto::write(&peer, &local))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        let cfg = proxy_tls_config(sni.as_deref().unwrap_or("localhost"), reuse);
                        let name = rustls::pki_types::ServerName::try_from(
                            sni.clone().unwrap_or_else(|| "localhost".to_string()),
                        )
                        .unwrap_or_else(|_| {
                            rustls::pki_types::ServerName::try_from("localhost".to_string())
                                .expect("localhost is a valid name")
                        });
                        let connector = tokio_rustls::TlsConnector::from(cfg);
                        // `proxy_ssl` only makes sense over TCP; a unix peer is
                        // a plain socket (nginx does not offer TLS there either).
                        let UpConn::Tcp(tcp) = upstream else {
                            return;
                        };
                        let Ok(tls_up) = connector.connect(name, tcp).await else {
                            return;
                        };
                        let counts = match tls {
                            Some(sc) => {
                                let acceptor = tokio_rustls::TlsAcceptor::from(sc);
                                match acceptor.accept(client).await {
                                    Ok(c) => splice(c, tls_up).await,
                                    Err(_) => (0, 0),
                                }
                            }
                            None => splice(client, tls_up).await,
                        };
                        if let Some(l) = alog.as_mut() {
                            l.finish_attempt(counts.0, counts.1);
                        }
                        return;
                    }
                    // `listen ... ssl` terminates TLS here, before the splice.
                    let counts = {
                        let _ = &tls;
                        match tls {
                            Some(cfg) => {
                                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                                match acceptor.accept(client).await {
                                    Ok(t) => proxy_io(t, upstream, timeout, peer).await,
                                    Err(_) => {
                                        if let Some(l) = alog.as_mut() {
                                            l.status = 500;
                                        }
                                        (0, 0)
                                    }
                                }
                            }
                            None => {
                                if write_pp {
                                    use tokio::io::AsyncWriteExt;
                                    let local = client_local
                                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                                    let mut upstream = upstream;
                                    let _ = upstream
                                        .write_all(&crate::proxyproto::write(&peer, &local))
                                        .await;
                                    // The PROXY header is not counted in
                                    // `$upstream_bytes_sent` by nginx.
                                    let (a, b) = proxy_tcp(client, upstream, timeout, peer, ul_rate, dl_rate).await;
                                    (a, b)
                                } else {
                                    proxy_tcp(client, upstream, timeout, peer, ul_rate, dl_rate).await
                                }
                            }
                        }
                    };
                    if let Some(l) = alog.as_mut() {
                        l.finish_attempt(counts.0, counts.1);
                    }
                });
            }
        }
    }
}

/// Client TLS config for `proxy_ssl`, with session resumption.
///
/// nginx's `proxy_ssl_session_reuse on` keeps a session cache per worker, so
/// the second connection to the same upstream resumes. rustls does the same
/// through `ClientConfig::resumption`; the config must be built once and
/// shared, otherwise every connection starts from an empty cache.
fn proxy_tls_config(name: &str, reuse: bool) -> std::sync::Arc<rustls::ClientConfig> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<rustls::ClientConfig>>>,
    > = std::sync::OnceLock::new();
    if !reuse {
        return build_proxy_tls(name, false);
    }
    let map = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .entry(name.to_string())
        .or_insert_with(|| build_proxy_tls(name, true))
        .clone()
}

fn build_proxy_tls(name: &str, reuse: bool) -> std::sync::Arc<rustls::ClientConfig> {
    // The upstream is a plain `stream` server with no CA of its own, so the
    // certificate is accepted as-is (`proxy_ssl_verify off`, nginx's default).
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default versions")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    cfg.alpn_protocols.clear();
    if reuse {
        cfg.resumption = rustls::client::Resumption::in_memory_sessions(64);
    }
    let _ = name;
    std::sync::Arc::new(cfg)
}

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Splice two arbitrary transports (used when either side speaks TLS).
///
/// `proxy_half_close` defaults to **off**, so the first EOF ends the whole
/// session: nginx shuts both sides down as soon as one is done. Waiting for
/// both directions to finish (`copy_bidirectional`) keeps the session -- and the
/// upstream connection slot -- alive while the peer that already finished just
/// sits there, which made `least_conn` see a tie where nginx sees a free peer
/// (`stream_upstream_least_conn.t`) and held `max_conns` slots too long.
/// The upstream side of a stream session: TCP, or a unix socket
/// (`stream_unix.t`). `proxy_ssl` only applies to TCP.
enum UpConn {
    Tcp(TcpStream),
    Unix(tokio::net::UnixStream),
}

impl tokio::io::AsyncRead for UpConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpConn::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpConn::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpConn::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpConn::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpConn::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Cumulative byte allowance, nginx's model for `proxy_*_rate`.
///
/// nginx does not use a token bucket with burst: it allows `rate * elapsed`
/// bytes in total since the session started, so the average is exactly `rate`
/// from the first byte. That distinction is observable -- `stream_limit_rate.t`
/// sets `proxy_download_rate 250` against 1011 bytes and expects the transfer to
/// take at least four seconds (1011/250 = 4.04), and `rate 1` to hand over
/// exactly one byte immediately.
struct Rate {
    rate: u64,
    sent: u64,
    /// Started lazily, on this direction's first byte.
    ///
    /// It must not be the session start: with `proxy_upload_rate 1000` the
    /// upload phase takes a second before the upstream replies, and that idle
    /// second would hand the download direction a full second of credit. The
    /// suite catches exactly this -- 1011 bytes at `proxy_download_rate 250`
    /// then took 3.04 s instead of 4.04 s, and `download - time` wants >= 4.
    started: Option<std::time::Instant>,
}

impl Rate {
    fn new(rate: u64) -> Rate {
        Rate {
            rate,
            sent: 0,
            started: None,
        }
    }

    /// How many bytes may be in flight right now, and how long to wait when the
    /// answer is zero. `None` means unlimited.
    fn allowance(&mut self) -> Option<u64> {
        if self.rate == 0 {
            return None;
        }
        let started = *self.started.get_or_insert_with(std::time::Instant::now);
        let elapsed = started.elapsed().as_micros() as u64;
        let allowed = self.rate.saturating_mul(elapsed) / 1_000_000;
        Some(allowed.saturating_sub(self.sent))
    }
}

async fn splice<A, B>(mut a: A, mut b: B) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    splice_rated(a, b, 0, 0).await
}

/// nginx puts `proxy_*_rate` on the **write** side: reads stay unthrottled and
/// only the bytes handed to the peer are paced (`c->write_rate`). Throttling the
/// reads instead breaks sessions, because a client that half-closes after
/// sending makes `read` return 0 and the loop exits with the response still
/// buffered -- measured as "download - data" receiving 1 of 1011 bytes.
/// Wait long enough that the budget covers the whole buffer, then write it in
/// one go.
///
/// Dribbling a byte at a time is wrong even though the average rate is the same:
/// a peer that does a single `read` only ever sees the first byte, and a test
/// backend built that way answers '1' instead of the 1000 bytes it was sent
/// (`stream_limit_rate.t`, "exact limit"). Delaying *before* the write and then
/// handing over the whole buffer keeps both properties -- the peer receives
/// complete records and the transfer still averages `rate` bytes per second.
///
/// A wait longer than five seconds is not worth blocking on, so the buffer is
/// then split and the excess is carried by later iterations; that keeps a large
/// transfer flowing at the configured rate instead of stalling for minutes.
async fn write_paced<W>(w: &mut W, mut buf: &[u8], rate: &mut Rate) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    const MAX_WAIT_US: u64 = 5_000_000;

    while !buf.is_empty() {
        let want = match rate.allowance() {
            None => buf.len(),
            Some(n) if n as usize >= buf.len() => buf.len(),
            Some(n) => {
                let need = buf.len() as u64 - n;
                let wait_us = need.saturating_mul(1_000_000) / rate.rate.max(1);
                if wait_us <= MAX_WAIT_US {
                    tokio::time::sleep(std::time::Duration::from_micros(wait_us)).await;
                    continue;
                }
                // Too long to wait for the whole thing: send one second's worth.
                (rate.rate.max(1) as usize).min(buf.len())
            }
        };
        let n = w.write(&buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "stream write returned 0",
            ));
        }
        rate.sent += n as u64;
        buf = &buf[n..];
    }
    w.flush().await

}

/// Resolve an expanded `proxy_pass` value: `host:port`, or just `host` (which is
/// an error in nginx: "no port in upstream"), through `resolver`.
async fn resolve_var_peer(
    text: &str,
    resolver: Option<&std::sync::Arc<crate::resolver::Resolver>>,
    timeout: std::time::Duration,
) -> Result<(SocketAddr, String), String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty proxy_pass value".to_string());
    }
    if let Ok(a) = text.parse::<SocketAddr>() {
        return Ok((a, text.to_string()));
    }
    // `ngx_stream_proxy_module`: a name without a port is rejected outright.
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h, p),
            Err(_) => return Err(format!("no port in upstream \"{text}\"")),
        },
        None => return Err(format!("no port in upstream \"{text}\"")),
    };
    let r = resolver.ok_or_else(|| format!("no resolver defined to resolve {host}"))?;
    let ip = match tokio::time::timeout(timeout, crate::resolver::resolve(r, host)).await {
        Ok(Some(mut v)) => match v.pop() {
            Some(ip) => ip,
            None => return Err(format!("{host} could not be resolved")),
        },
        _ => return Err(format!("{host} could not be resolved")),
    };
    Ok((SocketAddr::new(ip, port), text.to_string()))
}

async fn splice_rated<A, B>(
    mut a: A,
    mut b: B,
    upload_rate: u64,
    download_rate: u64,
) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut up = Rate::new(upload_rate);
    let mut down = Rate::new(download_rate);
    let mut ab = vec![0u8; 16 * 1024];
    let mut ba = vec![0u8; 16 * 1024];
    // `$upstream_bytes_sent` / `$upstream_bytes_received` count what went to and
    // came from `b`, i.e. the upstream.
    let mut sent = 0u64;
    let mut received = 0u64;
    loop {
        tokio::select! {
            r = a.read(&mut ab) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_paced(&mut b, &ab[..n], &mut up).await.is_err() {
                        break;
                    }
                    sent += n as u64;
                }
            },
            r = b.read(&mut ba) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_paced(&mut a, &ba[..n], &mut down).await.is_err() {
                        break;
                    }
                    received += n as u64;
                }
            },
        }
    }
    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    (sent, received)

}

/// Splice a TLS-terminated client to a plaintext upstream.
async fn proxy_io<C>(
    client: C,
    upstream: UpConn,
    _idle: Duration,
    _peer: SocketAddr,
) -> (u64, u64)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    splice(client, upstream).await
}

/// Serve `return <text>` on a stream listener, expanding the few variables a
/// stream server can see (`$ssl_session_reused`).
/// Writes one `access_log` line when a stream connection ends.
///
/// nginx logs `$status` 200 for a session that ended normally and 500 when the
/// session ended in an error (`ngx_stream_log_handler` on
/// `c->error`), which is what a failed TLS handshake produces. `Drop` is used
/// because the connection paths have many early returns.
pub struct StreamAccessLog {
    logs: Vec<crate::config::AccessLog>,
    logger: std::sync::Arc<crate::log::Logger>,
    peer: SocketAddr,
    listen: SocketAddr,
    protocol: &'static str,
    started: std::time::Instant,
    pub status: u16,
    /// One entry per upstream attempt: nginx logs `$upstream_addr` and the byte
    /// counters as comma-separated per-try lists, so a retry after a refused
    /// connect shows both peers (`stream_upstream.t`, "per-upstream variables").
    attempts: Vec<StreamAttempt>,
}

#[derive(Debug, Clone)]
struct StreamAttempt {
    addr: String,
    sent: u64,
    received: u64,
}

impl StreamAccessLog {
    pub fn new(
        server: &StreamServer,
        peer: SocketAddr,
        protocol: &'static str,
    ) -> Option<StreamAccessLog> {
        if server.access_logs.is_empty() {
            return None;
        }
        Some(StreamAccessLog {
            logs: server.access_logs.clone(),
            logger: server.logger.clone(),
            peer,
            listen: server.listen,
            protocol,
            started: std::time::Instant::now(),
            status: 200,
            attempts: Vec::new(),
        })
    }
}

impl StreamAccessLog {
    /// Record that a connection to `addr` is starting. A failed attempt keeps
    /// zero counters unless [`finish_attempt`] runs.
    pub fn start_attempt(&mut self, addr: &str) {
        self.attempts.push(StreamAttempt {
            addr: addr.to_string(),
            sent: 0,
            received: 0,
        });
    }

    pub fn finish_attempt(&mut self, sent: u64, received: u64) {
        if let Some(a) = self.attempts.last_mut() {
            a.sent = sent;
            a.received = received;
        }
    }
}

impl Drop for StreamAccessLog {
    fn drop(&mut self) {
        let now = crate::cache::now();
        let peer_ip = self.peer.ip().to_string();
        let peer_port = self.peer.port().to_string();
        let server_ip = self.listen.ip().to_string();
        let server_port = self.listen.port().to_string();
        let status = self.status.to_string();
        let session = format!("{:.3}", self.started.elapsed().as_secs_f64());
        let upstream_addr = if self.attempts.is_empty() {
            "-".to_string()
        } else {
            self.attempts
                .iter()
                .map(|a| a.addr.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let upstream_sent = if self.attempts.is_empty() {
            "-".to_string()
        } else {
            self.attempts
                .iter()
                .map(|a| a.sent.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let upstream_recv = if self.attempts.is_empty() {
            "-".to_string()
        } else {
            self.attempts
                .iter()
                .map(|a| a.received.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let vars: Vec<(&str, &str)> = vec![
            ("upstream_addr", &upstream_addr),
            ("upstream_bytes_sent", &upstream_sent),
            ("upstream_bytes_received", &upstream_recv),
            ("status", &status),
            ("remote_addr", &peer_ip),
            ("remote_port", &peer_port),
            ("server_addr", &server_ip),
            ("server_port", &server_port),
            ("protocol", self.protocol),
            ("session_time", &session),
            ("bytes_sent", "-"),
            ("bytes_received", "-"),
            ("time_local", ""),
        ];
        for log in &self.logs {
            let line = crate::http::expand_log(&log.format, &vars, now);
            self.logger.access(&log.path, line);
        }
    }
}

/// A `Vars` with no TLS facts yet: the handshake, when there is one, fills them.
/// The address `$remote_addr` should report.
///
/// Mirrors `ngx_stream_realip_handler`: nothing happens unless the server
/// configured `set_real_ip_from`, a PROXY header arrived, the peer is inside one
/// of the trusted networks (or is a unix peer with `set_real_ip_from unix:`),
/// and the header's source address parses. The port always comes from the
/// header, so `$remote_port` follows it too.
fn realip_addr(
    pp: &Option<std::sync::Arc<crate::proxyproto::Pp>>,
    peer: SocketAddr,
    peer_unix: bool,
    from: &[(std::net::IpAddr, u8)],
    from_unix: bool,
) -> Option<SocketAddr> {
    let pp = pp.as_ref()?;
    if from.is_empty() && !from_unix {
        return None;
    }
    let trusted = if peer_unix {
        from_unix
    } else {
        let ip = peer.ip();
        from.iter().any(|(net, bits)| {
            crate::http::cidr_contains_pub(*net, *bits, ip)
        })
    };
    if !trusted {
        return None;
    }
    let addr: std::net::IpAddr = pp.src_addr.trim().parse().ok()?;
    Some(SocketAddr::new(addr, pp.src_port))
}

fn base_vars<'a>(
    peer: SocketAddr,
    peer_unix: bool,
    eff: Option<SocketAddr>,
    local: SocketAddr,
    maps: &'a [crate::mapping::MapDef],
    geos: &'a [crate::geo::GeoDef],
    splits: &'a [crate::split::SplitClients],
) -> crate::streamvars::Vars<'a> {
    crate::streamvars::Vars {
        peer,
        peer_unix,
        eff,
        local,
        udp: false,
        maps,
        geos,
        ssl: None,
        proxy_protocol: None,
        custom: &NO_CUSTOM,
        splits,
        connection: crate::stats::accepted(),
    }
}

/// The empty `set` table, for the phase before any `set` has been evaluated.
static NO_CUSTOM: std::sync::LazyLock<std::collections::HashMap<String, String>> =
    std::sync::LazyLock::new(std::collections::HashMap::new);

async fn answer_stream_return(
    mut client: ClientIo,
    tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    text: &str,
    verify_mode: u8,
    client_ca: &Option<std::path::PathBuf>,
    trusted_ca: &Option<std::path::PathBuf>,
    log: Option<&mut StreamAccessLog>,
    base: &crate::streamvars::Vars<'_>,
) {
    let reused = match tls {
        Some(sc) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(sc);
            match acceptor.accept(client).await {
                Ok(mut t) => {
                    let facts = ssl_facts(t.get_ref().1, verify_mode, client_ca, trusted_ca);
                    let v = crate::streamvars::Vars {
                        ssl: Some(&facts),
                        ..*base
                    };
                    let body = v.expand(text);
                    let _ = t.write_all(body.as_bytes()).await;
                    let _ = t.flush().await;
                    let _ = t.shutdown().await;
                    return;
                }
                Err(mut e) => {
                    // A failed handshake makes nginx log `$status` 500.
                    if let Some(l) = log {
                        l.status = 500;
                        let _ = &mut e;
                    }
                    return;
                }
            }
        }
        None => {
            // A `return` in a non-ssl stream server sees no TLS facts at all,
            // which is why `$ssl_client_verify:$ssl_client_cert` renders as
            // `:` there.
            let body = base.expand(text);
            let _ = client.write_all(body.as_bytes()).await;
            let _ = client.shutdown().await;
            return;
        }
    };
}

/// The `$ssl_*` facts for a terminated TLS connection.
fn ssl_facts(
    conn: &rustls::ServerConnection,
    verify_mode: u8,
    client_ca: &Option<std::path::PathBuf>,
    trusted_ca: &Option<std::path::PathBuf>,
) -> crate::streamvars::SslFacts {
    let (client_verify, client_cert) =
        client_cert_vars(conn, verify_mode, client_ca, trusted_ca);
    let protocol = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1",
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0",
        Some(rustls::ProtocolVersion::SSLv3) => "SSLv3",
        _ => "",
    }
    .to_string();
    crate::streamvars::SslFacts {
        reused: matches!(
            conn.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        ),
        // rustls does not expose the session id; TLS 1.3 has none, and the test
        // accepts it being absent.
        session_id: String::new(),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_default(),
        protocol,
        server_name: conn.server_name().unwrap_or("").to_string(),
        alpn: conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_default(),
        client_verify,
        client_cert,
    }
}

/// `$ssl_client_verify` and `$ssl_client_cert` for a stream connection.
///
/// In `optional_no_ca` mode nginx records why verification would have failed
/// while still letting the connection through, so the chain is evaluated here
/// rather than in the handshake.
fn client_cert_vars(
    conn: &rustls::ServerConnection,
    verify_mode: u8,
    client_ca: &Option<std::path::PathBuf>,
    trusted_ca: &Option<std::path::PathBuf>,
) -> (String, String) {
    let chain: Vec<_> = conn
        .peer_certificates()
        .map(|c| c.iter().map(|d| d.to_owned()).collect())
        .unwrap_or_default();
    if chain.is_empty() {
        // `off` and `on` never reach here with a missing certificate (`on`
        // fails the handshake), but `optional` does.
        return ("NONE".to_string(), String::new());
    }
    let pem = crate::tls::der_to_pem(chain[0].as_ref());
    let verify = if verify_mode == 0 {
        "NONE".to_string()
    } else {
        // nginx loads both bundles into the verify store; `ssl_trusted_certificate`
        // simply does not contribute names to the CertificateRequest.
        let paths: Vec<&std::path::Path> = [client_ca, trusted_ca]
            .into_iter()
            .flatten()
            .map(|p| p.as_path())
            .collect();
        match crate::tls::verify_client_chain_multi(paths, &chain) {
            Ok(()) => "SUCCESS".to_string(),
            Err(reason) => format!("FAILED:{reason}"),
        }
    };
    (verify, pem)
}

async fn proxy_tcp(
    client: ClientIo,
    upstream: UpConn,
    _idle: Duration,
    _peer: SocketAddr,
    upload: u64,
    download: u64,
) -> (u64, u64) {
    // The earlier comment here claimed `copy_bidirectional` returns as soon as
    // one side closes. It does not: it waits for *both* directions, so a backend
    // that answers and closes kept the session -- and the upstream connection
    // slot -- alive until the client also went away. With `proxy_half_close`
    // off (the default) nginx ends the session on the first EOF, which is what
    // `splice` now does.
    // Rates must reach the paced splice; passing them in and then
    // calling the unlimited `splice` is exactly the bug that left
    // `proxy_download_rate` silently inert.
    splice_rated(client, upstream, upload, download).await
}

async fn serve_udp(server: StreamServer, shutdown: &mut watch::Receiver<bool>) {
    let sock = match bind_udp(server.listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "ngxrs: [error] stream cannot bind {} (udp): {e}",
                server.listen
            );
            return;
        }
    };
    crate::log::log_global(
        crate::log::Level::Notice,
        &format!("stream listening on {} (udp)", server.listen),
    );
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
                // UDP: one backend per client session, chosen once so the
                // session keeps talking to the same peer.
                let mut tried = vec![false; server.peers.len()];
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let backend = match server.peers.pick(&mut tried, None, now) {
                    Some(i) => {
                        // A UDP "connection" is a session, not a socket: the
                        // slot is taken for the pick and released at once so a
                        // long-lived session does not pin `max_conns`.
                        let a = server.peers.addr(i);
                        server.peers.release(i, true, now);
                        a
                    }
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
