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
#[derive(Clone)]
pub struct StreamServer {
    pub listen: SocketAddr,
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
            crate::log::log_global(
                crate::log::Level::Emerg,
                &format!("stream cannot bind {}: {e}", server.listen),
            );
            return;
        }
    };
    crate::log::log_global(
        crate::log::Level::Notice,
        &format!("stream listening on {} (tcp)", server.listen),
    );

    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // The address the *client* connected to, which is what the
                // PROXY header advertises as the destination. Taking the
                // upstream's local address instead produced a mixed-family
                // pair (127.0.0.1 -> [::1]) and therefore `PROXY UNKNOWN`.
                let client_local = client.local_addr().ok();
                let _ = client.set_nodelay(true);
                // nginx logs stream connections at `info`: the peer, the local
                // address and the chosen upstream.
                let local = client.local_addr().ok();
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
                let verify_mode = server.client_verify;
                let client_ca = server.client_ca.clone();
                let trusted_ca = server.trusted_ca.clone();
                // One log line per connection, written when the task ends.
                let mut alog = StreamAccessLog::new(&server, peer, "stream");
                tokio::spawn(async move {
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
                    // `return <text>` answers without touching an upstream.
                    if let Some(text) = return_text {
                        let local_addr = client
                            .local_addr()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                        let mut base = base_vars(peer, local_addr, &maps, &geos, &splits);
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
                    let mut tried = vec![false; peers.len()];
                    let mut chosen: Option<crate::streamlb::Guard> = None;
                    let mut upstream = None;
                    let mut attempts = 0usize;
                    while attempts < peers.len().max(1) * 2 {
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
                                    let (a, b) = proxy_tcp(client, upstream, timeout, peer).await;
                                    (a, b)
                                } else {
                                    proxy_tcp(client, upstream, timeout, peer).await
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

async fn splice<A, B>(mut a: A, mut b: B) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
                    if b.write_all(&ab[..n]).await.is_err() {
                        break;
                    }
                    sent += n as u64;
                }
            },
            r = b.read(&mut ba) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if a.write_all(&ba[..n]).await.is_err() {
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
fn base_vars<'a>(
    peer: SocketAddr,
    local: SocketAddr,
    maps: &'a [crate::mapping::MapDef],
    geos: &'a [crate::geo::GeoDef],
    splits: &'a [crate::split::SplitClients],
) -> crate::streamvars::Vars<'a> {
    crate::streamvars::Vars {
        peer,
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
    mut client: TcpStream,
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
    client: TcpStream,
    upstream: UpConn,
    _idle: Duration,
    _peer: SocketAddr,
) -> (u64, u64) {
    // The earlier comment here claimed `copy_bidirectional` returns as soon as
    // one side closes. It does not: it waits for *both* directions, so a backend
    // that answers and closes kept the session -- and the upstream connection
    // slot -- alive until the client also went away. With `proxy_half_close`
    // off (the default) nginx ends the session on the first EOF, which is what
    // `splice` now does.
    splice(client, upstream).await
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
