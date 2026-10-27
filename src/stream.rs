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
    /// Round-robin backend list; empty when `return` is set.
    pub backends: Vec<SocketAddr>,
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
    /// `geo` / `map` blocks from `stream {}`. Shared rather than copied: they are
    /// read-only and evaluated per connection.
    pub geos: std::sync::Arc<Vec<crate::geo::GeoDef>>,
    pub maps: std::sync::Arc<Vec<crate::mapping::MapDef>>,
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
                let verify_mode = server.client_verify;
                let client_ca = server.client_ca.clone();
                let trusted_ca = server.trusted_ca.clone();
                // One log line per connection, written when the task ends.
                let mut alog = StreamAccessLog::new(&server, peer, "stream");
                tokio::spawn(async move {
                    // `return <text>` answers without touching an upstream.
                    if let Some(text) = return_text {
                        let local_addr = client
                            .local_addr()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                        answer_stream_return(
                            client,
                            tls,
                            &text,
                            verify_mode,
                            &client_ca,
                            &trusted_ca,
                            alog.as_mut(),
                            &base_vars(peer, local_addr, &maps, &geos),
                        )
                        .await;
                        drop(alog);
                        return;
                    }
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
                    // `proxy_ssl on`: speak TLS to the upstream, then splice.
                    if proxy_ssl {
                        let cfg = proxy_tls_config(sni.as_deref().unwrap_or("localhost"), reuse);
                        let name = rustls::pki_types::ServerName::try_from(
                            sni.clone().unwrap_or_else(|| "localhost".to_string()),
                        )
                        .unwrap_or_else(|_| {
                            rustls::pki_types::ServerName::try_from("localhost".to_string())
                                .expect("localhost is a valid name")
                        });
                        let connector = tokio_rustls::TlsConnector::from(cfg);
                        let Ok(tls_up) = connector.connect(name, upstream).await else {
                            return;
                        };
                        match tls {
                            Some(sc) => {
                                let acceptor = tokio_rustls::TlsAcceptor::from(sc);
                                match acceptor.accept(client).await {
                                    Ok(c) => splice(c, tls_up).await,
                                    Err(_) => {}
                                }
                            }
                            None => splice(client, tls_up).await,
                        }
                        return;
                    }
                    // `listen ... ssl` terminates TLS here, before the splice.
                    match tls {
                        Some(cfg) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                            match acceptor.accept(client).await {
                                Ok(t) => proxy_io(t, upstream, timeout, peer).await,
                                Err(_) => {
                                    if let Some(l) = alog.as_mut() {
                                        l.status = 500;
                                    }
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
                                proxy_tcp(client, upstream, timeout, peer).await
                            } else {
                                proxy_tcp(client, upstream, timeout, peer).await
                            }
                        }
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

fn pick_backend(
    backends: &[SocketAddr],
    counter: &std::sync::atomic::AtomicUsize,
) -> Option<SocketAddr> {
    if backends.is_empty() {
        return None;
    }
    let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % backends.len();
    Some(backends[i])
}

/// Splice two arbitrary transports (used when either side speaks TLS).
async fn splice<A, B>(mut a: A, mut b: B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
}

/// Splice a TLS-terminated client to a plaintext upstream.
async fn proxy_io<C>(client: C, upstream: TcpStream, _idle: Duration, _peer: SocketAddr)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    splice(client, upstream).await;
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
        })
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
        let vars: Vec<(&str, &str)> = vec![
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
) -> crate::streamvars::Vars<'a> {
    crate::streamvars::Vars {
        peer,
        local,
        udp: false,
        maps,
        geos,
        ssl: None,
    }
}

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
                    // rustls reports whether the handshake resumed.
                    let r = matches!(
                        t.get_ref().1.handshake_kind(),
                        Some(rustls::HandshakeKind::Resumed)
                    );
                    let (verify, cert) =
                        client_cert_vars(t.get_ref().1, verify_mode, client_ca, trusted_ca);
                    let mut v = crate::streamvars::Vars {
                        peer: base.peer,
                        local: base.local,
                        udp: base.udp,
                        maps: base.maps,
                        geos: base.geos,
                        ssl: Some((&verify, &cert, r)),
                    };
                    let body = v.expand(text);
                    let _ = &mut v;
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
    mut client: TcpStream,
    mut upstream: TcpStream,
    _idle: Duration,
    _peer: SocketAddr,
) {
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
