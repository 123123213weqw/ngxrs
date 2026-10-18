//! `mail {}` — POP3 / IMAP / SMTP authenticating proxy.
//!
//! nginx speaks each client protocol just far enough to collect credentials,
//! asks an HTTP endpoint (`auth_http`) where the user's real mailbox lives, and
//! then splices the client onto that backend. This module follows the same
//! shape: `auth_http` is a plain HTTP/1.0 GET whose request headers carry the
//! credentials and whose response headers carry the routing decision.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::config::typed::MailServer;

/// Which client protocol a listener speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Pop3,
    Imap,
    Smtp,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Pop3 => "pop3",
            Protocol::Imap => "imap",
            Protocol::Smtp => "smtp",
        }
    }
}

/// Parsed `auth_http <url>`.
#[derive(Debug, Clone)]
pub struct AuthHttp {
    pub host: String,
    pub port: u16,
    pub uri: String,
    /// `auth_http_header name value`
    pub headers: Vec<(String, String)>,
}

impl AuthHttp {
    pub fn parse(url: &str) -> Option<AuthHttp> {
        let rest = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))?;
        let (authority, uri) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), 80),
        };
        Some(AuthHttp {
            host,
            port,
            uri,
            headers: Vec::new(),
        })
    }
}

/// Credentials collected from the client.
#[derive(Debug, Default)]
struct Session {
    method: &'static str,
    user: String,
    passwd: String,
    /// `Auth-Salt` for APOP / CRAM-MD5.
    salt: String,
    /// Credentials the client already sent, replayed to the backend once the
    /// routing decision is made.
    replay: Vec<u8>,
    /// IMAP command tag of the command being authorised.
    tag: String,
    /// `MAIL FROM` / `RCPT TO` address, sent as `Auth-SMTP-To`.
    smtp_to: String,
}

impl Session {
    fn new() -> Self {
        Session {
            method: "",
            ..Default::default()
        }
    }
}

/// What `auth_http` told us to do.
#[derive(Debug)]
struct AuthReply {
    ok: bool,
    wait: bool,
    server: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    pass: Option<String>,
    error: String,
    error_code: Option<String>,
}

/// Run every mail listener until `shutdown` fires.
pub async fn serve(servers: Vec<MailServer>, mut shutdown: watch::Receiver<bool>) {
    let mut handles = Vec::new();
    for server in servers {
        let mut sd = shutdown.clone();
        handles.push(tokio::spawn(async move {
            serve_one(server, &mut sd).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

async fn serve_one(server: MailServer, shutdown: &mut watch::Receiver<bool>) {
    let listener = match crate::stream::bind_tcp(server.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ngxrs: [error] mail cannot bind {}: {e}", server.listen);
            return;
        }
    };
    eprintln!(
        "ngxrs: mail listening on {} ({})",
        server.listen,
        server.protocol.name()
    );
    let server = Arc::new(server);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let _ = client.set_nodelay(true);
                let server = server.clone();
                tokio::spawn(async move {
                    let _ = handle(client, peer, server).await;
                });
            }
        }
    }
}

async fn handle(client: TcpStream, peer: SocketAddr, server: Arc<MailServer>) -> io::Result<()> {
    let (rd, wr) = client.into_split();
    let mut reader = BufReader::new(rd);
    let mut writer = BufWriter::new(wr);

    match server.protocol {
        Protocol::Pop3 => pop3(&mut reader, &mut writer, &peer, &server).await,
        Protocol::Imap => imap(&mut reader, &mut writer, &peer, &server).await,
        Protocol::Smtp => smtp(&mut reader, &mut writer, &peer, &server).await,
    }
}

/// Read one CRLF- (or LF-) terminated line, as nginx does for these protocols.
async fn read_line<R: AsyncReadExt + Unpin>(reader: &mut BufReader<R>) -> io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > 8192 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

// ---------------------------------------------------------------------------
// auth_http
// ---------------------------------------------------------------------------

/// Ask `auth_http` where this user's mailbox lives.
async fn auth_request(
    http: &AuthHttp,
    session: &Session,
    server: &MailServer,
    peer: &SocketAddr,
) -> Option<AuthReply> {
    let addr = resolve(&http.host, http.port).await?;
    let stream = tokio::time::timeout(server.auth_http_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    stream.set_nodelay(true).ok();

    let mut req = Vec::with_capacity(512);
    req.extend_from_slice(format!("GET {} HTTP/1.0\r\n", http.uri).as_bytes());
    req.extend_from_slice(format!("Host: {}\r\n", http.host).as_bytes());
    for (k, v) in &http.headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    req.extend_from_slice(format!("Auth-Method: {}\r\n", session.method).as_bytes());
    if !session.user.is_empty() {
        req.extend_from_slice(format!("Auth-User: {}\r\n", session.user).as_bytes());
    }
    // nginx omits the password when the authenticator only needs the digest.
    if !session.passwd.is_empty() {
        req.extend_from_slice(format!("Auth-Pass: {}\r\n", session.passwd).as_bytes());
    }
    if !session.salt.is_empty() {
        req.extend_from_slice(format!("Auth-Salt: {}\r\n", session.salt).as_bytes());
    }
    req.extend_from_slice(format!("Auth-Protocol: {}\r\n", server.protocol.name()).as_bytes());
    if !session.smtp_to.is_empty() {
        req.extend_from_slice(format!("Auth-SMTP-To: {}\r\n", session.smtp_to).as_bytes());
    }
    req.extend_from_slice(b"Auth-Login-Attempt: 1\r\n");
    req.extend_from_slice(format!("Client-IP: {}\r\n", peer.ip()).as_bytes());
    req.extend_from_slice(format!("Client-Host: {}\r\n", peer.ip()).as_bytes());
    req.extend_from_slice(b"\r\n");

    let (rd, mut wr) = stream.into_split();
    wr.write_all(&req).await.ok()?;
    wr.flush().await.ok()?;

    let mut reader = BufReader::new(rd);
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(server.auth_http_timeout, reader.read(&mut byte))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > 16384 {
            return None;
        }
    }
    Some(parse_auth_reply(&head))
}

async fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .next()
}

/// Turn the response headers into a decision.
///
/// Only `Auth-Status: OK` authorises the user; `WAIT` delays the rejection, and
/// anything else is the text to show (nginx uses it verbatim).
fn parse_auth_reply(head: &[u8]) -> AuthReply {
    let text = String::from_utf8_lossy(head);
    let mut map: HashMap<String, String> = HashMap::new();
    for line in text.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let status = map.get("auth-status").cloned().unwrap_or_default();
    let ok = status.eq_ignore_ascii_case("OK");
    let wait = status.eq_ignore_ascii_case("WAIT");
    AuthReply {
        ok,
        wait,
        server: map.get("auth-server").cloned(),
        port: map.get("auth-port").and_then(|p| p.parse().ok()),
        user: map.get("auth-user").cloned(),
        pass: map.get("auth-pass").cloned(),
        error: if ok || wait { String::new() } else { status },
        error_code: map.get("auth-error-code").cloned(),
    }
}

/// Read one line from an arbitrary reader (used for the upstream dialogue).
async fn read_line_plain<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > 8192 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

// ---------------------------------------------------------------------------
// POP3
// ---------------------------------------------------------------------------

const POP3_GREETING: &[u8] = b"+OK POP3 ready\r\n";

async fn pop3<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    peer: &SocketAddr,
    server: &MailServer,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // With APOP enabled nginx appends `<pid.seq@host>` to the greeting so the
    // client can digest it; the authenticator then sees it as `Auth-Salt`.
    let apop_salt = if server.auth_apop { make_salt() } else { String::new() };
    if apop_salt.is_empty() {
        writer.write_all(POP3_GREETING).await?;
    } else {
        writer
            .write_all(format!("+OK POP3 ready {apop_salt}\r\n").as_bytes())
            .await?;
    }
    writer.flush().await?;

    let mut s = Session::new();
    // Set once `USER` has been accepted, so `PASS` knows a login is pending.
    let mut have_user = false;

    loop {
        let line = match read_line(reader).await {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };
        let trimmed = line.trim_end();
        let (cmd, rest) = match trimmed.split_once(' ') {
            Some((c, r)) => (c.to_ascii_uppercase(), r.trim().to_string()),
            None => (trimmed.to_ascii_uppercase(), String::new()),
        };

        match cmd.as_str() {
            "QUIT" => {
                writer.write_all(b"+OK bye\r\n").await?;
                writer.flush().await?;
                return Ok(());
            }
            "CAPA" => {
                writer
                    .write_all(b"+OK\r\nUSER\r\nSASL\r\n.\r\n")
                    .await?;
                writer.flush().await?;
            }
            "USER" => {
                s.user = rest;
                s.method = "user";
                s.replay.extend_from_slice(line.as_bytes());
                s.replay.extend_from_slice(b"\r\n");
                have_user = true;
                writer.write_all(b"+OK\r\n").await?;
                writer.flush().await?;
            }
            "PASS" => {
                if !have_user {
                    writer.write_all(b"-ERR no USER\r\n").await?;
                    writer.flush().await?;
                    continue;
                }
                s.passwd = rest;
                s.replay.extend_from_slice(line.as_bytes());
                s.replay.extend_from_slice(b"\r\n");
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Pop3).await? {
                    return proxy(o, reader, writer, &s.replay, server, Protocol::Pop3).await;
                }
            }
            "APOP" => {
                let mut parts = rest.splitn(2, ' ');
                s.user = parts.next().unwrap_or("").to_string();
                s.passwd = parts.next().unwrap_or("").to_string();
                s.method = "apop";
                s.salt = apop_salt.clone();
                s.replay.extend_from_slice(line.as_bytes());
                s.replay.extend_from_slice(b"\r\n");
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Pop3).await? {
                    return proxy(o, reader, writer, &s.replay, server, Protocol::Pop3).await;
                }
            }
            "AUTH" => {
                // Bare `AUTH` advertises the mechanisms, one per line, then `.`
                if rest.is_empty() {
                    writer.write_all(b"+OK\r\n").await?;
                    for m in pop3_mechanisms(server) {
                        writer
                            .write_all(format!("{m}\r\n").as_bytes())
                            .await?;
                    }
                    writer.write_all(b".\r\n").await?;
                    writer.flush().await?;
                    continue;
                }
                match pop3_auth(reader, writer, &rest, &mut s, server).await? {
                    Some(()) => {
                        if let Some(o) =
                            authorise(writer, &s, server, peer, Protocol::Pop3).await?
                        {
                            return proxy(o, reader, writer, &s.replay, server, Protocol::Pop3).await;
                        }
                    }
                    None => continue,
                }
            }
            _ => {
                writer.write_all(b"-ERR unknown command\r\n").await?;
                writer.flush().await?;
            }
        }
    }
}

/// The address inside `MAIL FROM:<...>` / `RCPT TO:<...>`.
fn smtp_address(line: &str) -> String {
    let start = match line.find('<') {
        Some(i) => i + 1,
        None => return String::new(),
    };
    let end = line[start..].find('>').map(|e| start + e).unwrap_or(line.len());
    line[start..end].to_string()
}

/// `<pid.seq@host>`, the shape nginx uses for its APOP banner.
fn make_salt() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    format!(
        "<{}.{}@{}>",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        host
    )
}

/// Mechanisms advertised by a bare POP3 `AUTH`, in nginx's order.
fn pop3_mechanisms(server: &MailServer) -> Vec<&'static str> {
    let mut out = Vec::new();
    if server.auth_plain {
        out.push("PLAIN");
    }
    // LOGIN is always available; `pop3_auth` cannot disable it.
    out.push("LOGIN");
    if server.auth_cram_md5 {
        out.push("CRAM-MD5");
    }
    if server.auth_external {
        out.push("EXTERNAL");
    }
    out
}

/// Handle `AUTH <mechanism> [initial-response]`. Returns `Some(())` once
/// credentials have been collected and the session may be authorised.
async fn pop3_auth<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    rest: &str,
    s: &mut Session,
    server: &MailServer,
) -> io::Result<Option<()>>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut parts = rest.splitn(2, ' ');
    let mech = parts.next().unwrap_or("").to_ascii_uppercase();
    let arg = parts.next().map(|a| a.trim().to_string());

    match mech.as_str() {
        "PLAIN" => {
            if !server.auth_plain {
                writer.write_all(b"-ERR unsupported\r\n").await?;
                writer.flush().await?;
                return Ok(None);
            }
            let data = match arg {
                Some(a) if !a.is_empty() => a,
                _ => {
                    writer.write_all(b"+ \r\n").await?;
                    writer.flush().await?;
                    read_line(reader).await?
                }
            };
            // `\0user\0pass`
            let decoded = match crate::util::base64_decode(&data) {
                Some(d) => d,
                None => {
                    writer.write_all(b"-ERR invalid base64\r\n").await?;
                    writer.flush().await?;
                    return Ok(None);
                }
            };
            let text = String::from_utf8_lossy(&decoded).to_string();
            let fields: Vec<&str> = text.split('\0').collect();
            if fields.len() < 3 {
                writer.write_all(b"-ERR invalid response\r\n").await?;
                writer.flush().await?;
                return Ok(None);
            }
            s.method = "plain";
            s.user = fields[fields.len() - 2].to_string();
            s.passwd = fields[fields.len() - 1].to_string();
            s.replay
                .extend_from_slice(format!("AUTH PLAIN {data}\r\n").as_bytes());
            Ok(Some(()))
        }
        "LOGIN" => {
            if !server.auth_login {
                writer.write_all(b"-ERR unsupported\r\n").await?;
                writer.flush().await?;
                return Ok(None);
            }
            let mut replay = String::from("AUTH LOGIN");
            let user_b64 = match arg {
                Some(a) if !a.is_empty() => {
                    replay.push(' ');
                    replay.push_str(&a);
                    a
                }
                _ => {
                    writer.write_all(b"+ VXNlcm5hbWU6\r\n").await?;
                    writer.flush().await?;
                    let l = read_line(reader).await?;
                    replay.push(' ');
                    replay.push_str(&l);
                    l
                }
            };
            let user = String::from_utf8_lossy(
                &crate::util::base64_decode(&user_b64).unwrap_or_default(),
            )
            .to_string();

            writer.write_all(b"+ UGFzc3dvcmQ6\r\n").await?;
            writer.flush().await?;
            let pass_b64 = read_line(reader).await?;
            let pass = String::from_utf8_lossy(
                &crate::util::base64_decode(&pass_b64).unwrap_or_default(),
            )
            .to_string();

            s.method = "login";
            s.user = user;
            s.passwd = pass;
            s.replay
                .extend_from_slice(format!("{replay}\r\n{pass_b64}\r\n").as_bytes());
            Ok(Some(()))
        }
        "CRAM-MD5" => {
            if !server.auth_cram_md5 {
                writer.write_all(b"-ERR unsupported\r\n").await?;
                writer.flush().await?;
                return Ok(None);
            }
            // The digest must come from the authenticator, so this is a two-leg
            // exchange: ask for a salt, hand it to the client, then forward the
            // response.
            let challenge = crate::util::base64_encode(b"<1@ngxrs>");
            writer
                .write_all(format!("+ {challenge}\r\n").as_bytes())
                .await?;
            writer.flush().await?;
            let resp = read_line(reader).await?;
            let decoded =
                String::from_utf8_lossy(&crate::util::base64_decode(&resp).unwrap_or_default())
                    .to_string();
            let mut it = decoded.splitn(2, ' ');
            s.user = it.next().unwrap_or("").to_string();
            s.passwd = it.next().unwrap_or("").to_string();
            s.method = "cram-md5";
            s.salt = String::from_utf8_lossy(&crate::util::base64_decode(&challenge).unwrap_or_default()).to_string();
            s.replay
                .extend_from_slice(format!("AUTH CRAM-MD5\r\n{resp}\r\n").as_bytes());
            Ok(Some(()))
        }
        "EXTERNAL" => {
            if !server.auth_external {
                writer.write_all(b"-ERR unsupported\r\n").await?;
                writer.flush().await?;
                return Ok(None);
            }
            // Without an initial response the client is prompted, exactly as
            // nginx does, and the base64 line is forwarded to the backend.
            let mut replay = String::from("AUTH EXTERNAL");
            match arg {
                Some(a) if !a.is_empty() => {
                    replay.push(' ');
                    replay.push_str(&a);
                }
                _ => {
                    writer.write_all(b"+ \r\n").await?;
                    writer.flush().await?;
                    let r = read_line(reader).await?;
                    replay.push(' ');
                    replay.push_str(&r);
                }
            }
            s.method = "external";
            s.replay.extend_from_slice(format!("{replay}\r\n").as_bytes());
            Ok(Some(()))
        }
        _ => {
            writer.write_all(b"-ERR unsupported\r\n").await?;
            writer.flush().await?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// IMAP / SMTP (auth phase)
// ---------------------------------------------------------------------------

const IMAP_GREETING: &[u8] = b"* OK IMAP4 ready\r\n";

async fn imap<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    peer: &SocketAddr,
    server: &MailServer,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    writer.write_all(IMAP_GREETING).await?;
    writer.flush().await?;

    let mut s = Session::new();
    loop {
        let line = match read_line(reader).await {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };
        let mut it = line.trim_end().splitn(3, ' ');
        let tag = it.next().unwrap_or("").to_string();
        let cmd = it.next().unwrap_or("").to_ascii_uppercase();
        let rest = it.next().unwrap_or("").to_string();

        match cmd.as_str() {
            "CAPABILITY" => {
                writer
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4 AUTH={}\r\n{tag} OK\r\n",
                            imap_mechanisms(server).join(" ")
                        )
                        .as_bytes(),
                    )
                    .await?;
                writer.flush().await?;
            }
            "LOGOUT" => {
                writer
                    .write_all(format!("* BYE\r\n{tag} OK\r\n").as_bytes())
                    .await?;
                writer.flush().await?;
                return Ok(());
            }
            "LOGIN" => {
                let mut parts = rest.splitn(2, ' ');
                let u = parts.next().unwrap_or("");
                let p = parts.next();
                if u.is_empty() || p.is_none() {
                    // nginx answers a malformed LOGIN with BAD, not NO.
                    writer
                        .write_all(format!("{tag} BAD invalid arguments\r\n").as_bytes())
                        .await?;
                    writer.flush().await?;
                    continue;
                }
                s.user = imap_arg(u);
                s.passwd = imap_arg(p.unwrap_or(""));
                s.method = "login";
                s.tag = tag.clone();
                s.replay
                    .extend_from_slice(format!("{line}\r\n").as_bytes());
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Imap).await? {
                    return proxy(o, reader, writer, &s.replay, server, Protocol::Imap).await;
                }
            }
            "AUTHENTICATE" => {
                // `AUTHENTICATE <mech> [initial-response]`: only the mechanism
                // name is case-insensitive, so split before upper-casing.
                let mut mp = rest.splitn(2, ' ');
                let mech = mp.next().unwrap_or("").to_ascii_uppercase();
                // `AUTHENTICATE` without a mechanism is a syntax error.
                if mech.is_empty() {
                    writer
                        .write_all(format!("{tag} BAD invalid arguments\r\n").as_bytes())
                        .await?;
                    writer.flush().await?;
                    continue;
                }
                // An inline initial response replaces the `+` continuation.
                let inline = mp.next().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
                s.method = match mech.as_str() {
                    "PLAIN" => "PLAIN",
                    "LOGIN" => "LOGIN",
                    "CRAM-MD5" => "CRAM-MD5",
                    "EXTERNAL" => "EXTERNAL",
                    _ => {
                        writer
                            .write_all(format!("{tag} NO unsupported\r\n").as_bytes())
                            .await?;
                        writer.flush().await?;
                        continue;
                    }
                };
                s.tag = tag.clone();
                s.replay
                    .extend_from_slice(format!("{line}\r\n").as_bytes());
                match s.method {
                    "PLAIN" => {
                        let resp = match inline.clone() {
                            Some(v) => v,
                            None => {
                                writer.write_all(b"+ \r\n").await?;
                                writer.flush().await?;
                                read_line(reader).await?
                            }
                        };
                        let text = String::from_utf8_lossy(
                            &crate::util::base64_decode(&resp).unwrap_or_default(),
                        )
                        .to_string();
                        let f: Vec<&str> = text.split('\0').collect();
                        if f.len() >= 3 {
                            s.user = f[f.len() - 2].to_string();
                            s.passwd = f[f.len() - 1].to_string();
                        }
                        s.replay
                            .extend_from_slice(format!("{resp}\r\n").as_bytes());
                    }
                    "LOGIN" => {
                        let u = match inline.clone() {
                            Some(v) => v,
                            None => {
                                writer.write_all(b"+ VXNlcm5hbWU6\r\n").await?;
                                writer.flush().await?;
                                read_line(reader).await?
                            }
                        };
                        s.user = String::from_utf8_lossy(
                            &crate::util::base64_decode(&u).unwrap_or_default(),
                        )
                        .to_string();
                        writer.write_all(b"+ UGFzc3dvcmQ6\r\n").await?;
                        writer.flush().await?;
                        let p = read_line(reader).await?;
                        s.passwd = String::from_utf8_lossy(
                            &crate::util::base64_decode(&p).unwrap_or_default(),
                        )
                        .to_string();
                        s.replay
                            .extend_from_slice(format!("{u}\r\n{p}\r\n").as_bytes());
                    }
                    "CRAM-MD5" => {
                        let challenge = crate::util::base64_encode(b"<1@ngxrs>");
                        writer
                            .write_all(format!("+ {challenge}\r\n").as_bytes())
                            .await?;
                        writer.flush().await?;
                        let r = read_line(reader).await?;
                        let d = String::from_utf8_lossy(
                            &crate::util::base64_decode(&r).unwrap_or_default(),
                        )
                        .to_string();
                        let mut sp = d.splitn(2, ' ');
                        s.user = sp.next().unwrap_or("").to_string();
                        s.passwd = sp.next().unwrap_or("").to_string();
                        s.replay.extend_from_slice(format!("{r}\r\n").as_bytes());
                    }
                    _ => {}
                }
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Imap).await? {
                    return proxy(o, reader, writer, &s.replay, server, Protocol::Imap).await;
                }
            }
            _ => {
                writer
                    .write_all(format!("{tag} BAD unsupported\r\n").as_bytes())
                    .await?;
                writer.flush().await?;
            }
        }
    }
}

fn imap_mechanisms(server: &MailServer) -> Vec<&'static str> {
    let mut out = Vec::new();
    if server.auth_plain {
        out.push("PLAIN");
    }
    out.push("LOGIN");
    if server.auth_cram_md5 {
        out.push("CRAM-MD5");
    }
    if server.auth_external {
        out.push("EXTERNAL");
    }
    out
}

fn imap_arg(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

async fn smtp<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    peer: &SocketAddr,
    server: &MailServer,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // nginx puts its own `server_name` in the banner.
    writer
        .write_all(format!("220 {} ESMTP ready\r\n", server.name).as_bytes())
        .await?;
    writer.flush().await?;

    let mut s = Session::new();
    loop {
        let line = match read_line(reader).await {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };
        let trimmed = line.trim_end();
        let (cmd, rest) = match trimmed.split_once(' ') {
            Some((c, r)) => (c.to_ascii_uppercase(), r.trim().to_string()),
            None => (trimmed.to_ascii_uppercase(), String::new()),
        };
        match cmd.as_str() {
            "QUIT" => {
                writer.write_all(b"221 bye\r\n").await?;
                writer.flush().await?;
                return Ok(());
            }
            "EHLO" | "HELO" => {
                let mechs = smtp_mechanisms(server);
                let mut out = format!("250-{}\r\n", server.name);
                if !mechs.is_empty() {
                    out.push_str(&format!("250-AUTH {}\r\n", mechs.join(" ")));
                }
                out.push_str("250 8BITMIME\r\n");
                writer.write_all(out.as_bytes()).await?;
                writer.flush().await?;
            }
            "AUTH" => {
                let mut parts = rest.splitn(2, ' ');
                let mech = parts.next().unwrap_or("").to_ascii_uppercase();
                let arg = parts.next().map(|a| a.trim().to_string());
                match mech.as_str() {
                    "PLAIN" => {
                        let data = match arg {
                            Some(a) if !a.is_empty() => a,
                            _ => {
                                writer.write_all(b"334 \r\n").await?;
                                writer.flush().await?;
                                read_line(reader).await?
                            }
                        };
                        let d = crate::util::base64_decode(&data).unwrap_or_default();
                        let text = String::from_utf8_lossy(&d).to_string();
                        let f: Vec<&str> = text.split('\0').collect();
                        if f.len() < 3 {
                            writer.write_all(b"501 5.5.2 bad response\r\n").await?;
                            writer.flush().await?;
                            continue;
                        }
                        s.method = "plain";
                        s.user = f[f.len() - 2].to_string();
                        s.passwd = f[f.len() - 1].to_string();
                        // nginx does not replay AUTH to the backend.
                        s.replay.clear();
                        match authorise(writer, &s, server, peer, Protocol::Smtp).await? {
                            Some(o) => {
                                writer.write_all(b"235 2.0.0 OK\r\n").await?;
                                writer.flush().await?;
                                return proxy(o, reader, writer, &s.replay, server, Protocol::Smtp)
                                    .await;
                            }
                            None => continue,
                        }
                    }
                    "LOGIN" => {
                        let user_b64 = match arg {
                            Some(a) if !a.is_empty() => a,
                            _ => {
                                writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                                writer.flush().await?;
                                read_line(reader).await?
                            }
                        };
                        writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                        writer.flush().await?;
                        let p = read_line(reader).await?;
                        s.method = "login";
                        s.user = String::from_utf8_lossy(
                            &crate::util::base64_decode(&user_b64).unwrap_or_default(),
                        )
                        .to_string();
                        s.passwd = String::from_utf8_lossy(
                            &crate::util::base64_decode(&p).unwrap_or_default(),
                        )
                        .to_string();
                        s.replay.clear();
                        match authorise(writer, &s, server, peer, Protocol::Smtp).await? {
                            Some(o) => {
                                writer.write_all(b"235 2.0.0 OK\r\n").await?;
                                writer.flush().await?;
                                return proxy(o, reader, writer, &s.replay, server, Protocol::Smtp)
                                    .await;
                            }
                            None => continue,
                        }
                    }
                    "CRAM-MD5" => {
                        let challenge = crate::util::base64_encode(b"<1@ngxrs>");
                        writer
                            .write_all(format!("334 {challenge}\r\n").as_bytes())
                            .await?;
                        writer.flush().await?;
                        let r = read_line(reader).await?;
                        let d = String::from_utf8_lossy(
                            &crate::util::base64_decode(&r).unwrap_or_default(),
                        )
                        .to_string();
                        let mut sp = d.splitn(2, ' ');
                        s.user = sp.next().unwrap_or("").to_string();
                        s.passwd = sp.next().unwrap_or("").to_string();
                        s.method = "cram-md5";
                        // The decoded challenge is what auth_http sees as the salt.
                        s.salt = String::from_utf8_lossy(
                            &crate::util::base64_decode(&challenge).unwrap_or_default(),
                        )
                        .to_string();
                        s.replay.clear();
                        match authorise(writer, &s, server, peer, Protocol::Smtp).await? {
                            Some(o) => {
                                writer.write_all(b"235 2.0.0 OK\r\n").await?;
                                writer.flush().await?;
                                return proxy(o, reader, writer, &s.replay, server, Protocol::Smtp)
                                    .await;
                            }
                            None => continue,
                        }
                    }
                    "EXTERNAL" => {
                        // The prompt is the username challenge, base64 "Username:".
                        let user_b64 = match arg {
                            Some(a) if !a.is_empty() => a,
                            _ => {
                                writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                                writer.flush().await?;
                                read_line(reader).await?
                            }
                        };
                        s.method = "external";
                        s.user = String::from_utf8_lossy(
                            &crate::util::base64_decode(&user_b64).unwrap_or_default(),
                        )
                        .to_string();
                        s.replay.clear();
                        match authorise(writer, &s, server, peer, Protocol::Smtp).await? {
                            Some(o) => {
                                writer.write_all(b"235 2.0.0 OK\r\n").await?;
                                writer.flush().await?;
                                return proxy(o, reader, writer, &s.replay, server, Protocol::Smtp)
                                    .await;
                            }
                            None => continue,
                        }
                    }
                    _ => {
                        writer.write_all(b"504 5.5.4 unsupported mechanism\r\n").await?;
                        writer.flush().await?;
                    }
                }
            }
            // With `smtp_auth none` nginx answers `MAIL FROM` optimistically and
            // only then starts proxying; the backend's reply to that one command
            // is swallowed, so the client sees exactly one answer per command.
            // Before a proxy exists `RSET` is answered by nginx itself; once the
            // session is spliced the backend sees it instead (see auth none tests).
            "RSET" if server.auth_none => {
                writer.write_all(b"250 2.0.0 OK\r\n").await?;
                writer.flush().await?;
            }
            "MAIL" | "RCPT" if server.auth_none => {
                let optimistic = cmd == "MAIL";
                if optimistic {
                    writer.write_all(b"250 2.0.0 OK\r\n").await?;
                    writer.flush().await?;
                }
                s.method = "none";
                s.replay.clear();
                s.replay.extend_from_slice(format!("{line}\r\n").as_bytes());
                // The `auth_http` endpoint routes on where the mail is going.
                s.smtp_to = smtp_address(trimmed);
                match authorise(writer, &s, server, peer, Protocol::Smtp).await? {
                    Some(o) => {
                        let discard = usize::from(optimistic);
                        return proxy_n(
                            o,
                            reader,
                            writer,
                            &s.replay,
                            server,
                            Protocol::Smtp,
                            discard,
                        )
                        .await;
                    }
                    None => continue,
                }
            }
            _ => {
                writer.write_all(b"500 5.5.2 unrecognized command\r\n").await?;
                writer.flush().await?;
            }
        }
    }
}

/// Mechanisms advertised in the EHLO reply. LOGIN is always present, matching
/// nginx where only plain/apop/cram-md5/external are configurable.
fn smtp_mechanisms(server: &MailServer) -> Vec<&'static str> {
    let mut out = Vec::new();
    if server.auth_plain {
        out.push("PLAIN");
    }
    out.push("LOGIN");
    if server.auth_cram_md5 {
        out.push("CRAM-MD5");
    }
    if server.auth_external {
        out.push("EXTERNAL");
    }
    out
}

// ---------------------------------------------------------------------------
// authorise + splice
// ---------------------------------------------------------------------------

/// Where to send the client once authenticated.
struct Upstream {
    addr: SocketAddr,
    /// Credentials the authenticator supplied, used when the client only sent a
    /// digest (nginx replaces them before replaying to the backend).
    replay: Vec<u8>,
}

/// Ask `auth_http` and render the outcome to the client.
///
/// `Ok(Some(upstream))` means authentication succeeded; `Ok(None)` means the
/// client has been told and the loop should continue.
async fn authorise<W>(
    writer: &mut BufWriter<W>,
    s: &Session,
    server: &MailServer,
    peer: &SocketAddr,
    protocol: Protocol,
) -> io::Result<Option<Upstream>>
where
    W: AsyncWriteExt + Unpin,
{
    let Some(http) = server.auth_http.as_ref() else {
        let msg = render_error(protocol, &s.tag, "auth service not configured");
        writer.write_all(msg.as_bytes()).await?;
        writer.flush().await?;
        return Ok(None);
    };

    let reply = match auth_request(http, s, server, peer).await {
        Some(r) => r,
        None => {
            let msg = render_error(protocol, &s.tag, "authorization service unavailable");
            writer.write_all(msg.as_bytes()).await?;
            writer.flush().await?;
            return Ok(None);
        }
    };

    if reply.ok {
        let (Some(host), Some(port)) = (reply.server.as_deref(), reply.port) else {
            let msg = render_error(protocol, &s.tag, "no backend configured");
            writer.write_all(msg.as_bytes()).await?;
            writer.flush().await?;
            return Ok(None);
        };
        let Some(addr) = resolve(host, port).await else {
            let msg = render_error(protocol, &s.tag, "cannot resolve backend");
            writer.write_all(msg.as_bytes()).await?;
            writer.flush().await?;
            return Ok(None);
        };
        return Ok(Some(Upstream {
            addr,
            replay: s.replay.clone(),
        }));
    }

    if reply.wait {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // nginx only shows the authenticator's text when `proxy_pass_error_message`
    // is on; otherwise the protocol's generic failure is used.
    let shown = if server.pass_error_message && !reply.error.is_empty() {
        reply.error.as_str()
    } else {
        ""
    };
    let _ = reply.error_code;
    let msg = if shown.is_empty() {
        render_failure(protocol, &s.tag)
    } else {
        render_error(protocol, &s.tag, shown)
    };
    writer.write_all(msg.as_bytes()).await?;
    writer.flush().await?;
    Ok(None)
}

fn render_error(protocol: Protocol, tag: &str, text: &str) -> String {
    match protocol {
        Protocol::Pop3 => format!("-ERR {text}\r\n"),
        Protocol::Imap => format!("{tag} NO {text}\r\n"),
        Protocol::Smtp => format!("535 5.7.8 {text}\r\n"),
    }
}

fn render_failure(protocol: Protocol, tag: &str) -> String {
    match protocol {
        Protocol::Pop3 => "-ERR authorization failed\r\n".to_string(),
        Protocol::Imap => format!("{tag} NO authorization failed\r\n"),
        Protocol::Smtp => "535 5.7.8 authorization failed\r\n".to_string(),
    }
}

/// Splice the client onto its backend and relay until either side closes.
///
/// nginx consumes the client's credentials during the auth phase, so they are
/// replayed to the backend first — the mailbox server re-authenticates the same
/// session against its own user database.
#[allow(clippy::too_many_arguments)]
async fn proxy<R, W>(
    up: Upstream,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    replay: &[u8],
    server: &MailServer,
    protocol: Protocol,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    proxy_n(up, reader, writer, replay, server, protocol, 0).await
}

/// Same, but swallow `discard` replies the client has already been given.
#[allow(clippy::too_many_arguments)]
async fn proxy_n<R, W>(
    up: Upstream,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    _replay: &[u8],
    server: &MailServer,
    protocol: Protocol,
    discard: usize,
) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let backend = match TcpStream::connect(up.addr).await {
        Ok(b) => b,
        Err(e) => {
            writer
                .write_all(format!("-ERR backend unavailable: {e}\r\n").as_bytes())
                .await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    let _ = backend.set_nodelay(true);
    let (mut brd, mut bwr) = backend.into_split();

    // nginx re-runs the SMTP dialogue with the backend: the client already got
    // its greeting from us, so the upstream one is dropped along with the reply
    // to our own HELO. Forwarding either would put a `220`/`250` in front of
    // the `235` the client is waiting for.
    if protocol == Protocol::Smtp {
        let _greeting = read_line_plain(&mut brd).await.unwrap_or_default();
        bwr.write_all(format!("EHLO {}\r\n", server.name).as_bytes()).await?;
        bwr.flush().await?;
        let _helo = read_line_plain(&mut brd).await.unwrap_or_default();
    }

    if !up.replay.is_empty() {
        bwr.write_all(&up.replay).await?;
        bwr.flush().await?;
        // Replies the client has already been given must not be repeated.
        for _ in 0..discard {
            let _ = read_line_plain(&mut brd).await;
        }
    }

    // Relay by hand rather than with `copy`: the client side is a `BufWriter`,
    // so every write must be flushed or the client sees nothing until the
    // buffer fills (which never happens for a one-line greeting).
    let timeout = server.proxy_timeout;
    let mut cbuf = vec![0u8; 8192];
    let mut bbuf = vec![0u8; 8192];
    loop {
        tokio::select! {
            r = tokio::time::timeout(timeout, reader.read(&mut cbuf)) => {
                match r {
                    Err(_) => break,
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        bwr.write_all(&cbuf[..n]).await?;
                        bwr.flush().await?;
                    }
                    Ok(Err(_)) => break,
                }
            }
            r = tokio::time::timeout(timeout, brd.read(&mut bbuf)) => {
                match r {
                    Err(_) => break,
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        writer.write_all(&bbuf[..n]).await?;
                        writer.flush().await?;
                    }
                    Ok(Err(_)) => break,
                }
            }
        }
    }
    Ok(())
}

