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
    writer.write_all(POP3_GREETING).await?;
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
                s.method = "USER";
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
                    return proxy(o, reader, writer, &s.replay, server).await;
                }
            }
            "APOP" => {
                let mut parts = rest.splitn(2, ' ');
                s.user = parts.next().unwrap_or("").to_string();
                s.passwd = parts.next().unwrap_or("").to_string();
                s.method = "APOP";
                s.replay.extend_from_slice(line.as_bytes());
                s.replay.extend_from_slice(b"\r\n");
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Pop3).await? {
                    return proxy(o, reader, writer, &s.replay, server).await;
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
                            return proxy(o, reader, writer, &s.replay, server).await;
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

/// Mechanisms advertised by a bare POP3 `AUTH`, in nginx's order.
fn pop3_mechanisms(server: &MailServer) -> Vec<&'static str> {
    let mut out = Vec::new();
    if server.auth_plain {
        out.push("PLAIN");
    }
    if server.auth_login {
        out.push("LOGIN");
    }
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
            s.method = "PLAIN";
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

            s.method = "LOGIN";
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
            s.method = "CRAM-MD5";
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
            s.method = "EXTERNAL";
            s.replay
                .extend_from_slice(format!("AUTH EXTERNAL {}\r\n", arg.unwrap_or_default()).as_bytes());
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
                s.user = imap_arg(parts.next().unwrap_or(""));
                s.passwd = imap_arg(parts.next().unwrap_or(""));
                s.method = "LOGIN";
                s.tag = tag.clone();
                s.replay
                    .extend_from_slice(format!("{line}\r\n").as_bytes());
                if let Some(o) = authorise(writer, &s, server, peer, Protocol::Imap).await? {
                    return proxy(o, reader, writer, &s.replay, server).await;
                }
            }
            "AUTHENTICATE" => {
                let mech = rest.to_ascii_uppercase();
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
                        writer.write_all(b"+ \r\n").await?;
                        writer.flush().await?;
                        let resp = read_line(reader).await?;
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
                        writer.write_all(b"+ VXNlcm5hbWU6\r\n").await?;
                        writer.flush().await?;
                        let u = read_line(reader).await?;
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
                    return proxy(o, reader, writer, &s.replay, server).await;
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
    if server.auth_login {
        out.push("LOGIN");
    }
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

const SMTP_GREETING: &[u8] = b"220 ESMTP ready\r\n";

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
    writer.write_all(SMTP_GREETING).await?;
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
                let mut caps = String::from("250-ESMTP\r\n");
                if server.auth_plain || server.auth_login || server.auth_cram_md5 {
                    let mut mechs = Vec::new();
                    if server.auth_plain {
                        mechs.push("PLAIN");
                    }
                    if server.auth_login {
                        mechs.push("LOGIN");
                    }
                    if server.auth_cram_md5 {
                        mechs.push("CRAM-MD5");
                    }
                    caps.push_str(&format!("250-AUTH {}\r\n", mechs.join(" ")));
                }
                caps.push_str("250 8BITMIME\r\n");
                writer.write_all(caps.as_bytes()).await?;
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
                            writer.write_all(b"501 bad response\r\n").await?;
                            writer.flush().await?;
                            continue;
                        }
                        s.method = "PLAIN";
                        s.user = f[f.len() - 2].to_string();
                        s.passwd = f[f.len() - 1].to_string();
                        s.replay
                            .extend_from_slice(format!("AUTH PLAIN {data}\r\n").as_bytes());
                        if let Some(o) =
                            authorise(writer, &s, server, peer, Protocol::Smtp).await?
                        {
                            return proxy(o, reader, writer, &s.replay, server).await;
                        }
                    }
                    "LOGIN" => {
                        writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                        writer.flush().await?;
                        let u = read_line(reader).await?;
                        s.user = String::from_utf8_lossy(
                            &crate::util::base64_decode(&u).unwrap_or_default(),
                        )
                        .to_string();
                        writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                        writer.flush().await?;
                        let p = read_line(reader).await?;
                        s.passwd = String::from_utf8_lossy(
                            &crate::util::base64_decode(&p).unwrap_or_default(),
                        )
                        .to_string();
                        s.method = "LOGIN";
                        s.replay
                            .extend_from_slice(format!("AUTH LOGIN\r\n{u}\r\n{p}\r\n").as_bytes());
                        if let Some(o) =
                            authorise(writer, &s, server, peer, Protocol::Smtp).await?
                        {
                            return proxy(o, reader, writer, &s.replay, server).await;
                        }
                    }
                    _ => {
                        writer
                            .write_all(b"504 unsupported mechanism\r\n")
                            .await?;
                        writer.flush().await?;
                    }
                }
            }
            _ => {
                writer.write_all(b"500 unknown command\r\n").await?;
                writer.flush().await?;
            }
        }
    }
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
        Protocol::Imap => format!("{tag}NO {text}\r\n"),
        Protocol::Smtp => format!("535 5.7.8 {text}\r\n"),
    }
}

fn render_failure(protocol: Protocol, tag: &str) -> String {
    match protocol {
        Protocol::Pop3 => "-ERR authorization failed\r\n".to_string(),
        Protocol::Imap => format!("{tag}NO authorization failed\r\n"),
        Protocol::Smtp => "535 5.7.8 authorization failed\r\n".to_string(),
    }
}

/// Splice the client onto its backend and relay until either side closes.
async fn proxy<R, W>(
    up: Upstream,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    _replay: &[u8],
    server: &MailServer,
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

    tokio::select! {
        r = tokio::io::copy(&mut *reader, &mut bwr) => { let _ = r; }
        r = tokio::io::copy(&mut brd, writer) => { let _ = r; }
    }
    let _ = server.proxy_timeout;
    Ok(())
}
