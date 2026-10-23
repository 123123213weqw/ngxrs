//! Per-connection buffered I/O and zero-copy file transmission.

use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::http::request::{HttpError, Request};

pub const MAX_REQUEST_LINE: usize = 8 * 1024;
pub const MAX_HEADER_BYTES: usize = 32 * 1024;

pub enum RecvError {
    Io(io::Error),
    Bad(HttpError),
}

impl From<io::Error> for RecvError {
    fn from(e: io::Error) -> Self {
        RecvError::Io(e)
    }
}

/// Plain TCP or a TLS session over TCP. `sendfile(2)` only applies to the
/// former, so TLS falls back to a buffered copy.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    /// `listen unix:/path`. nginx forbids `ssl` on a unix socket, so there is
    /// no TLS variant of this.
    Unix(tokio::net::UnixStream),
}

impl Stream {
    fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Stream::Plain(s) => Some(s),
            Stream::Tls(s) => Some(s.get_ref().0),
            Stream::Unix(_) => None,
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }

    pub fn is_unix(&self) -> bool {
        matches!(self, Stream::Unix(_))
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Per-connection TLS facts nginx exposes as `$ssl_*` variables.
#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    /// `TLSv1.2` / `TLSv1.3`, as `$ssl_protocol` spells it.
    pub version: String,
    /// IANA suite name, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher: String,
    /// SNI name the client sent, if any.
    pub server_name: Option<String>,
    /// `SUCCESS`, `NONE` or `FAILED:<reason>` — `$ssl_client_verify`.
    pub client_verify: String,
    /// PEM of the presented client certificate.
    pub client_cert: String,
    /// True when the session was resumed — `$ssl_session_reused` reports `r`
    /// then and `.` otherwise, for both TLS 1.2 and 1.3 (rustls reports a
    /// resumed handshake for either).
    pub session_reused: bool,
    /// `/CN=...` subject and issuer of the client certificate.
    pub client_s_dn: String,
    pub client_i_dn: String,
    pub client_serial: String,
    pub client_fingerprint: String,
    pub client_v_start: String,
    pub client_v_end: String,
}

impl Conn {
    /// Raw descriptor of the underlying socket, for `limit_conn` slot
    /// reclaim: nginx notices a client close through epoll, and this is how we
    /// ask the same question from another request's thread.
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        match &self.stream {
            Stream::Plain(s) => Some(s.as_raw_fd()),
            Stream::Unix(s) => Some(s.as_raw_fd()),
            Stream::Tls(s) => Some(s.get_ref().0.as_raw_fd()),
        }
    }

    /// The client certificate chain as presented in the handshake, if any.
    pub fn peer_chain(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        let Stream::Tls(tls) = &self.stream else {
            return None;
        };
        tls.get_ref()
            .1
            .peer_certificates()
            .filter(|c| !c.is_empty())
            .map(|c| c.iter().cloned().collect())
    }
}

pub struct Conn {
    stream: Stream,
    /// Synthesisable for a unix socket, where there is no peer address. Check
    /// `peer_unix` before reporting it: nginx prints `unix:` as `$remote_addr`.
    pub peer: SocketAddr,
    /// Connected over `listen unix:`. `allow unix:` and `$remote_addr` depend
    /// on this, not on `peer`.
    pub peer_unix: bool,
    pub tcp_nopush: bool,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// Staging buffer for `read`, allocated once per connection.
    ///
    /// `fill` used to declare `let mut tmp = [0u8; 16 * 1024]` on the stack,
    /// which zero-fills 16 KB and dirties 256 cache lines for *every* read --
    /// on a keepalive connection, that is once per request. Reading through a
    /// per-connection buffer turns that into no initialisation at all plus one
    /// copy of the bytes actually received.
    staging: Vec<u8>,
    /// Reused response staging buffer: saves one allocation per request.
    pub out: Vec<u8>,
    /// `stub_status` state for this connection: whether it is currently
    /// counted as reading / writing.
    reading: bool,
    writing: bool,
    /// `limit_rate` for the response in flight, in bytes per second (0 = off),
    /// and how many leading bytes escape throttling (`limit_rate_after`).
    pub limit_rate: u64,
    pub limit_rate_after: u64,
    rate_bytes: u64,
    rate_start: Option<std::time::Instant>,
}

impl Conn {
    /// TLS facts for this connection, or `None` for plaintext.
    pub fn tls_info(&self) -> Option<TlsInfo> {
        let Stream::Tls(tls) = &self.stream else {
            return None;
        };
        let (_, conn) = tls.get_ref();
        let version = match conn.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
            Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
            Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1",
            Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0",
            _ => "",
        };
        let cipher = conn
            .negotiated_cipher_suite()
            .and_then(|c| c.suite().as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        // A presented client certificate: recorded here, judged per virtual
        // host later (the CA bundle lives in that server's config).
        let mut info = TlsInfo {
            version: version.to_string(),
            cipher,
            server_name: conn.server_name().map(|s| s.to_string()),
            session_reused: conn
                .handshake_kind()
                .map(|k| k == rustls::HandshakeKind::Resumed)
                .unwrap_or(false),
            ..TlsInfo::default()
        };
        match conn.peer_certificates() {
            Some(chain) if !chain.is_empty() => {
                info.client_verify = "NONE".to_string();
                info.client_cert = crate::tls::der_to_pem(chain[0].as_ref());
            }
            _ => info.client_verify = "NONE".to_string(),
        }
        Some(info)
    }

    /// `$remote_addr`. nginx reports the literal `unix:` for a unix socket,
    /// where there is no address at all.
    pub fn peer_ip_str(&self) -> String {
        if self.peer_unix {
            "unix:".to_string()
        } else {
            self.peer.ip().to_string()
        }
    }

    pub fn new(stream: Stream, peer: SocketAddr, tcp_nopush: bool) -> Self {
        Conn {
            stream,
            peer,
            peer_unix: false,
            tcp_nopush,
            // Grown on demand: a request head is a few hundred bytes, and a
            // 16 KB reservation per connection costs more in cache misses than
            // it saves in reallocations (nginx's header buffer is 1 KB).
            buf: Vec::with_capacity(512),
            staging: Vec::new(),
            start: 0,
            end: 0,
            out: Vec::with_capacity(512),
            reading: false,
            writing: false,
            limit_rate: 0,
            limit_rate_after: 0,
            rate_bytes: 0,
            rate_start: None,
        }
    }

    /// nginx's tcp_nopush: hold the header until the file payload is queued so
    /// both leave in one segment (TCP_CORK on Linux, TCP_NOPUSH on BSD/macOS).
    pub fn set_cork(&self, on: bool) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let Some(tcp) = self.stream.tcp() else { return };
            let v: libc::c_int = i32::from(on);
            unsafe {
                libc::setsockopt(
                    tcp.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_CORK,
                    &v as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = on;
        }
    }

    /// Local address of the underlying socket (works for TLS too).
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.tcp().and_then(|t| t.local_addr().ok())
    }

    pub fn set_read_timeout(&self, dur: Duration) -> io::Result<()> {
        if let Some(tcp) = self.stream.tcp() {
            tcp.set_nodelay(true)?;
        }
        // tokio has no per-socket read timeout; the handler wraps reads in
        // tokio::time::timeout, so this is deliberately a no-op placeholder.
        let _ = dur;
        Ok(())
    }

    fn compact(&mut self) {
        if self.start > 0 {
            if self.end > self.start {
                self.buf.copy_within(self.start..self.end, 0);
            }
            self.end -= self.start;
            self.start = 0;
            self.buf.truncate(self.end);
        }
    }

    /// Resolves when the peer has closed its side, without consuming data.
    ///
    /// nginx watches the client for a readable event while it waits on an
    /// upstream, so a request whose client has gone away is finalized at once
    /// (this is what releases a `limit_conn` slot). Only plain sockets are
    /// watched: a TLS stream cannot be probed without consuming records, and
    /// "not closed" is the safe answer there.
    ///
    /// Callers only await this where the answer changes behaviour (a
    /// `limit_conn` slot is held), because probing costs a 2 ms timer per
    /// iteration for as long as the upstream takes.
    pub async fn peer_closed(&self) {
        // `recv(MSG_PEEK)` reports end-of-stream without consuming anything and
        // behaves the same on Linux and macOS (POLLRDHUP is Linux-only).
        let probe = |fd: std::os::unix::io::RawFd| -> bool {
            let mut b = [0u8; 1];
            let n = unsafe {
                libc::recv(
                    fd,
                    b.as_mut_ptr() as *mut libc::c_void,
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            n == 0
                || (n < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock)
        };
        use std::os::unix::io::AsRawFd;
        let fd = match &self.stream {
            Stream::Plain(s) => s.as_raw_fd(),
            Stream::Unix(s) => s.as_raw_fd(),
            Stream::Tls(_) => {
                std::future::pending::<()>().await;
                return;
            }
        };
        // 1 ms for the first 200 ms (the window a following request can
        // observe), then back off so a very slow upstream does not spin.
        let started = std::time::Instant::now();
        loop {
            if probe(fd) {
                return;
            }
            let waited = started.elapsed();
            let step = if waited < Duration::from_millis(200) {
                Duration::from_millis(1)
            } else {
                Duration::from_millis(10)
            };
            tokio::time::sleep(step).await;
        }
    }

    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Read one chunk into the connection buffer.
    ///
    /// A stack staging buffer is deliberate: growing `self.buf` by 16 KB per
    /// read would zero-fill 16 KB for every request (measured: ~6x more CPU).
    async fn fill(&mut self) -> io::Result<usize> {
        self.compact();
        // Staging buffer for `read`, allocated once per connection rather than
        // zero-filled per call (see the field comment).
        const CHUNK: usize = 16 * 1024;
        if self.staging.len() < CHUNK {
            self.staging.resize(CHUNK, 0);
        }
        // Disjoint field borrows: `stream` and `staging` are separate fields.
        let n = self.stream.read(&mut self.staging[..]).await?;
        if n > 0 {
            self.buf.extend_from_slice(&self.staging[..n]);
            self.end += n;
        }
        Ok(n)
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start >= self.end {
            // The buffer must be *emptied*, not merely marked empty: `fill`
            // appends at buf.len(), so a stale tail would be re-parsed as the
            // next request on a keepalive connection.
            self.start = 0;
            self.end = 0;
            self.buf.clear();
        }
    }

    /// Read one parsed request head. Returns `None` on a clean EOF.
    /// Update the `reading` counter for this connection only.
    fn set_reading(&mut self, on: bool) {
        if self.reading != on {
            self.reading = on;
            crate::stats::reading_delta(on);
        }
    }

    /// Update the `writing` counter for this connection only.
    pub fn set_writing(&mut self, on: bool) {
        if self.writing != on {
            self.writing = on;
            crate::stats::writing_delta(on);
        }
    }

    /// Clear both counters, for use on the way out of a connection.
    pub fn clear_stats(&mut self) {
        self.set_reading(false);
        self.set_writing(false);
    }

    pub async fn read_request(
        &mut self,
        max_line: usize,
        max_total: usize,
    ) -> Result<Option<Request>, RecvError> {
        loop {
            if let Some(pos) = find_header_end(self.buffered()) {
                let head = &self.buffered()[..pos];
                let parsed = Request::parse(head, max_line, max_total);
                self.set_reading(false);
                crate::stats::request_started();
                match parsed {
                    Ok(req) => {
                        self.consume(pos);
                        return Ok(Some(req));
                    }
                    Err(e) => {
                        self.consume(pos);
                        return Err(RecvError::Bad(e));
                    }
                }
            }
            if self.buffered().len() > max_total {
                return Err(RecvError::Bad(HttpError::new(400, true)));
            }
            // Data is pending: nginx counts the connection as reading from the
            // moment `recv` returns bytes until the header is complete. With
            // nothing buffered it is idle, i.e. "waiting".
            self.set_reading(!self.buffered().is_empty());
            let n = self.fill().await?;
            if n == 0 {
                if self.buffered().is_empty() {
                    return Ok(None);
                }
                return Err(RecvError::Bad(HttpError::new(400, true)));
            }
        }
    }

    /// Discard a declared request body.
    pub async fn drain_body(&mut self, len: u64) -> io::Result<()> {
        let avail = self.buffered().len() as u64;
        if avail >= len {
            self.consume(len as usize);
            return Ok(());
        }
        self.consume(avail as usize);
        let mut remaining = len - avail;
        let mut tmp = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(tmp.len() as u64) as usize;
            let n = self.stream.read(&mut tmp[..want]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "body truncated",
                ));
            }
            remaining -= n as u64;
        }
        Ok(())
    }

    /// Discard a chunked request body (trailers included).
    pub async fn drain_chunked(&mut self) -> io::Result<()> {
        loop {
            let line = self.read_line().await?;
            let size_str = std::str::from_utf8(&line)
                .ok()
                .map(|s| s.split(';').next().unwrap_or("").trim().to_string())
                .unwrap_or_default();
            let size = u64::from_str_radix(&size_str, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // trailers
                loop {
                    let l = self.read_line().await?;
                    if l.is_empty() {
                        return Ok(());
                    }
                }
            }
            // chunk data + CRLF
            let need = size + 2;
            while (self.buffered().len() as u64) < need {
                if self.fill().await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "chunk truncated",
                    ));
                }
            }
            self.consume(need as usize);
        }
    }

    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(idx) = memchr::memchr(b'\n', self.buffered()) {
                let mut line = self.buffered()[..idx].to_vec();
                if line.ends_with(b"\r") {
                    line.pop();
                }
                self.consume(idx + 1);
                return Ok(line);
            }
            if self.buffered().len() > 8 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in line"));
            }
        }
    }

    /// Move exactly `len` bytes of body into `out`, using buffered bytes first.
    pub async fn take_into(&mut self, out: &mut Vec<u8>, len: usize) -> io::Result<()> {
        let mut remaining = len;
        while remaining > 0 {
            let avail = self.end - self.start;
            if avail > 0 {
                let take = avail.min(remaining);
                out.extend_from_slice(&self.buf[self.start..self.start + take]);
                self.consume(take);
                remaining -= take;
                continue;
            }
            let before = out.len();
            out.resize(before + 64 * 1024, 0);
            let n = match self.stream.read(&mut out[before..]).await {
                Ok(n) => n,
                Err(e) => {
                    out.truncate(before);
                    return Err(e);
                }
            };
            out.truncate(before + n);
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "body truncated",
                ));
            }
            if n > remaining {
                // over-read: keep the surplus for the next request
                let extra = &out[before + remaining..];
                self.buf.extend_from_slice(extra);
                self.end += extra.len();
                out.truncate(before + remaining);
                remaining = 0;
            } else {
                remaining -= n;
            }
        }
        Ok(())
    }

    pub async fn read_line_pub(&mut self) -> io::Result<Vec<u8>> {
        self.read_line().await
    }

    /// Hand this connection's socket to a bidirectional pipe (WebSocket).
    pub async fn pipe_with(&mut self, mut upstream: TcpStream) -> io::Result<()> {
        let _ = tokio::io::copy_bidirectional(&mut self.stream, &mut upstream).await;
        Ok(())
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        // `limit_rate` throttles the whole response, headers included — nginx's
        // write filter applies the limit to whatever the chain produced, so a
        // 155-byte header with an empty body still takes 155/rate seconds
        // (measured: 20 s at `limit_rate 15`). The fast path must stay free, so
        // the check is a single field comparison.
        if self.limit_rate == 0 {
            self.rate_bytes += data.len() as u64;
            return self.stream.write_all(data).await;
        }
        let rate = self.limit_rate;
        let mut sent = 0usize;
        while sent < data.len() {
            // Anything below `limit_rate_after` is not throttled.
            let head_free = self.rate_bytes < self.limit_rate_after;
            let chunk = if head_free {
                (self.limit_rate_after - self.rate_bytes).max(1) as usize
            } else {
                // Aim for ~10 writes per second at the configured rate, but keep
                // chunks small enough that a large body does not stall the loop.
                (rate / 10).clamp(1, 16 * 1024) as usize
            };
            let end = (sent + chunk).min(data.len());
            // Pace against the schedule: sleep only if we are ahead of it.
            if !head_free {
                let target =
                    std::time::Duration::from_secs_f64(self.rate_bytes as f64 / rate as f64);
                if let Some(elapsed) = self.rate_start.map(|t| t.elapsed()) {
                    if elapsed < target {
                        // A throttled response can sit here for seconds. nginx
                        // keeps the read event armed, so a client disconnect
                        // finalises the request immediately rather than after
                        // the body has been paced out; watch for readability
                        // during the wait to get the same behaviour.
                        let wait = tokio::time::sleep(target - elapsed);
                        tokio::pin!(wait);
                        tokio::select! {
                            _ = &mut wait => {}
                            _ = async {
                                match &self.stream {
                                    Stream::Plain(t) => { let _ = t.readable().await; }
                                    Stream::Unix(t) => { let _ = t.readable().await; }
                                    Stream::Tls(_) => std::future::pending::<()>().await,
                                }
                            } => {
                                if self.peer_gone() {
                                    return Err(io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "peer closed",
                                    ));
                                }
                            }
                        }
                    }
                }
                if self.peer_gone() {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"));
                }
            }
            self.stream.write_all(&data[sent..end]).await?;
            self.rate_bytes += (end - sent) as u64;
            sent = end;
            // A partial write means the client is keeping up (or the buffer
            // drained); the wait above paces the rest.
            if self.rate_start.is_none() {
                self.rate_start = Some(std::time::Instant::now());
            }
        }
        Ok(())
    }

    /// One-shot "has the peer gone?" probe.
    ///
    /// `recv(MSG_PEEK | MSG_DONTWAIT)` returning 0 is an orderly shutdown;
    /// `EAGAIN` means the connection is still open.
    fn peer_gone(&self) -> bool {
        use std::os::unix::io::AsRawFd;
        let fd = match &self.stream {
            Stream::Plain(s) => s.as_raw_fd(),
            Stream::Unix(s) => s.as_raw_fd(),
            // TLS keeps its own framing state; fall back to write errors.
            Stream::Tls(_) => return false,
        };
        let mut b = [0u8; 1];
        let n = unsafe {
            libc::recv(
                fd,
                b.as_mut_ptr() as *mut libc::c_void,
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        // 0 is an orderly shutdown; any error other than "would block" is a
        // reset (a close with unread data yields ECONNRESET), which also means
        // the peer is gone.
        n == 0
            || (n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock)
    }

    /// Start a new response: reset the `limit_rate` accounting.
    pub fn begin_response(&mut self, rate: u64, after: u64) {
        self.limit_rate = rate;
        self.limit_rate_after = after;
        self.rate_bytes = 0;
        self.rate_start = None;
    }

    pub async fn send_file(&mut self, file: &File, offset: u64, len: u64) -> io::Result<u64> {
        // A rate-limited response cannot use sendfile: the bytes have to pass
        // through the throttling writer.
        if self.limit_rate != 0 && self.rate_bytes >= self.limit_rate_after {
            use std::os::unix::fs::FileExt;
            let mut buf = vec![0u8; 16 * 1024];
            let mut done = 0u64;
            while done < len {
                let want = ((len - done) as usize).min(buf.len());
                let n = file.read_at(&mut buf[..want], offset + done)?;
                if n == 0 {
                    break;
                }
                self.write_all(&buf[..n]).await?;
                done += n as u64;
            }
            return Ok(done);
        }
        match &mut self.stream {
            Stream::Plain(tcp) => send_file_impl(tcp, file, offset, len).await,
            // TLS cannot use sendfile, and neither can a unix socket (which
            // nginx also serves through a buffered copy): fall through to the
            // bounded-buffer path.
            stream => {
                use std::os::unix::fs::FileExt;
                let mut remaining = len;
                let mut pos = offset;
                let mut buf = vec![0u8; 64 * 1024];
                let mut sent = 0u64;
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    let n = match file.read_at(&mut buf[..want], pos) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    stream.write_all(&buf[..n]).await?;
                    pos += n as u64;
                    remaining -= n as u64;
                    sent += n as u64;
                }
                Ok(sent)
            }
        }
    }

    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

/// Locate the end of the request head.
///
/// Accepts CRLF and bare-LF line endings (nginx accepts both). Leading empty
/// lines are tolerated, as nginx does.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut line_start = 0usize;
    while i < buf.len() {
        if buf[i] != b'\n' {
            i += 1;
            continue;
        }
        let mut line_end = i;
        if line_end > line_start && buf[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        let empty = line_end == line_start;
        i += 1;
        if empty {
            // An empty line before the request line is permitted; the head
            // ends at the first empty line that follows it.
            if line_start > 0 {
                return Some(i);
            }
        }
        line_start = i;
    }
    None
}

#[cfg(target_os = "linux")]
async fn send_file_impl(
    stream: &mut TcpStream,
    file: &File,
    offset: u64,
    len: u64,
) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let sock = stream.as_raw_fd();
    let fd = file.as_raw_fd();
    let mut off: libc::off_t = offset as libc::off_t;
    let mut remaining = len;
    let mut sent_total = 0u64;

    while remaining > 0 {
        let chunk = remaining.min(1 << 30) as usize;
        let n = unsafe { libc::sendfile(sock, fd, &mut off, chunk) };
        if n > 0 {
            remaining -= n as u64;
            sent_total += n as u64;
            continue;
        }
        if n == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {
                stream.writable().await?;
                match stream.try_io(tokio::io::Interest::WRITABLE, || {
                    let n = unsafe { libc::sendfile(sock, fd, &mut off, chunk) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(0) => break,
                    Ok(n) => {
                        remaining -= n as u64;
                        sent_total += n as u64;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(err),
        }
    }
    Ok(sent_total)
}

#[cfg(not(target_os = "linux"))]
async fn send_file_impl(
    stream: &mut TcpStream,
    file: &File,
    offset: u64,
    len: u64,
) -> io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    let mut remaining = len;
    let mut buf = vec![0u8; 128 * 1024];
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n]).await?;
        remaining -= n as u64;
        total += n as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::find_header_end;

    fn end(buf: &[u8]) -> Option<usize> {
        find_header_end(buf)
    }

    #[test]
    fn crlf_head() {
        assert_eq!(end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY"), Some(27));
    }

    #[test]
    fn lf_head() {
        let buf = b"GET / HTTP/1.1\nHost: a\n\nBODY";
        assert_eq!(end(buf), Some(24));
    }

    #[test]
    fn incomplete_head() {
        assert_eq!(end(b"GET / HTTP/1.1\r\nHost: a\r\n"), None);
    }

    #[test]
    fn leading_crlf_is_skipped() {
        let buf = b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(end(buf), Some(buf.len()));
    }
}
