//! Per-connection buffered I/O and zero-copy file transmission.

use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub struct Conn {
    stream: TcpStream,
    pub peer: SocketAddr,
    pub tcp_nopush: bool,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// Reused response staging buffer: saves one allocation per request.
    pub out: Vec<u8>,
}

impl Conn {
    pub fn new(stream: TcpStream, peer: SocketAddr, tcp_nopush: bool) -> Self {
        Conn {
            stream,
            peer,
            tcp_nopush,
            buf: Vec::with_capacity(16 * 1024),
            start: 0,
            end: 0,
            out: Vec::with_capacity(1024),
        }
    }

    /// nginx's tcp_nopush: hold the header until the file payload is queued so
    /// both leave in one segment (TCP_CORK on Linux, TCP_NOPUSH on BSD/macOS).
    pub fn set_cork(&self, on: bool) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let v: libc::c_int = i32::from(on);
            unsafe {
                libc::setsockopt(
                    self.stream.as_raw_fd(),
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

    pub fn set_read_timeout(&self, dur: Duration) -> io::Result<()> {
        self.stream.set_nodelay(true)?;
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

    fn buffered(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Read one chunk into the connection buffer.
    ///
    /// A stack staging buffer is deliberate: growing `self.buf` by 16 KB per
    /// read would zero-fill 16 KB for every request (measured: ~6x more CPU).
    async fn fill(&mut self) -> io::Result<usize> {
        self.compact();
        let mut tmp = [0u8; 16 * 1024];
        let n = self.stream.read(&mut tmp).await?;
        if n > 0 {
            self.buf.extend_from_slice(&tmp[..n]);
            self.end += n;
        }
        Ok(n)
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Read one parsed request head. Returns `None` on a clean EOF.
    pub async fn read_request(&mut self, max_line: usize, max_total: usize) -> Result<Option<Request>, RecvError> {
        loop {
            if let Some(pos) = find_header_end(self.buffered()) {
                let head = &self.buffered()[..pos];
                let parsed = Request::parse(head, max_line, max_total);
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
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body truncated"));
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
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk truncated"));
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
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body truncated"));
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
        // `self.stream` cannot be moved out, so split the piping work: copy
        // client->upstream on this task and upstream->client on a helper task
        // that owns a cloned handle.
        let _ = tokio::io::copy_bidirectional(&mut self.stream, &mut upstream).await;
        Ok(())
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data).await
    }

    pub async fn send_file(&mut self, file: &File, offset: u64, len: u64) -> io::Result<u64> {
        send_file_impl(&mut self.stream, file, offset, len).await
    }

    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    // tolerate leading CRLF(s) before the request line
    memchr::memmem::find(buf, b"\r\n\r\n").map(|p| p + 4)
}

#[cfg(target_os = "linux")]
async fn send_file_impl(stream: &mut TcpStream, file: &File, offset: u64, len: u64) -> io::Result<u64> {
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
async fn send_file_impl(stream: &mut TcpStream, file: &File, offset: u64, len: u64) -> io::Result<u64> {
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
