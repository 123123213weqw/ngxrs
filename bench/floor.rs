//! Calibration: the cheapest possible tokio HTTP/1.1 server.
//!
//! Purpose: measure the framework floor. If a server that does nothing but
//! `read` a request head and `write` a canned response already costs about as
//! much CPU per request as ngxrs, then ngxrs's 1.14-1.32x against nginx is the
//! cost of building on tokio, not a defect in the request path. If this floor
//! is much cheaper than ngxrs, the difference is our own code.
//!
//! Deliberately naive-but-fair: same tokio runtime shape (one current-thread
//! runtime per worker, SO_REUSEPORT), same response bytes (240-byte header
//! block + 1024-byte body), one read per request, keepalive, no allocation-free
//! tricks beyond a reusable buffer.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn response(body_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(240 + body_len);
    v.extend_from_slice(
        b"HTTP/1.1 200 OK\r\n\
          Server: nginx/1.28.0\r\n\
          Date: Mon, 19 Oct 2026 03:57:24 GMT\r\n\
          Content-Type: text/plain\r\n\
          Content-Length: 1024\r\n\
          Last-Modified: Sat, 17 Oct 2026 16:37:58 GMT\r\n\
          ETag: \"6ad3a466-400\"\r\n\
          Accept-Ranges: bytes\r\n\
          Connection: keep-alive\r\n\r\n",
    );
    v.resize(v.len() + body_len, b'x');
    v
}

async fn serve(mut sock: TcpStream, resp: &[u8]) -> io::Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        // Read until the end of the request head. One recv in the common case.
        let mut filled = 0usize;
        loop {
            if memchr(b'\n', &buf[..filled]).is_some()
                && buf[..filled].windows(4).any(|w| w == b"\r\n\r\n")
            {
                break;
            }
            let n = sock.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Ok(());
            }
            filled += n;
        }
        sock.write_all(resp).await?;
    }
}

fn worker(addr: SocketAddr, body_len: usize) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let resp = std::sync::Arc::new(response(body_len));
    rt.block_on(async move {
        let listener = {
            use socket2::{Domain, Protocol, Socket, Type};
            let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            s.set_reuse_address(true)?;
            s.set_reuse_port(true)?;
            s.set_nonblocking(true)?;
            s.bind(&addr.into())?;
            s.listen(1024)?;
            TcpListener::from_std(s.into())?
        };
        // Concurrency model must match ngxrs (one task per connection, one
        // current-thread runtime per worker) or the comparison measures
        // serialisation rather than framework cost.
        loop {
            let (sock, _) = listener.accept().await?;
            let resp = resp.clone();
            tokio::spawn(async move {
                let _ = serve(sock, &resp).await;
            });
        }
    })
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().unwrap_or_else(|| "18900".into()).parse().unwrap();
    let workers: usize = args.next().unwrap_or_else(|| "1".into()).parse().unwrap();
    let body_len: usize = args.next().unwrap_or_else(|| "1024".into()).parse().unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut kids = Vec::new();
    for _ in 1..workers {
        match unsafe { libc::fork() } {
            -1 => return Err(io::Error::last_os_error()),
            0 => {
                worker(addr, body_len)?;
                std::process::exit(0);
            }
            _ => kids.push(()),
        }
    }
    let _ = kids;
    worker(addr, body_len)
}

fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|b| *b == needle)
}
