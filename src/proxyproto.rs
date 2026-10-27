//! HAProxy PROXY protocol (v1 text and v2 binary), from
//! `ngx_proxy_protocol.c`.
//!
//! `listen ... proxy_protocol` makes the *first* bytes on the socket a header
//! that carries the client's real address, which is the whole point: the
//! connection comes from a load balancer, so `$binary_remote_addr` would
//! otherwise be the balancer. Nothing about the request changes until the
//! header has been consumed.
//!
//! The two shapes:
//!
//! ```text
//! v1:  PROXY TCP4 192.0.2.1 192.0.2.2 123 5678\r\n
//!      PROXY UNKNOWN\r\n
//!      PROXY UNKNOWN 1 2 3 4 5 6\r\n      (anything after UNKNOWN is skipped)
//!
//! v2:  \r\n\r\n\0\r\nQUIT\n  <ver/cmd> <fam/transport> <len16> <addrs> [TLVs]
//! ```
//!
//! `UNKNOWN` and an unsupported v2 family are *not* errors: nginx answers them
//! with an empty address/port and lets the request through, which is what
//! `proxy_protocol.t` asserts (`X-PP: !`).

/// One parsed PROXY header.
#[derive(Debug, Clone, Default)]
pub struct Pp {
    /// `$proxy_protocol_addr` -- the client, as text (IPv6 in nginx's lowercase
    /// compressed form).
    pub src_addr: String,
    pub src_port: u16,
    /// `$proxy_protocol_server_addr` -- the address the balancer connected to.
    pub dst_addr: String,
    pub dst_port: u16,
    /// v2 TLVs, still packed (`<type><len16><value>...`), which is what
    /// `$proxy_protocol_tlv_*` walks.
    pub tlvs: Vec<u8>,
}

/// Parsed prefix length and the header it carried.
pub struct Parsed {
    pub pp: Pp,
    /// Bytes consumed from the front of the buffer.
    pub consumed: usize,
}

const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// Try to parse a PROXY header from the front of `buf`.
///
/// `Ok(None)` means "not enough bytes yet, read more". `Err` means the header is
/// broken, which nginx reports as a 400 and then closes.
pub fn parse(buf: &[u8]) -> Result<Option<Parsed>, ()> {
    // A v2 signature needs 16 bytes before the fixed part can be sized.
    if buf.len() >= 16 && buf.starts_with(V2_SIGNATURE) {
        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        // 16 fixed + payload.
        if buf.len() < 16 + len {
            // nginx caps this at `NGX_PROXY_PROTOCOL_V2_MAX_HEADER`; a length
            // that big is a broken peer rather than a slow one.
            if len > 65535 {
                return Err(());
            }
            return Ok(None);
        }
        return Ok(Some(parse_v2(&buf[12..16 + len])?));
    }
    // v1 starts with "PROXY "; the header ends at the first CRLF.
    if buf.len() >= 6 && &buf[..6] == b"PROXY " {
        let Some(pos) = find_crlf(buf) else {
            // nginx refuses a v1 header longer than 107 bytes.
            if buf.len() > 107 {
                return Err(());
            }
            return Ok(None);
        };
        return Ok(Some(parse_v1(&buf[..pos + 2])?));
    }
    // Neither signature, and enough bytes to know: nginx is strict here.
    if buf.len() >= V2_SIGNATURE.len() || buf.len() >= 6 {
        return Err(());
    }
    Ok(None)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    memchr::memmem::find(buf, b"\r\n")
}

fn parse_v1(line: &[u8]) -> Result<Parsed, ()> {
    // `PROXY ` has already been matched.
    let rest = &line[6..line.len() - 2];
    let text = std::str::from_utf8(rest).map_err(|_| ())?;
    if let Some(after) = text.strip_prefix("UNKNOWN") {
        // "PROXY UNKNOWN" plus anything: skip to the CRLF, no addresses.
        let _ = after;
        return Ok(Parsed {
            pp: Pp::default(),
            consumed: line.len(),
        });
    }
    let mut it = text.split(' ');
    let proto = it.next().ok_or(())?;
    if proto != "TCP4" && proto != "TCP6" {
        return Err(());
    }
    let src = it.next().ok_or(())?;
    let dst = it.next().ok_or(())?;
    let sport = it.next().ok_or(())?;
    let dport = it.next().ok_or(())?;
    if it.next().is_some() {
        return Err(());
    }
    // nginx accepts only `[0-9a-fA-F:.]` in the addresses and parses the ports
    // as unsigned decimal.
    for a in [src, dst] {
        if !a
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(());
        }
    }
    let port = |s: &str| -> Result<u16, ()> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        s.parse::<u32>().map_err(|_| ())?.try_into().map_err(|_| ())
    };
    Ok(Parsed {
        pp: Pp {
            // nginx copies the text verbatim, so `2001:Db8::1` keeps its case.
            src_addr: src.to_string(),
            dst_addr: dst.to_string(),
            src_port: port(sport)?,
            dst_port: port(dport)?,
            tlvs: Vec::new(),
        },
        consumed: line.len(),
    })
}

fn parse_v2(payload: &[u8]) -> Result<Parsed, ()> {
    // `payload` starts at the version/command byte: 12 signature bytes were
    // already matched by the caller.
    if payload.len() < 2 {
        return Err(());
    }
    let ver_cmd = payload[0];
    if ver_cmd >> 4 != 2 {
        return Err(());
    }
    let command = ver_cmd & 0x0f;
    // `payload` is everything after the 12-byte signature.
    let consumed = 12 + payload.len();
    // Only PROXY (1) carries addresses; LOCAL (0) is skipped like an unknown
    // family, which is nginx's behaviour.
    if command != 1 {
        return Ok(Parsed {
            pp: Pp::default(),
            consumed,
        });
    }
    let fam_transport = payload[1];
    if fam_transport & 0x0f != 1 {
        // Only STREAM.
        return Ok(Parsed {
            pp: Pp::default(),
            consumed,
        });
    }
    // ver/cmd, family/transport, length (which the caller already bounds), then
    // the address block and any TLVs.
    let body = &payload[4..];
    let (pp, used) = match fam_transport >> 4 {
        1 => {
            if body.len() < 12 {
                return Err(());
            }
            let src = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let dst = std::net::Ipv4Addr::new(body[4], body[5], body[6], body[7]);
            let sp = u16::from_be_bytes([body[8], body[9]]);
            let dp = u16::from_be_bytes([body[10], body[11]]);
            (
                Pp {
                    src_addr: src.to_string(),
                    dst_addr: dst.to_string(),
                    src_port: sp,
                    dst_port: dp,
                    tlvs: Vec::new(),
                },
                12,
            )
        }
        2 => {
            if body.len() < 36 {
                return Err(());
            }
            let mut s = [0u8; 16];
            s.copy_from_slice(&body[0..16]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&body[16..32]);
            let sp = u16::from_be_bytes([body[32], body[33]]);
            let dp = u16::from_be_bytes([body[34], body[35]]);
            (
                Pp {
                    // `ngx_sock_ntop` prints IPv6 in the compressed lowercase
                    // form, which `Ipv6Addr`'s Display also produces.
                    src_addr: std::net::Ipv6Addr::from(s).to_string(),
                    dst_addr: std::net::Ipv6Addr::from(d).to_string(),
                    src_port: sp,
                    dst_port: dp,
                    tlvs: Vec::new(),
                },
                36,
            )
        }
        _ => {
            // Unsupported family: skip the whole header, keep the connection.
            return Ok(Parsed {
                pp: Pp::default(),
                consumed,
            });
        }
    };
    let mut pp = pp;
    if body.len() > used {
        pp.tlvs = body[used..].to_vec();
    }
    Ok(Parsed { pp, consumed })
}

impl Pp {
    /// `$proxy_protocol_addr` family: a port of 0 renders as the empty string
    /// (`ngx_http_variable_proxy_protocol_port` only formats `0 < port < 65536`).
    pub fn port_text(port: u16) -> String {
        if port > 0 {
            port.to_string()
        } else {
            String::new()
        }
    }

    /// `ngx_proxy_protocol_get_tlv`: `name` is what follows
    /// `proxy_protocol_tlv_`, i.e. a symbolic name, `0xNN`, or `ssl_<sub>`.
    ///
    /// Returns `None` for an absent TLV and `Err` for a malformed one, which
    /// nginx turns into a 500.
    pub fn tlv(&self, name: &str) -> Result<Option<Vec<u8>>, ()> {
        if self.tlvs.is_empty() {
            return Ok(None);
        }
        // `ssl_<sub>`: the sub-TLVs live inside TLV 0x20 after a 5-byte prefix
        // (`client` + 4-byte verify). nginx checks the raw name prefix, so
        // `ssl` alone is the whole TLV and `ssl_verify` is the prefix field.
        if let Some(sub) = name.strip_prefix("ssl_") {
            let Some(ssl) = lookup(&self.tlvs, 0x20)? else {
                return Ok(None);
            };
            if ssl.len() < 5 {
                return Err(());
            }
            if sub == "verify" {
                let v = u32::from_be_bytes([ssl[1], ssl[2], ssl[3], ssl[4]]);
                return Ok(Some(v.to_string().into_bytes()));
            }
            return lookup_named(&ssl[5..], sub).map(|v| v.map(|v| v.to_vec()));
        }
        lookup_named(&self.tlvs, name).map(|v| v.map(|v| v.to_vec()))
    }
}

/// `ngx_proxy_protocol_lookup_tlv` by numeric type.
fn lookup(tlvs: &[u8], want: u8) -> Result<Option<&[u8]>, ()> {
    let mut p = tlvs;
    while !p.is_empty() {
        if p.len() < 3 {
            return Err(());
        }
        let ty = p[0];
        let len = u16::from_be_bytes([p[1], p[2]]) as usize;
        let rest = &p[3..];
        if rest.len() < len {
            return Err(());
        }
        if ty == want {
            return Ok(Some(&rest[..len]));
        }
        p = &rest[len..];
    }
    Ok(None)
}

/// Symbolic name or `0xNN` -> the TLV's value.
fn lookup_named<'a>(tlvs: &'a [u8], name: &str) -> Result<Option<&'a [u8]>, ()> {
    // The two tables from the nginx source, in its order, so `0x…` and a name
    // resolve identically.
    const TOP: &[(&str, u8)] = &[
        ("alpn", 0x01),
        ("authority", 0x02),
        ("unique_id", 0x05),
        ("ssl", 0x20),
        ("netns", 0x30),
    ];
    const SUB: &[(&str, u8)] = &[
        ("version", 0x21),
        ("cn", 0x22),
        ("cipher", 0x23),
        ("sig_alg", 0x24),
        ("key_alg", 0x25),
    ];
    if let Some(hex) = name.strip_prefix("0x") {
        let ty = u32::from_str_radix(hex, 16).map_err(|_| ())?;
        if ty > 255 {
            return Err(());
        }
        return lookup(tlvs, ty as u8);
    }
    // Sub-TLV names are only reachable through `ssl_`, but nginx's `te` pointer
    // is already the sub table in that case; here the caller has narrowed
    // `tlvs` to the ssl payload, so try the sub names too.
    for (n, ty) in TOP.iter().chain(SUB.iter()) {
        if *n == name {
            return lookup(tlvs, *ty);
        }
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1(line: &str) -> Result<Option<Parsed>, ()> {
        parse(line.as_bytes())
    }

    #[test]
    fn v1_tcp4_and_tcp6() {
        let p = v1("PROXY TCP4 192.0.2.1 192.0.2.2 123 5678\r\n").unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "192.0.2.1");
        assert_eq!(p.pp.dst_addr, "192.0.2.2");
        assert_eq!((p.pp.src_port, p.pp.dst_port), (123, 5678));
        // The whole line, CRLF included.
        assert_eq!(p.consumed, 41);

        // The address text is copied, not reformatted.
        let p = v1("PROXY TCP6 2001:Db8::1 2001:Db8::2 123 5678\r\n").unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "2001:Db8::1");
        assert_eq!(p.pp.src_port, 123);
    }

    #[test]
    fn v1_unknown_is_accepted_with_empty_addresses() {
        for line in ["PROXY UNKNOWN\r\n", "PROXY UNKNOWN 1 2 3 4 5 6\r\n"] {
            let p = v1(line).unwrap().unwrap();
            assert_eq!(p.pp.src_addr, "");
            assert_eq!(p.pp.src_port, 0);
            assert_eq!(Pp::port_text(p.pp.src_port), "");
        }
    }

    #[test]
    fn v1_rejects_what_nginx_rejects() {
        assert!(v1("PROXY TCP4 192.0.2.1 192.0.2.2 123\r\n").is_err());
        assert!(v1("PROXY TCP5 192.0.2.1 192.0.2.2 1 2\r\n").is_err());
        assert!(v1("PROXY TCP4 192.0.2.1 192.0.2.2 99999 2\r\n").is_err());
        assert!(v1("PROXY TCP4 192.0.2.1 192.0.2.2 x 2\r\n").is_err());
        assert!(v1("PROXY TCP4 192.0.2.1 192.0.2.2 1 2 3\r\n").is_err());
        // Not a PROXY header at all.
        assert!(v1("GET / HTTP/1.1\r\n").is_err());
        // Incomplete: wait for more.
        assert!(v1("PROXY TCP4 192.0.2.1").unwrap().is_none());
    }

    fn v2_bytes(fam_transport: u8, body: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.push(0x21);
        out.push(fam_transport);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn v2_inet_and_inet6() {
        let mut body = Vec::new();
        body.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        body.extend_from_slice(&123u16.to_be_bytes());
        body.extend_from_slice(&5678u16.to_be_bytes());
        let buf = v2_bytes(0x11, &body);
        let p = parse(&buf).unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "192.0.2.1");
        assert_eq!(p.pp.dst_port, 5678);
        assert_eq!(p.consumed, 16 + body.len());

        let mut b6 = Vec::new();
        b6.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        b6.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        b6.extend_from_slice(&123u16.to_be_bytes());
        b6.extend_from_slice(&5678u16.to_be_bytes());
        let buf = v2_bytes(0x21, &b6);
        let p = parse(&buf).unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "2001:db8::1");
        assert_eq!(p.pp.dst_addr, "2001:db8::2");
    }

    #[test]
    fn v2_unknown_family_and_command_pass_through_empty() {
        // 0x41: AF_UNSPEC/STREAM -> nginx skips the header, keeps the conn.
        let buf = v2_bytes(0x41, &[1, 2, 3, 4]);
        let p = parse(&buf).unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "");
        assert_eq!(p.consumed, 16 + 4);

        // Command LOCAL (0).
        let mut buf = V2_SIGNATURE.to_vec();
        buf.push(0x20);
        buf.push(0x11);
        buf.extend_from_slice(&0u16.to_be_bytes());
        let p = parse(&buf).unwrap().unwrap();
        assert_eq!(p.pp.src_addr, "");
    }

    #[test]
    fn v2_tlvs() {
        let mut body = Vec::new();
        body.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        body.extend_from_slice(&123u16.to_be_bytes());
        body.extend_from_slice(&5678u16.to_be_bytes());
        // alpn = "ALPN1"
        body.extend_from_slice(&[0x01, 0x00, 0x05]);
        body.extend_from_slice(b"ALPN1");
        // unknown-but-addressed 0x0a = "12345"
        body.extend_from_slice(&[0x0a, 0x00, 0x05]);
        body.extend_from_slice(b"12345");
        // ssl: client=1, verify=255, sub tlv 0x22 (cn) = "example.com"
        let mut ssl = vec![0x01, 0, 0, 0, 0xff];
        ssl.extend_from_slice(&[0x22, 0x00, 0x0b]);
        ssl.extend_from_slice(b"example.com");
        body.extend_from_slice(&[0x20, 0x00, ssl.len() as u8]);
        body.extend_from_slice(&ssl);

        let buf = v2_bytes(0x11, &body);
        let p = parse(&buf).unwrap().unwrap();
        assert_eq!(p.pp.tlv("alpn").unwrap().as_deref(), Some(&b"ALPN1"[..]));
        assert_eq!(p.pp.tlv("0x01").unwrap().as_deref(), Some(&b"ALPN1"[..]));
        assert_eq!(p.pp.tlv("0x000a").unwrap().as_deref(), Some(&b"12345"[..]));
        assert_eq!(p.pp.tlv("ssl_verify").unwrap().as_deref(), Some(&b"255"[..]));
        assert_eq!(
            p.pp.tlv("ssl_cn").unwrap().as_deref(),
            Some(&b"example.com"[..])
        );
        // Absent and malformed.
        assert!(p.pp.tlv("netns").unwrap().is_none());
        assert!(p.pp.tlv("0x0f").unwrap().is_none());
        assert!(p.pp.tlv("nonsense").is_err());
    }
}

/// `ngx_proxy_protocol_write`: the v1 header for a proxied connection.
///
/// nginx writes `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n`, or
/// `PROXY UNKNOWN\r\n` when either side is not an IP socket (`stream`'s
/// `proxy_protocol on`).
pub fn write(client: &std::net::SocketAddr, local: &std::net::SocketAddr) -> Vec<u8> {
    match (client, local) {
        (std::net::SocketAddr::V4(src), std::net::SocketAddr::V4(dst)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            src.ip(),
            dst.ip(),
            src.port(),
            dst.port()
        )
        .into_bytes(),
        (std::net::SocketAddr::V6(src), std::net::SocketAddr::V6(dst)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            src.ip(),
            dst.ip(),
            src.port(),
            dst.port()
        )
        .into_bytes(),
        // Mixed families have no v1 spelling.
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

/// Read a PROXY header straight off a fresh TCP connection.
///
/// The stream module needs this before TLS: `listen ... ssl proxy_protocol` puts
/// the header in front of the handshake. Reading exactly what the header claims
/// (never more) means the bytes that follow stay in the socket for the next
/// layer, which is why this does not use a buffered reader.
pub async fn read_from(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<Pp> {
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    // Enough for the v2 fixed part, so the common case is one read.
    let mut head = [0u8; 16];
    let mut filled = 0usize;
    while filled < 16 {
        let n = stream.read(&mut head[filled..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "PROXY protocol header truncated",
            ));
        }
        filled += n;
    }
    buf.extend_from_slice(&head);
    if buf.starts_with(V2_SIGNATURE) {
        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        buf.extend_from_slice(&body);
    } else {
        // v1: read one byte at a time until CRLF, so nothing past it is taken.
        loop {
            if find_crlf(&buf).is_some() {
                break;
            }
            if buf.len() > 107 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "broken PROXY protocol header",
                ));
            }
            let mut b = [0u8; 1];
            if stream.read(&mut b).await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "PROXY protocol header truncated",
                ));
            }
            buf.push(b[0]);
        }
    }
    match parse(&buf) {
        Ok(Some(p)) => Ok(p.pp),
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "PROXY protocol header truncated",
        )),
        Err(()) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "broken PROXY protocol header",
        )),
    }
}
