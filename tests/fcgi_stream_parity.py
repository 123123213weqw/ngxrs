#!/usr/bin/env python3
"""FastCGI + stream parity check against nginx.

Runs a minimal FastCGI responder (php-fpm stand-in), a TCP echo server and a UDP
echo server, then compares nginx and ngxrs through the same config.
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time

PAIRS = [
    # (responder behaviour, expected content-type)
    ("ok", b"text/plain"),
    ("json", b"application/json"),
    ("status", b"text/plain"),
    ("body", b"text/plain"),
]

# --------------------------------------------------------------- FastCGI responder
FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_record(sock):
    head = recv_exact(sock, 8)
    if head is None:
        return None
    version, ty, req_id, clen, plen, _ = struct.unpack(">BBHHBB", head)
    content = recv_exact(sock, clen) if clen else b""
    if plen:
        recv_exact(sock, plen)
    if content is None:
        return None
    return ty, req_id, content


def write_record(sock, ty, req_id, content):
    pad = (8 - len(content) % 8) % 8
    sock.sendall(struct.pack(">BBHHBB", 1, ty, req_id, len(content), pad, 0) + content + b"\0" * pad)


def parse_nv(data):
    params = {}
    i = 0
    while i < len(data):
        def read_len():
            nonlocal i
            b = data[i]
            if b >> 7:
                v = struct.unpack(">I", data[i:i + 4])[0] & 0x7FFFFFFF
                i += 4
                return v
            i += 1
            return b
        nlen = read_len()
        vlen = read_len()
        name = data[i:i + nlen].decode("latin1")
        i += nlen
        value = data[i:i + vlen].decode("latin1")
        i += vlen
        params[name] = value
    return params


def fcgi_responder(port, behaviour):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
    except OSError:
        return  # leftover responder is already listening
    srv.listen(64)

    def handle(conn):
        params = {}
        while True:
            rec = read_record(conn)
            if rec is None:
                conn.close()
                return
            ty, req_id, content = rec
            if ty == FCGI_PARAMS:
                if content:
                    params.update(parse_nv(content))
            elif ty == FCGI_STDIN:
                if not content:
                    break
        # respond
        script = params.get("SCRIPT_NAME", "")
        req_uri = params.get("REQUEST_URI", "")
        method = params.get("REQUEST_METHOD", "")
        body_all = params.get("CONTENT_LENGTH", "0")
        if behaviour == "json":
            payload = b'{"script":"%s","uri":"%s"}' % (script.encode(), req_uri.encode())
            head = b"Content-Type: application/json\r\n"
        elif behaviour == "status":
            payload = b"teapot\n"
            head = b"Status: 418 I'm a teapot\r\nContent-Type: text/plain\r\n"
        elif behaviour == "body":
            payload = b"%s %s len=%s\n" % (method.encode(), script.encode(), body_all.encode())
            head = b"Content-Type: text/plain\r\n"
        else:
            payload = b"hello from fcgi\n"
            head = b"Content-Type: text/plain\r\n"
        write_record(conn, FCGI_STDOUT, req_id, head + b"\r\n" + payload)
        write_record(conn, FCGI_STDOUT, req_id, b"")
        write_record(conn, FCGI_END_REQUEST, req_id, struct.pack(">IB3x", 0, 0))
        conn.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def tcp_echo(port, reuse=True):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
    except OSError:
        return  # a leftover server from an earlier run is already serving
    srv.listen(64)

    def handle(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        return

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                return
            s.sendto(b"udp:" + data, addr)

    threading.Thread(target=loop, daemon=True).start()


# --------------------------------------------------------------- clients
def http_get(port, path, headers=None, body=None, method="GET"):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    hdrs = {"Host": "t", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    s.sendall(req.encode() + (body or b""))
    data = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        data += d
    s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1")
    h = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            h[k.strip().lower().decode()] = v.strip().decode()
    return status, h, payload


def tcp_roundtrip(port, msg=b"ping\n"):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(msg)
    d = s.recv(4096)
    s.close()
    return d


def udp_roundtrip(port, msg=b"ping"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(msg, ("127.0.0.1", port))
    d, _ = s.recvfrom(4096)
    s.close()
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nginx", type=int, default=19500)
    ap.add_argument("--ngxrs", type=int, default=19501)
    ap.add_argument("--nginx-tcp", type=int, default=19510)
    ap.add_argument("--ngxrs-tcp", type=int, default=19511)
    ap.add_argument("--nginx-udp", type=int, default=19520)
    ap.add_argument("--ngxrs-udp", type=int, default=19521)
    args = ap.parse_args()

    fcgi_responder(19600, "ok")
    fcgi_responder(19601, "json")
    fcgi_responder(19602, "status")
    fcgi_responder(19603, "body")
    tcp_echo(19610)
    udp_echo(19611)
    time.sleep(0.6)

    rows = []
    failures = 0

    def record(name, a, b):
        nonlocal failures
        problems = []
        sa, ha, ba = a
        sb, hb, bb = b
        if sa.split(" ")[0] != sb.split(" ")[0]:
            problems.append(f"status {sa!r} != {sb!r}")
        if ba != bb:
            problems.append(f"body {ba[:60]!r} != {bb[:60]!r}")
        for k in ("content-type", "content-length"):
            if ha.get(k) != hb.get(k):
                problems.append(f"{k}: {ha.get(k)!r} != {hb.get(k)!r}")
        rows.append((name, sa.split(" ")[1], sb.split(" ")[1], problems))
        if problems:
            failures += 1

    fcgi_cases = [
        ("fcgi-basic", "/fcgi/info.php"),
        ("fcgi-json", "/fcgi2/info.php"),
        ("fcgi-status", "/fcgi3/teapot.php"),
        ("fcgi-pathinfo", "/fcgi/info.php/extra/path"),
        ("fcgi-post-body", "/fcgi4/p.php"),
        ("fcgi-query", "/fcgi/info.php?a=1&b=2"),
    ]
    for name, path in fcgi_cases:
        record(name, http_get(args.nginx, path), http_get(args.ngxrs, path))

    record("fcgi-post", 
           http_get(args.nginx, "/fcgi/p.php", body=b"hello", method="POST"),
           http_get(args.ngxrs, "/fcgi/p.php", body=b"hello", method="POST"))

    # stream TCP
    a = tcp_roundtrip(args.nginx_tcp)
    b = tcp_roundtrip(args.ngxrs_tcp)
    ok = a == b == b"ping\n"
    rows.append(("stream-tcp-echo", a.decode(errors="replace"), b.decode(errors="replace"),
                 [] if ok else [f"{a!r} != {b!r}"]))
    if not ok:
        failures += 1

    # stream UDP
    a = udp_roundtrip(args.nginx_udp)
    b = udp_roundtrip(args.ngxrs_udp)
    ok = a == b == b"udp:ping"
    rows.append(("stream-udp-echo", a.decode(errors="replace"), b.decode(errors="replace"),
                 [] if ok else [f"{a!r} != {b!r}"]))
    if not ok:
        failures += 1

    width = max(len(r[0]) for r in rows) + 2
    print(f"{'case'.ljust(width)}{'nginx':<24}{'ngxrs':<24}result")
    for name, sa, sb, problems in rows:
        verdict = "OK" if not problems else "DIFF: " + "; ".join(str(p) for p in problems)
        print(f"{name.ljust(width)}{sa:<24}{sb:<24}{verdict}")
    print(f"\n{len(rows) - failures}/{len(rows)} cases match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
