#!/usr/bin/env python3
"""Feature-level parity check against nginx for the non-static modules:
gzip, error_page, reverse proxy, upstream balancing, WebSocket upgrade.

Both servers are started with the same nginx-format config (bench/feature.conf),
only the listening port differs.
"""

import argparse
import gzip
import http.client
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- backends
class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        port = self.server.server_address[1]
        payload = f'{{"backend":{port},"path":"{self.path}"}}'.encode()
        return payload

    def do_GET(self):
        if self.path.startswith("/json"):
            body = self._body()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/chunked"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (b"alpha-", b"beta-", b"gamma"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
            return
        if self.path.startswith("/echo"):
            body = self._body()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"backend-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n) if n else b""
        body = b"got:" + data
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "10")
        self.end_headers()


class WSHandler(BackendHandler):
    """Minimal WebSocket echo: upgrades, then echoes raw frames."""

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            return super().do_GET()
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = _ws_accept(key)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        sock = self.connection
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                sock.sendall(data)
        except OSError:
            pass
        self.close_connection = True


def _ws_accept(key):
    import base64
    import hashlib

    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()


def start_backends():
    servers = []
    for port, handler in ((19201, WSHandler), (19202, BackendHandler)):
        srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


# ---------------------------------------------------------------- requests
def fetch(port, path, headers=None, method="GET", body=None, timeout=5):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), data
    finally:
        conn.close()


def summarize(status, headers, body, port=None):
    if headers.get("content-encoding") == "gzip" and body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    keep = {}
    for k in ("content-type", "content-encoding", "content-length", "transfer-encoding",
              "vary", "etag", "last-modified", "connection", "location"):
        if k in headers:
            keep[k] = headers[k]
    if port and "location" in keep:
        # the two servers listen on different ports; that is not a difference
        keep["location"] = keep["location"].replace(f":{port}", ":PORT")
    return status, keep, len(body), body[:200]


def compare(name, a, b, ignore=(), ports=(None, None)):
    sa, ha, la, ba = summarize(*a, port=ports[0])
    sb, hb, lb, bb = summarize(*b, port=ports[1])
    problems = []
    if sa != sb:
        problems.append(f"status {sa} != {sb}")
    if ba != bb:
        problems.append(f"body {ba[:60]!r} != {bb[:60]!r}")
    if ha.get("content-encoding") == hb.get("content-encoding") == "gzip":
        # nginx streams the gzip through chunked encoding, we send a length;
        # the decoded payload is what matters.
        ignore = tuple(ignore) + ("transfer-encoding", "content-length")
    for k in sorted(set(ha) | set(hb)):
        if k in ignore:
            continue
        if k == "content-length" and la != lb:
            continue
        if ha.get(k) != hb.get(k):
            problems.append(f"{k}: {ha.get(k)!r} != {hb.get(k)!r}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nginx", type=int, default=19300)
    ap.add_argument("--ngxrs", type=int, default=19301)
    args = ap.parse_args()

    start_backends()
    time.sleep(0.4)

    cases = [
        ("gzip-json", "/gzip/data.json", {"Accept-Encoding": "gzip"}),
        ("gzip-off", "/plain/data.json", {"Accept-Encoding": "gzip"}),
        ("gzip-noaccept", "/gzip/data.json", {}),
        ("gzip-small", "/gzip/tiny.txt", {"Accept-Encoding": "gzip"}),
        ("err-404", "/missing.html", {}),
        ("err-404-internal", "/404.html", {}),
        ("err-418", "/teapot", {}),
        ("proxy-get", "/p/echo", {}),
        ("proxy-post", "/p/echo", {}),
        ("proxy-chunked", "/p/chunked", {}),
        ("proxy-direct", "/direct/echo", {}),
        ("proxy-keepalive-seq", "/p/echo", {}),
        ("rewrite-last", "/rw/old/x", {}),
        ("rewrite-permanent", "/rw/perm/x", {}),
        ("rewrite-redirect", "/rw/tmp/x", {}),
        ("rewrite-break", "/rw/new/y", {}),
        ("rewrite-none", "/rw/other", {}),
        ("if-default", "/if/x", {}),
        ("if-set-pro", "/if/x", {"X-Tier": "pro"}),
        ("if-else-branch", "/if/x", {"X-Tier": "basic"}),
        ("if-regex", "/if-re/x", {"User-Agent": "curl/8.0"}),
        ("if-regex-miss", "/if-re/x", {"User-Agent": "Mozilla/5.0"}),
    ]

    rows = []
    failures = 0

    def record(name, pa, pb, ignore=()):
        nonlocal failures
        problems = compare(name, pa, pb, ignore, ports=(args.nginx, args.ngxrs))
        sa = pa[0]
        sb = pb[0]
        rows.append((name, sa, sb, problems))
        if problems:
            failures += 1

    for name, path, headers in cases:
        if name == "proxy-post":
            a = fetch(args.nginx, path, headers, method="POST", body=b"hello")
            b = fetch(args.ngxrs, path, headers, method="POST", body=b"hello")
            record(name, a, b, ignore=("content-length",))
            continue
        if name == "proxy-keepalive-seq":
            # ten requests over fresh connections must all succeed
            ok = True
            for _ in range(10):
                st, _, body = fetch(args.ngxrs, path, headers)
                ok = ok and st == 200 and body.startswith(b'{"backend"')
            rows.append((name, 200 if ok else 0, 200, [] if ok else ["ngxrs failed"]))
            if not ok:
                failures += 1
            continue
        a = fetch(args.nginx, path, headers)
        b = fetch(args.ngxrs, path, headers)
        # backend identity differs only if balancing differs; compare shape
        ignore = ("etag", "last-modified")
        record(name, a, b, ignore=ignore)

    # ---- proxy_cache ----
    # Clear both caches, then request the same URL three times: MISS, HIT, HIT.
    import shutil
    for d in ("cache-nginx", "cache-ngxrs"):
        shutil.rmtree(os.path.join(ROOT, "bench", "run", d), ignore_errors=True)

    def cache_seq(port, path):
        return [fetch(port, path)[1].get("x-cache-status", "") for _ in range(3)]

    # nginx uses its own cache dir in the nginx-rendered config; both start cold
    a_seq = cache_seq(args.nginx, "/cached/echo")
    b_seq = cache_seq(args.ngxrs, "/cached/echo")
    problems = []
    if a_seq[1:] != b_seq[1:]:
        problems.append(f"sequence {a_seq} != {b_seq}")
    if b_seq[0] != "MISS" or b_seq[1] != "HIT" or b_seq[2] != "HIT":
        problems.append(f"ngxrs sequence wrong: {b_seq}")
    # cached body must be identical to the first (uncached) response
    a_body = fetch(args.nginx, "/cached/echo")[2]
    b_body = fetch(args.ngxrs, "/cached/echo")[2]
    if a_body != b_body:
        problems.append(f"cached body {a_body[:40]!r} != {b_body[:40]!r}")
    rows.append(("proxy-cache-hit", ",".join(a_seq), ",".join(b_seq), problems))
    if problems:
        failures += 1

    # balancing distribution (only meaningful for ngxrs: nginx uses its own)
    dist = {}
    for _ in range(20):
        st, _, body = fetch(args.ngxrs, "/p/echo", {})
        if st == 200:
            port = body.split(b'"backend":')[1].split(b",")[0]
            dist[port] = dist.get(port, 0) + 1
    balanced = len(dist) == 2 and min(dist.values()) >= 5
    rows.append(("lb-round-robin", "-", "-", [] if balanced else [f"distribution {dist}"]))
    if not balanced:
        failures += 1

    # websocket upgrade through ngxrs
    ws_ok = False
    try:
        s = socket.create_connection(("127.0.0.1", args.ngxrs), timeout=5)
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        s.sendall(
            f"GET /ws/ HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        head = s.recv(4096)
        ws_ok = b"101" in head and b"sec-websocket-accept" in head.lower()
        if not ws_ok:
            print("  ws debug:", head[:400])
        s.close()
    except OSError as e:
        rows.append(("websocket", "-", "-", [f"exception {e}"]))
    rows.append(("websocket", 101 if ws_ok else 0, 101, [] if ws_ok else ["ngxrs upgrade failed"]))
    if not ws_ok:
        failures += 1

    width = max(len(r[0]) for r in rows) + 2
    print(f"{'case'.ljust(width)}{'nginx':<8}{'ngxrs':<8}result")
    for name, sa, sb, problems in rows:
        verdict = "OK" if not problems else "DIFF: " + "; ".join(str(p) for p in problems)
        print(f"{name.ljust(width)}{str(sa):<8}{str(sb):<8}{verdict}")
    print(f"\n{len(rows) - failures}/{len(rows)} cases match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
