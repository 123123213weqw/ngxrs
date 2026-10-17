#!/usr/bin/env python3
"""Differential HTTP parity check: send identical raw requests to nginx and
ngxrs, compare status line, selected headers and body hash."""

import argparse
import hashlib
import os
import socket
import sys

INTERESTING = [
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "location",
    "connection",
    "etag",
    "last-modified",
    "cache-control",
]


def read_all(port, raw, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(raw)
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1") if lines else "<no response>"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    return status, headers, body


def summarize(res):
    status, headers, body = res
    picked = {k: headers.get(k) for k in INTERESTING if k in headers}
    return status, picked, len(body), hashlib.sha256(body).hexdigest()[:16]


def compare(name, a, b, strict_headers=True):
    sa, ha, la, da = summarize(a)
    sb, hb, lb, db = summarize(b)
    problems = []
    if sa.split(" ")[0] != sb.split(" ")[0]:
        problems.append(f"status {sa!r} != {sb!r}")
    if da != db or la != lb:
        problems.append(f"body differs (len {la} vs {lb})")
    if strict_headers:
        for k in sorted(set(ha) | set(hb)):
            if ha.get(k) != hb.get(k):
                problems.append(f"{k}: {ha.get(k)!r} != {hb.get(k)!r}")
    return problems, (sa, sb)


CASES = [
    ("simple-get", b"GET /1k.txt HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("head", b"HEAD /1k.txt HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("missing", b"GET /nope HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("index", b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("dir-no-slash", b"GET /sub HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("dir-slash", b"GET /sub/ HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("range", b"GET /1k.txt HTTP/1.1\r\nHost: bench\r\nRange: bytes=0-9\r\nConnection: close\r\n\r\n"),
    ("range-suffix", b"GET /1k.txt HTTP/1.1\r\nHost: bench\r\nRange: bytes=-16\r\nConnection: close\r\n\r\n"),
    ("range-bad", b"GET /1k.txt HTTP/1.1\r\nHost: bench\r\nRange: bytes=99999-\r\nConnection: close\r\n\r\n"),
    ("post", b"POST /1k.txt HTTP/1.1\r\nHost: bench\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"),
    ("http10", b"GET /1k.txt HTTP/1.0\r\n\r\n"),
    ("no-host", b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
    ("merged-slashes", b"GET //1k.txt HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("dot-segments", b"GET /sub/../1k.txt HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("encoded-dotdot", b"GET /%2e%2e/etc/passwd HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("query", b"GET /1k.txt?a=1&b=2 HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("unknown-method", b"BREW /1k.txt HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"),
    ("bad-version", b"GET / HTTP/9.9\r\nHost: bench\r\n\r\n"),
    ("etag-304", None),  # filled at runtime from simple-get
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nginx", type=int, default=18080)
    ap.add_argument("--ngxrs", type=int, default=18081)
    ap.add_argument("--www", default=os.path.join(os.path.dirname(__file__), "..", "bench", "www"))
    args = ap.parse_args()

    os.makedirs(os.path.join(args.www, "sub"), exist_ok=True)
    for name, size in [("1k.txt", 1024), ("64k.bin", 64 * 1024)]:
        p = os.path.join(args.www, name)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(b"x" * size)

    failures = 0
    rows = []
    for name, raw in CASES:
        if raw is None:
            continue
        a = read_all(args.nginx, raw)
        b = read_all(args.ngxrs, raw)
        problems, (sa, sb) = compare(name, a, b)
        rows.append((name, sa.split(" ")[1] if " " in sa else sa,
                     sb.split(" ")[1] if " " in sb else sb, problems))
        if problems:
            failures += 1

    # conditional GET needs the ETag nginx returned for the same inode
    base = read_all(args.nginx, CASES[0][1])
    etag = base[1].get("etag")
    if etag:
        raw = (f"GET /1k.txt HTTP/1.1\r\nHost: bench\r\nIf-None-Match: {etag}\r\n"
               "Connection: close\r\n\r\n").encode()
        a = read_all(args.nginx, raw)
        b = read_all(args.ngxrs, raw)
        problems, (sa, sb) = compare("if-none-match", a, b)
        rows.append(("if-none-match", sa.split(" ")[1], sb.split(" ")[1], problems))
        if problems:
            failures += 1

    width = max(len(r[0]) for r in rows) + 2
    print(f"{'case'.ljust(width)}{'nginx':<22}{'ngxrs':<22}result")
    for name, sa, sb, problems in rows:
        verdict = "OK" if not problems else "DIFF: " + "; ".join(problems)
        print(f"{name.ljust(width)}{sa:<22}{sb:<22}{verdict}")

    print(f"\n{len(rows) - failures}/{len(rows)} cases match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
