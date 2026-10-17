#!/usr/bin/env python3
"""TLS parity check: certificates, SNI selection, protocol versions and plain
HTTP/1.1 over TLS, compared against nginx on the same config."""

import argparse
import os
import socket
import ssl
import sys
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS = os.path.join(ROOT, "bench", "certs")


def ensure_certs():
    os.makedirs(CERTS, exist_ok=True)
    specs = [("default", "default.example"), ("exact", "exact.example"), ("wild", "*.wild.example")]
    for name, cn in specs:
        crt = os.path.join(CERTS, f"{name}.crt")
        key = os.path.join(CERTS, f"{name}.key")
        if os.path.exists(crt) and os.path.exists(key):
            continue
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", crt, "-days", "3650",
                "-subj", f"/CN={cn}",
                "-addext", f"subjectAltName=DNS:{cn}",
            ],
            check=True,
            capture_output=True,
        )


def tls_request(port, sni, path="/who", version=None, ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            cert = s.getpeercert(binary_form=True)
            cipher = s.cipher()
            ver = s.version()
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin1")
    return status, body, cert, cipher[0] if cipher else None, ver


def cert_cn(der):
    """Extract the CN from a DER cert using the openssl CLI (no crypto libs)."""
    with open("/tmp/_probe.crt", "wb") as f:
        f.write(der)
    out = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", "/tmp/_probe.crt", "-noout", "-subject"],
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nginx", type=int, default=19443)
    ap.add_argument("--ngxrs", type=int, default=19444)
    args = ap.parse_args()

    ensure_certs()

    rows = []
    failures = 0

    def record(name, a, b, compare_body=True):
        nonlocal failures
        problems = []
        sa, ba, ca, cipa, va = a
        sb, bb, cb, cipb, vb = b
        if sa != sb:
            problems.append(f"status {sa!r} != {sb!r}")
        if compare_body and ba != bb:
            problems.append(f"body {ba[:40]!r} != {bb[:40]!r}")
        if cert_cn(ca) != cert_cn(cb):
            problems.append(f"cert {cert_cn(ca)!r} != {cert_cn(cb)!r}")
        if va != vb:
            problems.append(f"tls version {va} != {vb}")
        rows.append((name, sa.split(" ")[1], sb.split(" ")[1], va, problems))
        if problems:
            failures += 1

    # SNI routing: each name must be served by its own server block *and* cert
    for name, expected in [
        ("exact.example", b"exact"),
        ("anything.wild.example", b"wild"),
        ("unknown.example", b"default"),
        (None, b"default"),
    ]:
        a = tls_request(args.nginx, name)
        b = tls_request(args.ngxrs, name)
        record(f"sni:{name or '-'}", a, b)
        if not b[1].startswith(expected):
            rows.append((f"sni-body:{name or '-'}", "-", "-", "-",
                         [f"expected {expected!r} got {b[1][:20]!r}"]))
            failures += 1

    # protocol versions
    for label, ver in [("tls1.2", ssl.TLSVersion.TLSv1_2), ("tls1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            a = tls_request(args.nginx, "default.example", version=ver)
            b = tls_request(args.ngxrs, "default.example", version=ver)
            record(f"proto:{label}", a, b)
        except ssl.SSLError as e:
            rows.append((f"proto:{label}", "-", "-", "-", [f"ssl error {e}"]))
            failures += 1

    # static file over TLS
    a = tls_request(args.nginx, "default.example", path="/1k.txt")
    b = tls_request(args.ngxrs, "default.example", path="/1k.txt")
    record("static-over-tls", a, b)

    width = max(len(r[0]) for r in rows) + 2
    print(f"{'case'.ljust(width)}{'nginx':<8}{'ngxrs':<8}{'tls':<9}result")
    for name, sa, sb, ver, problems in rows:
        verdict = "OK" if not problems else "DIFF: " + "; ".join(str(p) for p in problems)
        print(f"{name.ljust(width)}{str(sa):<8}{str(sb):<8}{str(ver):<9}{verdict}")
    print(f"\n{len(rows) - failures}/{len(rows)} cases match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
