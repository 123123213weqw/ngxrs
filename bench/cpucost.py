#!/usr/bin/env python3
"""Bisect per-request CPU between the HTTP core and file serving.

Both servers get the same three endpoints:
  /ret      return 200 "hello"      -> HTTP core only, no filesystem
  /1k.txt   static 1024-byte file   -> core + open/fstat/read/close
  /missing  404                      -> core + failed stat

If ngxrs is 2x on /ret too, the cost is in the request/response path. If the gap
only appears on the static endpoints, it is in file handling.
"""

import glob
import subprocess
import sys
import time

ROOT = "/home/wzu/ngxrs"
RUN = ROOT + "/bench/run"
WWW = ROOT + "/bench/www"
WRK = ["env", "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu", "wrk"]
NGINX_BIN = ROOT + "/../nginx-baseline/sbin/nginx"
NGINX_PREFIX = ROOT + "/../nginx-baseline"
NGXRS_BIN = ROOT + "/target/release/ngxrs"
PORTS = {"nginx": 18601, "ngxrs": 18602}

CONF = """worker_processes %(wp)s;
daemon off;
pid %(run)s/pid-cpu-%(port)d;
error_log %(run)s/err-cpu-%(port)d.log warn;
events { worker_connections 65535; }
http {
  include %(root)s/conf/mime.types;
  default_type application/octet-stream;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  keepalive_requests 1000000;
  access_log off;
  server {
    listen %(port)d;
    server_name _;
    root %(www)s;
    location / { }
    location /ret { return 200 "hello"; }
  }
}
"""

ENDPOINTS = ["/ret", "/1k.txt", "/64k.bin", "/1m.bin", "/missing"]


def per_thread(pid):
    out = []
    for t in glob.glob("/proc/%d/task/*" % pid):
        try:
            with open(t + "/schedstat") as f:
                run, wait, slices = map(int, f.read().split())
        except OSError:
            continue
        out.append((run, wait, slices))
    return out


def tree(pid):
    pids = [pid]
    try:
        with open("/proc/%d/task/%d/children" % (pid, pid)) as f:
            pids.extend(int(c) for c in f.read().split())
    except OSError:
        pass
    return pids


def snap(root_pid):
    run = wait = slices = 0
    for p in tree(root_pid):
        for r, w, s in per_thread(p):
            run += r
            wait += w
            slices += s
    return run, wait, slices


def start(workers):
    subprocess.run(["pkill", "-x", "ngxrs"])
    for port in PORTS.values():
        try:
            with open("%s/pid-cpu-%d" % (RUN, port)) as f:
                subprocess.run(["kill", f.read().strip()])
        except OSError:
            pass
    time.sleep(1.0)
    for name, binary, prefix in (
        ("nginx", NGINX_BIN, NGINX_PREFIX),
        ("ngxrs", NGXRS_BIN, ROOT),
    ):
        port = PORTS[name]
        path = "%s/cpu-%s.conf" % (RUN, name)
        with open(path, "w") as f:
            f.write(CONF % dict(wp=workers, run=RUN, port=port, root=ROOT, www=WWW))
        subprocess.Popen(
            [binary, "-c", path, "-p", prefix],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    time.sleep(2.0)


def pid_of(name):
    with open("%s/pid-cpu-%d" % (RUN, PORTS[name])) as f:
        return int(f.read().strip())


def main():
    c = int(sys.argv[1]) if len(sys.argv) > 1 else 256
    workers = sys.argv[2] if len(sys.argv) > 2 else "auto"
    start(workers)
    pids = {name: pid_of(name) for name in PORTS}
    print("workers=%s  c=%d  (-t4 -d5s)" % (workers, c))
    print("%-6s %-9s %-11s %-10s %-9s" % ("srv", "path", "rps", "cpu/req", "wait/req"))
    for ep in ENDPOINTS:
        for name in ("nginx", "ngxrs"):
            port = PORTS[name]
            r0, w0, _ = snap(pids[name])
            t0 = time.time()
            proc = subprocess.run(
                WRK
                + ["-t4", "-c%d" % c, "-d5s", "http://127.0.0.1:%d%s" % (port, ep)],
                capture_output=True,
                text=True,
            )
            dur = time.time() - t0
            r1, w1, _ = snap(pids[name])
            rps = 0.0
            for line in proc.stdout.splitlines():
                if "Requests/sec" in line:
                    rps = float(line.split()[1])
            reqs = max(rps * dur, 1)
            print(
                "%-6s %-9s %-11.0f %8.2fus %8.2fus"
                % (name, ep, rps, (r1 - r0) / 1e3 / reqs, (w1 - w0) / 1e3 / reqs)
            )
        print()
    subprocess.run(["pkill", "-x", "ngxrs"])


if __name__ == "__main__":
    main()
