#!/usr/bin/env python3
"""Interleaved A/B/B/A CPU-per-request comparison.

A plain "run nginx, then run ngxrs" pair is biased on a shared host: if another
tenant's load lands during the second run, the second server looks worse. This
alternates A B B A and takes the median of the two A samples and of the two B
samples, so a slow window hits both servers.

Reports thread-CPU nanoseconds per completed request, from schedstat.
"""

import glob
import statistics
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


def sched(pid):
    run = wait = 0
    pids = [pid]
    try:
        with open("/proc/%d/task/%d/children" % (pid, pid)) as f:
            pids.extend(int(c) for c in f.read().split())
    except OSError:
        pass
    for p in pids:
        for t in glob.glob("/proc/%d/task/*" % p):
            try:
                with open(t + "/schedstat") as f:
                    r, w, _ = map(int, f.read().split())
            except OSError:
                continue
            run += r
            wait += w
    return run, wait


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


def measure(name, path, conns, dur):
    port = PORTS[name]
    pid = int(open("%s/pid-cpu-%d" % (RUN, port)).read().strip())
    r0, w0 = sched(pid)
    t0 = time.time()
    proc = subprocess.run(
        WRK + ["-t4", "-c%d" % conns, "-d%ds" % dur, "http://127.0.0.1:%d%s" % (port, path)],
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - t0
    r1, w1 = sched(pid)
    rps = 0.0
    for line in proc.stdout.splitlines():
        if "Requests/sec" in line:
            rps = float(line.split()[1])
    if rps == 0:
        raise RuntimeError("wrk produced no result for %s %s" % (name, path))
    reqs = rps * elapsed
    return rps, (r1 - r0) / 1e3 / reqs, (w1 - w0) / 1e3 / reqs


def main():
    conns = int(sys.argv[1]) if len(sys.argv) > 1 else 256
    workers = sys.argv[2] if len(sys.argv) > 2 else "auto"
    dur = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    repeats = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    paths = sys.argv[5:] or ["/ret", "/1k.txt"]
    start(workers)
    print("workers=%s c=%d d=%ds repeats=%d (ABBA)" % (workers, conns, dur, repeats))
    for path in paths:
        res = {"nginx": ([], []), "ngxrs": ([], [])}
        for _ in range(repeats):
            for name in ("nginx", "ngxrs", "ngxrs", "nginx"):
                rps, cpu, wait = measure(name, path, conns, dur)
                res[name][0].append(cpu)
                res[name][1].append(rps)
        n_cpu = statistics.median(res["nginx"][0])
        x_cpu = statistics.median(res["ngxrs"][0])
        n_rps = statistics.median(res["nginx"][1])
        x_rps = statistics.median(res["ngxrs"][1])
        print(
            "%-10s nginx cpu=%6.2fus rps=%8.0f  ngxrs cpu=%6.2fus rps=%8.0f "
            "cpu_ratio=%.2f rps_ratio=%.3f"
            % (path, n_cpu, n_rps, x_cpu, x_rps, x_cpu / n_cpu, x_rps / n_rps)
        )
    subprocess.run(["pkill", "-x", "ngxrs"])


if __name__ == "__main__":
    main()
