#!/usr/bin/env python3
"""Three-way CPU comparison: nginx vs the tokio floor vs ngxrs.

If `floor` (a server that only reads a request head and writes a canned
response) already costs about as much as ngxrs, the gap against nginx is the
price of the framework rather than a defect in our request path.

Interleaved (nginx, floor, ngxrs) x repeats, medians.
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
FLOOR_BIN = ROOT + "/bench/floor/floor"

CONF = """worker_processes %(wp)s;
daemon off;
pid %(run)s/pid-3w-%(port)d;
error_log %(run)s/err-3w-%(port)d.log warn;
events { worker_connections 65535; }
http {
  include %(root)s/conf/mime.types;
  default_type application/octet-stream;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65; keepalive_requests 1000000;
  access_log off;
  server {
    listen %(port)d; server_name _; root %(www)s;
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


def kill_pidfile(path):
    try:
        with open(path) as f:
            subprocess.run(["kill", f.read().strip()])
    except OSError:
        pass


def wait_free(port, timeout=5.0):
    """A previous run's server can still hold the port; binding would fail."""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.1)
    return False


def start(workers):
    subprocess.run(["pkill", "-x", "ngxrs"])
    subprocess.run(["pkill", "-x", "floor"])
    for port in (18601, 18602, 18603):
        kill_pidfile("%s/pid-3w-%d" % (RUN, port))
        kill_pidfile("%s/pid-cpu-%d" % (RUN, port))
    time.sleep(1.5)
    nport, fport, xport = 18601, 18603, 18602
    for port in (nport, fport, xport):
        if not wait_free(port):
            raise RuntimeError("port %d still in use" % port)
    path = RUN + "/3w-nginx.conf"
    with open(path, "w") as f:
        f.write(CONF % dict(conc="", wp=workers, run=RUN, port=nport, root=ROOT, www=WWW))
    subprocess.Popen(
        [NGINX_BIN, "-c", path, "-p", NGINX_PREFIX],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    path = RUN + "/3w-ngxrs.conf"
    with open(path, "w") as f:
        f.write(CONF % dict(conc="", wp=workers, run=RUN, port=xport, root=ROOT, www=WWW))
    subprocess.Popen(
        [NGXRS_BIN, "-c", path, "-p", ROOT],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.Popen(
        [FLOOR_BIN, str(fport), str(workers), "1024"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2.0)
    return {"nginx": (nport, None), "floor": (fport, None), "ngxrs": (xport, None)}


def pidof(name):
    out = subprocess.run(["pgrep", "-x", "-o", "floor"], capture_output=True, text=True).stdout
    return int(out.split()[0])


def measure(name, port, pid, conns, dur, path):
    r0, w0 = sched(pid)
    t0 = time.time()
    proc = subprocess.run(
        WRK + ["-t4", "-c%d" % conns, "-d%ds" % dur, "http://127.0.0.1:%d%s" % (port, path)],
        capture_output=True, text=True,
    )
    elapsed = time.time() - t0
    r1, w1 = sched(pid)
    rps = 0.0
    for line in proc.stdout.splitlines():
        if "Requests/sec" in line:
            rps = float(line.split()[1])
    if rps == 0:
        raise RuntimeError("no wrk result for %s: %s" % (name, proc.stderr[:200]))
    reqs = rps * elapsed
    return rps, (r1 - r0) / 1e3 / reqs, (w1 - w0) / 1e3 / reqs


def main():
    conns = int(sys.argv[1]) if len(sys.argv) > 1 else 128
    workers = sys.argv[2] if len(sys.argv) > 2 else "1"
    dur = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    repeats = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    paths = sys.argv[5:] or ["/1k.txt"]
    info = start(workers)
    pids = {
        "nginx": int(open("%s/pid-3w-18601" % RUN).read().strip()),
        "ngxrs": int(open("%s/pid-3w-18602" % RUN).read().strip()),
        "floor": pidof("floor"),
    }
    print("workers=%s c=%d d=%ds repeats=%d" % (workers, conns, dur, repeats))
    for path in paths:
        res = {k: {"cpu": [], "rps": []} for k in pids}
        for _ in range(repeats):
            for name in ("nginx", "floor", "ngxrs"):
                rps, cpu, _ = measure(name, info[name][0], pids[name], conns, dur, path)
                res[name]["cpu"].append(cpu)
                res[name]["rps"].append(rps)
        base = statistics.median(res["nginx"]["cpu"])
        fl = statistics.median(res["floor"]["cpu"])
        print("--- %s" % path)
        for name in ("nginx", "floor", "ngxrs"):
            c = statistics.median(res[name]["cpu"])
            r = statistics.median(res[name]["rps"])
            print(
                "  %-6s cpu=%6.2fus rps=%8.0f  vs_nginx=%.2f  vs_floor=%.2f"
                % (name, c, r, c / base, c / fl)
            )
    subprocess.run(["pkill", "-x", "ngxrs"])
    subprocess.run(["pkill", "-x", "floor"])


if __name__ == "__main__":
    main()
