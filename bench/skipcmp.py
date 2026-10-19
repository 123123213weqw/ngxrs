#!/usr/bin/env python3
"""Attribute ngxrs's per-request CPU in four points.

  nginx     reference
  floor     bare tokio: read a head, write a canned 200 + 5-byte body
  skip      ngxrs with NGXRS_SKIP_AFTER_PARSE=1: our parser and connection
            loop, then the same canned 200 + 5-byte body
  full      ngxrs serving `location /ret { return 200 "hello"; }`

  skip - floor   our parser + connection loop, versus the framework alone
  full - skip    routing, access phase, filters and header rendering

All four answer 200 with a 5-byte body, so the write side is comparable.
Interleaved, medians. Only kills processes by pidfile.
"""

import glob
import statistics
import subprocess
import sys
import time

ROOT = "/home/wzu/ngxrs"
RUN = ROOT + "/bench/run"
WRK = ["env", "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu", "wrk"]
NGINX_BIN = ROOT + "/../nginx-baseline/sbin/nginx"
NGINX_PREFIX = ROOT + "/../nginx-baseline"
NGXRS_BIN = ROOT + "/target/release/ngxrs"
FLOOR_BIN = ROOT + "/bench/floor/floor"

PORTS = {
    "nginx": 18951,
    "floor": 18952,
    "skip": 18953,
    "full": 18954,
    # skip-right-after-parse with the per-request keepalive timer disabled, to
    # separate the timer-wheel registration from the parser itself.
    "notimer": 18955,
    # Graduated stops: 1 = after parse, 2 = after URL normalisation.
    "stage1": 18956,
    "stage2": 18957,
}

CONF = """worker_processes %(wp)s;
daemon off;
pid %(run)s/pid-4w-%(port)d;
error_log %(run)s/err-4w-%(port)d.log warn;
events { worker_connections 8192; }
http {
  access_log off;
  default_type text/plain;
  keepalive_timeout 65;
  keepalive_requests 1000000;
  sendfile on;
  server {
    listen %(port)d;
    server_name _;
    location /ret { return 200 "hello"; }
  }
}
"""


def sched(pid):
    run = 0
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
                    r, _, _ = map(int, f.read().split())
            except OSError:
                continue
            run += r
    return run


def kill_pidfile(port):
    try:
        with open("%s/pid-4w-%d" % (RUN, port)) as f:
            subprocess.run(["kill", f.read().strip()], stderr=subprocess.DEVNULL)
    except OSError:
        pass


def port_free(port, timeout=6.0):
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
    for _, port in PORTS.items():
        kill_pidfile(port)
    subprocess.run(["pkill", "-x", "floor"], stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    for name, port in PORTS.items():
        if not port_free(port):
            raise RuntimeError("port %d busy" % port)
        path = "%s/4w-%s.conf" % (RUN, name)
        with open(path, "w") as f:
            f.write(CONF % dict(wp=workers, run=RUN, port=port))
        if name == "nginx":
            cmd, envv = [NGINX_BIN, "-c", path, "-p", NGINX_PREFIX], None
        elif name == "floor":
            cmd, envv = [FLOOR_BIN, str(port), str(workers), "5"], None
        elif name == "skip":
            cmd = [NGXRS_BIN, "-c", path, "-p", ROOT]
            envv = dict(**__import__("os").environ, NGXRS_SKIP_AFTER_PARSE="1")
        elif name == "stage1":
            cmd = [NGXRS_BIN, "-c", path, "-p", ROOT]
            envv = dict(**__import__("os").environ, NGXRS_STOP_STAGE="1")
        elif name == "stage2":
            cmd = [NGXRS_BIN, "-c", path, "-p", ROOT]
            envv = dict(**__import__("os").environ, NGXRS_STOP_STAGE="2")
        elif name == "notimer":
            cmd = [NGXRS_BIN, "-c", path, "-p", ROOT]
            envv = dict(
                **__import__("os").environ,
                NGXRS_SKIP_AFTER_PARSE="1",
                NGXRS_NO_IDLE_TIMER="1",
            )
        else:
            cmd, envv = [NGXRS_BIN, "-c", path, "-p", ROOT], None
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=envv,
        )
    time.sleep(2.0)


def pid_for(name):
    if name == "floor":
        out = subprocess.run(["pgrep", "-x", "-o", "floor"], capture_output=True, text=True).stdout
        return int(out.split()[0])
    return int(open("%s/pid-4w-%d" % (RUN, PORTS[name])).read().strip())


def measure(name, conns, dur):
    port = PORTS[name]
    pid = pid_for(name)
    r0 = sched(pid)
    t0 = time.time()
    proc = subprocess.run(
        WRK + ["-t4", "-c%d" % conns, "-d%ds" % dur, "http://127.0.0.1:%d/ret" % port],
        capture_output=True, text=True,
    )
    elapsed = time.time() - t0
    r1 = sched(pid)
    rps = 0.0
    for line in proc.stdout.splitlines():
        if "Requests/sec" in line:
            rps = float(line.split()[1])
    if rps < 1000:
        raise RuntimeError("%s: no load (%s)" % (name, proc.stderr[:200]))
    return rps, (r1 - r0) / 1e3 / (rps * elapsed)


def main():
    conns = int(sys.argv[1]) if len(sys.argv) > 1 else 128
    workers = sys.argv[2] if len(sys.argv) > 2 else "1"
    dur = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    repeats = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    start(workers)
    print("workers=%s c=%d d=%ds repeats=%d  (/ret, 200 + 5-byte body)" % (workers, conns, dur, repeats))
    res = {k: {"cpu": [], "rps": []} for k in PORTS}
    for _ in range(repeats):
        for name in ("nginx", "floor", "stage1", "stage2", "full"):
            rps, cpu = measure(name, conns, dur)
            res[name]["cpu"].append(cpu)
            res[name]["rps"].append(rps)
    med = {}
    wanted = ("nginx", "floor", "stage1", "stage2", "full")
    for name in wanted:
        if not res[name]["cpu"]:
            raise RuntimeError("%s produced no samples" % name)
        med[name] = (statistics.median(res[name]["cpu"]), statistics.median(res[name]["rps"]))
    for name in ("nginx", "floor", "stage1", "stage2", "full"):
        c, r = med[name]
        print("  %-6s cpu=%6.2fus rps=%8.0f  vs_ngxrs_full=%.2f" % (name, c, r, c / med["full"][0]))
    print()
    print("  parser + connection loop        : %+.2fus" % (med["stage1"][0] - med["floor"][0]))
    print("  URL normalisation (parse_target): %+.2fus" % (med["stage2"][0] - med["stage1"][0]))
    print("  everything after location match : %+.2fus" % (med["full"][0] - med["stage2"][0]))
    print("  total ngxrs over floor          : %+.2fus" % (med["full"][0] - med["floor"][0]))
    print("  total nginx over floor          : %+.2fus" % (med["nginx"][0] - med["floor"][0]))
    for name, port in PORTS.items():
        kill_pidfile(port)
    subprocess.run(["pkill", "-x", "floor"], stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
