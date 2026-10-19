#!/usr/bin/env python3
"""Does per-request CPU scale with the number of `location` blocks?

nginx keeps a prefix tree plus per-server regex arrays. If our cost grows with
the location count, matching is linear and that is the HTTP-layer deficit.

Serves the same `/ret` from a config with N locations, for N = 2, 20, 200.
"""

import glob
import statistics
import subprocess
import sys
import time

ROOT = "/home/wzu/ngxrs"
RUN = ROOT + "/bench/run"
WRK = ["env", "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu", "wrk"]
NGXRS_BIN = ROOT + "/target/release/ngxrs"
NGINX_BIN = ROOT + "/../nginx-baseline/sbin/nginx"
NGINX_PREFIX = ROOT + "/../nginx-baseline"
PORT_X = 18922
PORT_N = 18921

HEAD = """worker_processes 1;
daemon off;
pid %(run)s/pid-%(port)d;
error_log %(run)s/err-%(port)d.log warn;
events { worker_connections 16384; }
http {
  access_log off;
  default_type text/plain;
  keepalive_timeout 65;
  keepalive_requests 1000000;
  server {
    listen %(port)d;
    server_name _;
    location /ret { return 200 "hello"; }
"""

TAIL = """  }
}
"""


def conf(n, port):
    body = []
    for i in range(n):
        body.append('    location /p%04d/ { return 200 "p%04d"; }\n' % (i, i))
    return (HEAD % dict(run=RUN, port=port)) + "".join(body) + TAIL


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


def kill_pidfile(path):
    """Only ever kill the process this harness started.

    `pkill -x nginx` would kill any nginx on this shared host, including other
    tenants' servers, so it must never be used here.
    """
    try:
        with open(path) as f:
            subprocess.run(["kill", f.read().strip()], stderr=subprocess.DEVNULL)
    except OSError:
        pass


def port_free(port, timeout=5.0):
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


def start(n, which):
    port = PORT_X if which == "ngxrs" else PORT_N
    kill_pidfile("%s/pid-%d" % (RUN, port))
    time.sleep(0.8)
    if not port_free(port):
        raise RuntimeError("port %d still in use" % port)
    path = "%s/loc-%s-%d.conf" % (RUN, which, n)
    with open(path, "w") as f:
        f.write(conf(n, port))
    binary = NGXRS_BIN if which == "ngxrs" else NGINX_BIN
    prefix = ROOT if which == "ngxrs" else NGINX_PREFIX
    subprocess.Popen(
        [binary, "-c", path, "-p", prefix],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 8.0
    while time.time() < deadline:
        try:
            return int(open("%s/pid-%d" % (RUN, port)).read().strip()), port
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("%s did not start: %s" % (which, path))


def measure(pid, port, conns, dur):
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
    if rps == 0:
        raise RuntimeError("no result: %s" % proc.stderr[:300])
    return rps, (r1 - r0) / 1e3 / (rps * elapsed)


def main():
    conns = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    print("c=%d d=2s repeats=%d  (/ret)" % (conns, repeats))
    print("%-6s %-5s %-10s %-10s" % ("srv", "locs", "rps", "cpu/req"))
    for which in ("nginx", "ngxrs"):
        prev = None
        for n in (2, 20, 200):
            samples = []
            rpss = []
            for _ in range(repeats):
                pid, port = start(n, which)
                rps, cpu = measure(pid, port, conns, 2)
                samples.append(cpu)
                rpss.append(rps)
            c = statistics.median(samples)
            delta = "" if prev is None else "  (+%.2fus)" % (c - prev)
            prev = c
            print("%-6s %-5d %-10.0f %-10.2f%s" % (which, n, statistics.median(rpss), c, delta))
            kill_pidfile("%s/pid-%d" % (RUN, PORT_X if which == "ngxrs" else PORT_N))
            time.sleep(0.5)


if __name__ == "__main__":
    main()
