#!/usr/bin/env python3
"""Compare per-request CPU cost and scheduler wait between nginx and ngxrs.

`perf` is unavailable on the benchmark host (perf_event_paranoid=4, no root), so
this uses /proc/<pid>/task/<tid>/schedstat instead, which the kernel maintains
already: (runtime_ns, runqueue_wait_ns, timeslices).

Per request it reports:
  cpu    - nanoseconds of CPU actually consumed (runtime_ns delta)
  wait   - nanoseconds spent runnable but waiting for a CPU
  slices - involuntary context switches

If `cpu` is similar but `wait` is larger for one server, the difference is
scheduling/queueing, not work. If `cpu` is larger, it is compute.
"""

import glob
import subprocess
import sys
import time

ROOT = "/home/wzu/ngxrs"
RUN = ROOT + "/bench/run"
WRK = ["env", "LD_LIBRARY_PATH=/lib/x86_64-linux-gnu", "wrk"]
NGINX_BIN = ROOT + "/../nginx-baseline/sbin/nginx"
NGINX_PREFIX = ROOT + "/../nginx-baseline"
NGXRS_BIN = ROOT + "/target/release/ngxrs"
PORT_N = 18501
PORT_X = 18502


def thread_stats(pid):
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
        for r, w, s in thread_stats(p):
            run += r
            wait += w
            slices += s
    return run, wait, slices


def start():
    subprocess.run(["pkill", "-x", "ngxrs"])
    for pf in (RUN + "/pid-acc-%d" % PORT_N, RUN + "/pid-acc-%d" % PORT_X):
        try:
            with open(pf) as f:
                subprocess.run(["kill", f.read().strip()])
        except OSError:
            pass
    time.sleep(1.0)
    for binary, conf, prefix in (
        (NGINX_BIN, RUN + "/acc-n.conf", NGINX_PREFIX),
        (NGXRS_BIN, RUN + "/acc-x.conf", ROOT),
    ):
        subprocess.Popen(
            [binary, "-c", conf, "-p", prefix],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    time.sleep(2.0)


def pid_of(path):
    with open(path) as f:
        return int(f.read().strip())


def main():
    conns = [int(x) for x in sys.argv[1:]] or [512]
    for c in conns:
        start()
        targets = [
            ("nginx", PORT_N, pid_of(RUN + "/pid-acc-%d" % PORT_N)),
            ("ngxrs", PORT_X, pid_of(RUN + "/pid-acc-%d" % PORT_X)),
        ]
        for name, port, pid in targets:
            r0, w0, s0 = snap(pid)
            t0 = time.time()
            proc = subprocess.run(
                WRK + ["-t4", "-c%d" % c, "-d5s", "http://127.0.0.1:%d/1k.txt" % port],
                capture_output=True,
                text=True,
            )
            dur = time.time() - t0
            r1, w1, s1 = snap(pid)
            rps = ""
            for line in proc.stdout.splitlines():
                if "Requests/sec" in line:
                    rps = line.split()[1]
            reqs = max(int(float(rps) * dur), 1) if rps else 1
            print(
                "%-6s c=%-5d rps=%-11s cpu=%6.2fus wait=%7.2fus isw=%5.2f"
                % (
                    name,
                    c,
                    rps or "?",
                    (r1 - r0) / 1e3 / reqs,
                    (w1 - w0) / 1e3 / reqs,
                    (s1 - s0) / reqs,
                )
            )
        subprocess.run(["pkill", "-x", "ngxrs"])
        time.sleep(0.5)


if __name__ == "__main__":
    main()
