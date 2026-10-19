#!/usr/bin/env python3
"""Where does the CPU go? Per-thread breakdown during a fixed load.

sched.py showed ngxrs burns ~80us of CPU per request against nginx's ~46us.
That could be uniform real work or a few pathological threads. This samples
per-thread schedstat twice around one wrk run and prints the distribution.
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


def per_thread(pid):
    out = {}
    for t in glob.glob("/proc/%d/task/*" % pid):
        tid = int(t.rsplit("/", 1)[1])
        try:
            with open(t + "/schedstat") as f:
                run, wait, slices = map(int, f.read().split())
            with open(t + "/comm") as f:
                name = f.read().strip()
            with open(t + "/stat") as f:
                fields = f.read().rsplit(") ", 1)[1].split()
            utime = int(fields[11])
            stime = int(fields[12])
        except (OSError, IndexError):
            continue
        out[tid] = (run, wait, slices, utime + stime, name)
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
    merged = {}
    for p in tree(root_pid):
        for tid, v in per_thread(p).items():
            merged[(p, tid)] = v
    return merged


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
    c = int(sys.argv[1]) if len(sys.argv) > 1 else 512
    start()
    for name, port, pid in (
        ("nginx", PORT_N, pid_of(RUN + "/pid-acc-%d" % PORT_N)),
        ("ngxrs", PORT_X, pid_of(RUN + "/pid-acc-%d" % PORT_X)),
    ):
        before = snap(pid)
        t0 = time.time()
        proc = subprocess.run(
            WRK + ["-t4", "-c%d" % c, "-d5s", "http://127.0.0.1:%d/1k.txt" % port],
            capture_output=True,
            text=True,
        )
        dur = time.time() - t0
        after = snap(pid)
        rps = 0.0
        for line in proc.stdout.splitlines():
            if "Requests/sec" in line:
                rps = float(line.split()[1])
        reqs = max(rps * dur, 1)
        deltas = []
        total = 0
        for key, (run1, wait1, sl1, cpu1, nm) in after.items():
            if key not in before:
                continue
            run0, wait0, sl0, cpu0, _ = before[key]
            d = run1 - run0
            total += d
            deltas.append((d, wait1 - wait0, sl1 - sl0, nm, key[0]))
        deltas.sort(reverse=True)
        print(
            "=== %s c=%d rps=%.0f threads=%d total_cpu=%.2fs cpu/req=%.2fus"
            % (name, c, rps, len(deltas), total / 1e9, total / 1e3 / reqs)
        )
        busiest = deltas[:6]
        for d, w, s, nm, p in busiest:
            print(
                "    %-12s pid=%-7d cpu=%8.3fs (%5.1f%%) wait=%7.3fs isw=%6d"
                % (nm, p, d / 1e9, 100.0 * d / max(total, 1), w / 1e9, s)
            )
        idle = [d for d, _, _, _, _ in deltas if d < total * 0.001]
        print(
            "    threads below 0.1%% of total: %d   top-6 share: %.1f%%"
            % (len(idle), 100.0 * sum(d for d, *_ in busiest) / max(total, 1))
        )
    subprocess.run(["pkill", "-x", "ngxrs"])


if __name__ == "__main__":
    main()
