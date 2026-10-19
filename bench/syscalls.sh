#!/usr/bin/env bash
# Compare per-request syscalls between nginx and ngxrs.
#
# perf is blocked on this host (perf_event_paranoid=4, no root), so this uses
# `strace -c`. Both servers run with worker_processes 1 so the attach target is
# unambiguous (nginx: one worker child; ngxrs: one process). strace slows both
# down, so only the counts are compared, normalised per completed request.
set -uo pipefail

ROOT=/home/wzu/ngxrs
RUN=$ROOT/bench/run
WWW=$ROOT/bench/www
NGINX_BIN=$ROOT/../nginx-baseline/sbin/nginx
NGINX_PREFIX=$ROOT/../nginx-baseline
NGXRS_BIN=$ROOT/target/release/ngxrs
WRK="env LD_LIBRARY_PATH=/lib/x86_64-linux-gnu wrk"
CONNS=${1:-32}
DUR=${2:-8}
PATH_=${3:-/1k.txt}

mkdir -p "$RUN"
mkconf() { # $1=port $2=file
  cat >"$2" <<EOF
worker_processes 1;
daemon off;
pid $RUN/pid-sc-$1;
error_log $RUN/err-sc-$1.log warn;
events { worker_connections 65535; }
http {
  include $ROOT/conf/mime.types;
  default_type application/octet-stream;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65; keepalive_requests 1000000;
  access_log off;
  server { listen $1; server_name _; root $WWW; location / { } }
}
EOF
}

ulimit -n 65536 2>/dev/null || true
mkconf 18701 "$RUN/sc-n.conf"
mkconf 18702 "$RUN/sc-x.conf"

"$NGINX_BIN" -c "$RUN/sc-n.conf" -p "$NGINX_PREFIX" </dev/null >/dev/null 2>&1 &
"$NGXRS_BIN" -c "$RUN/sc-x.conf" -p "$ROOT" </dev/null >/dev/null 2>&1 &
sleep 2

NMASTER=$(cat "$RUN/pid-sc-18701")
NWORKER=$(pgrep -P "$NMASTER" | head -1)
XPROC=$(cat "$RUN/pid-sc-18702")

trace_one() { # $1=label $2=pid $3=port
  local label=$1 pid=$2 port=$3
  $WRK -t2 -c"$CONNS" -d"$DUR"s "http://127.0.0.1:$port$PATH_" >"/tmp/wrk-$label.txt" 2>&1 &
  local wrkpid=$!
  sleep 1
  timeout 4 strace -c -f -p "$pid" -o "/tmp/sc-$label.txt" >/dev/null 2>&1
  wait $wrkpid
  local reqs
  reqs=$(awk '/Requests\/sec:/{print $2}' "/tmp/wrk-$label.txt")
  echo "--- $label ($PATH_) rps=$reqs ---"
  head -14 "/tmp/sc-$label.txt"
}

trace_one nginx "$NWORKER" 18701
trace_one ngxrs "$XPROC" 18702

pkill -x ngxrs
kill "$NMASTER" 2>/dev/null
