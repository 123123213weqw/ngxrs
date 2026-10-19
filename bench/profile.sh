#!/usr/bin/env bash
# Attribute ngxrs per-request CPU by phase, for one endpoint.
#
# Runs the server with NGXRS_PROF=1, drives load for a few seconds, then reads
# /_prof for thread-CPU microseconds per phase.
set -uo pipefail

ROOT=/home/wzu/ngxrs
RUN=$ROOT/bench/run
WWW=$ROOT/bench/www
NGXRS_BIN=$ROOT/target/release/ngxrs
WRK="env LD_LIBRARY_PATH=/lib/x86_64-linux-gnu wrk"
PORT=${1:-18801}
CONNS=${2:-32}
DUR=${3:-6}
shift 3 || true
PATHS=${*:-"/ret /1k.txt /missing"}

mkdir -p "$RUN"
cat >"$RUN/prof-x.conf" <<EOF
worker_processes 1;
daemon off;
pid $RUN/pid-prof-$PORT;
error_log $RUN/err-prof-$PORT.log warn;
events { worker_connections 65535; }
http {
  include $ROOT/conf/mime.types;
  default_type application/octet-stream;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65; keepalive_requests 1000000;
  access_log off;
  server {
    listen $PORT; server_name _; root $WWW;
    location / { }
    location /ret { return 200 "hello"; }
  }
}
EOF

ulimit -n 65536 2>/dev/null || true
pkill -x ngxrs 2>/dev/null
sleep 0.5
NGXRS_PROF=1 "$NGXRS_BIN" -c "$RUN/prof-x.conf" -p "$ROOT" </dev/null >/dev/null 2>&1 &
sleep 1.5

# wrk refuses `-c` smaller than `-t`, so a single-connection run (needed for
# uncontaminated region timing on a cooperative scheduler) must use one thread.
TH=2
if [ "$CONNS" -lt 2 ]; then TH=1; fi

for p in $PATHS; do
  curl -s "http://127.0.0.1:$PORT/_prof_reset" >/dev/null
  $WRK -t"$TH" -c"$CONNS" -d"$DUR"s "http://127.0.0.1:$PORT$p" >/tmp/prof-wrk.txt 2>&1
  echo "### $p  $(awk '/Requests\/sec:/{print $2" rps"}' /tmp/prof-wrk.txt)"
  curl -s "http://127.0.0.1:$PORT/_prof"
  echo
done

pkill -x ngxrs
