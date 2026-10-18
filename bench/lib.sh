#!/usr/bin/env bash
# Shared helpers for the nginx/ngxrs comparison harness.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/bench/run"
WWW="$ROOT/bench/www"
OUT="$ROOT/bench/results"
PORT_NGINX="${PORT_NGINX:-19180}"
PORT_NGXRS="${PORT_NGXRS:-19181}"
# Reference nginx for the A/B comparisons. Set NGINX_BIN/NGINX_PREFIX to pin it,
# otherwise look in the two conventional locations before falling back to PATH.
# A distro nginx is fine as long as it is built with the modules a test needs;
# some packaged builds (e.g. openresty without lualib) refuse to start, which is
# why an explicit path is preferred.
if [[ -z "${NGINX_BIN:-}" ]]; then
  for _cand in "$HOME/nginx-baseline/sbin/nginx" /usr/local/nginx/sbin/nginx; do
    if [[ -x "$_cand" ]]; then
      NGINX_BIN="$_cand"
      NGINX_PREFIX="${_cand%/sbin/nginx}"
      break
    fi
  done
  if [[ -z "${NGINX_BIN:-}" ]]; then
    NGINX_BIN=nginx
    NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
  fi
  unset _cand
fi
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"

# The host's /usr/local LuaJIT is ABI-incompatible with the distro wrk build.
WRK="env LD_LIBRARY_PATH=/lib/x86_64-linux-gnu wrk"

make_fixtures() {
  mkdir -p "$RUN" "$WWW" "$OUT"
  # `auth_basic` regression fixture: the guarded-proxy locations in
  # feature.conf authenticate against this file.
  printf 'user:{PLAIN}secret\n' > "$ROOT/htpasswd"
  python3 - "$WWW" <<'PY'
import os, sys
www = sys.argv[1]
os.makedirs(os.path.join(www, "sub"), exist_ok=True)
for name, size in [("1k.txt", 1024), ("64k.bin", 64 * 1024), ("1m.bin", 1024 * 1024)]:
    path = os.path.join(www, name)
    if not os.path.exists(path) or os.path.getsize(path) != size:
        with open(path, "wb") as f:
            f.write(b"0123456789abcdef" * (size // 16) + b"x" * (size % 16))
extra = [("404.html", "<h1>custom not found</h1>\n"), ("50x.html", "<h1>custom 50x</h1>\n"),
         ("gzip/data.json", '{"items":[%s]}' % ",".join('{"id":%d,"name":"item-%d"}' % (i, i) for i in range(200))),
         ("plain/data.json", '{"items":[%s]}' % ",".join('{"id":%d,"name":"item-%d"}' % (i, i) for i in range(200))),
         ("gzip/tiny.txt", "hi\n"), ("plain/tiny.txt", "hi\n")]
for name, body in extra:
    path = os.path.join(www, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)
for name, body in [("index.html", "<h1>ngxrs bench</h1>\n"), ("sub/index.html", "<h1>sub</h1>\n")]:
    with open(os.path.join(www, name), "w") as f:
        f.write(body)
PY
}

write_conf() { # $1=port $2=out
  local port="$1" out="$2"
  local wp="${WORKER_PROCESSES:-auto}"
  cat > "$out" <<EOF
worker_processes $wp;
daemon off;
pid $RUN/pid-$port;
error_log $RUN/error-$port.log warn;
events { worker_connections 65535; }
http {
  include $ROOT/conf/mime.types;
  default_type application/octet-stream;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  keepalive_requests 1000000;
  access_log off;
  server {
    listen $port;
    server_name _;
    root $WWW;
    index index.html;
    location / { }
  }
}
EOF
}

wait_port() { # $1=port
  for _ in $(seq 1 100); do
    if curl -fsS -m 1 "http://127.0.0.1:$1/1k.txt" -o /dev/null 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

start_pair() {
  # Enough for worker_connections, but NOT the hard limit: RLIMIT_NOFILE=1M
  # measurably slows open()/close() (measured: 1.02M -> 0.66M rps).
  ulimit -n 65536 2>/dev/null || true
  make_fixtures
  write_conf "$PORT_NGINX" "$RUN/nginx.conf"
  write_conf "$PORT_NGXRS" "$RUN/ngxrs.conf"
  "$NGINX_BIN" -c "$RUN/nginx.conf" -p "$NGINX_PREFIX" &
  NGINX_PID=$!
  "$ROOT/target/release/ngxrs" -c "$RUN/ngxrs.conf" -p "$ROOT" \
    >"$RUN/ngxrs.stdout" 2>"$RUN/ngxrs.stderr" &
  NGXRS_PID=$!
  wait_port "$PORT_NGINX" || { echo "nginx failed to start"; tail -5 "$RUN/error-$PORT_NGINX.log" 2>/dev/null; exit 1; }
  wait_port "$PORT_NGXRS" || { echo "ngxrs failed to start"; tail -5 "$RUN/ngxrs.stderr"; exit 1; }
}

stop_pair() {
  set +e
  [[ -n "${NGXRS_PID:-}" ]] && kill "$NGXRS_PID" 2>/dev/null
  [[ -n "${NGINX_PID:-}" ]] && kill "$NGINX_PID" 2>/dev/null
  wait 2>/dev/null
}
