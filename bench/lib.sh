#!/usr/bin/env bash
# Shared helpers for the nginx/ngxrs comparison harness.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/bench/run"
WWW="$ROOT/bench/www"
OUT="$ROOT/bench/results"
PORT_NGINX="${PORT_NGINX:-19180}"
PORT_NGXRS="${PORT_NGXRS:-19181}"
# Prefer our own nginx 1.28 build; the distro one on this host is a Baota
# openresty build whose lualib is missing.
if [[ -z "${NGINX_BIN:-}" ]]; then
  if [[ -x /home/wzu/nginx-baseline/sbin/nginx ]]; then
    NGINX_BIN=/home/wzu/nginx-baseline/sbin/nginx
    NGINX_PREFIX=/home/wzu/nginx-baseline
  else
    NGINX_BIN=nginx
    NGINX_PREFIX=/usr/local/nginx
  fi
fi
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"

# The host's /usr/local LuaJIT is ABI-incompatible with the distro wrk build.
WRK="env LD_LIBRARY_PATH=/lib/x86_64-linux-gnu wrk"

make_fixtures() {
  mkdir -p "$RUN" "$WWW" "$OUT"
  python3 - "$WWW" <<'PY'
import os, sys
www = sys.argv[1]
os.makedirs(os.path.join(www, "sub"), exist_ok=True)
for name, size in [("1k.txt", 1024), ("64k.bin", 64 * 1024), ("1m.bin", 1024 * 1024)]:
    path = os.path.join(www, name)
    if not os.path.exists(path) or os.path.getsize(path) != size:
        with open(path, "wb") as f:
            f.write(b"0123456789abcdef" * (size // 16) + b"x" * (size % 16))
for name, body in [("index.html", "<h1>ngxrs bench</h1>\n"), ("sub/index.html", "<h1>sub</h1>\n")]:
    with open(os.path.join(www, name), "w") as f:
        f.write(body)
PY
}

write_conf() { # $1=port $2=out
  local port="$1" out="$2"
  cat > "$out" <<EOF
worker_processes auto;
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
  ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
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
