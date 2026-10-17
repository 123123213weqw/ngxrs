#!/usr/bin/env bash
# Worker-count scaling curve: nginx vs ngxrs on identical static configs.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

T="${T:-24}"
C="${C:-1024}"
D="${D:-6}"
WORKERS="${WORKERS:-4 8 16 32 64}"

make_fixtures

render() { # $1=workers $2=port $3=out
  cat > "$3" <<CONF
worker_processes $1;
daemon off;
pid $RUN/scale-$2.pid;
error_log $RUN/scale-$2.err warn;
events { worker_connections 65535; }
http {
  include $ROOT/conf/mime.types;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65; keepalive_requests 1000000;
  access_log off;
  server { listen $2; root $WWW; location / { } }
}
CONF
}

cleanup() {
  set +e
  [[ -n "${RP:-}" ]] && kill "$RP" 2>/dev/null
  [[ -n "${PORT:-}" ]] && "$NGINX_BIN" -c "$RUN/scale-nginx-$PORT.conf" -p "$NGINX_PREFIX" -s stop 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

echo "scale test: t=$T c=$C d=${D}s"
printf '%-9s %-12s %-12s %s\n' workers nginx ngxrs ratio
for w in $WORKERS; do
  np=$((19600 + w))
  rp=$((19700 + w))
  render "$w" "$np" "$RUN/scale-nginx-$w.conf"
  render "$w" "$rp" "$RUN/scale-ngxrs-$w.conf"
  PORT=$w
  "$NGINX_BIN" -c "$RUN/scale-nginx-$w.conf" -p "$NGINX_PREFIX" 2>/dev/null
  "$ROOT/target/release/ngxrs" -c "$RUN/scale-ngxrs-$w.conf" -p "$ROOT" >"$RUN/scale-$w.out" 2>&1 &
  RP=$!
  wait_port "$np" >/dev/null 2>&1
  wait_port "$rp" >/dev/null 2>&1
  rn=$($WRK -t"$T" -c"$C" -d"${D}s" "http://127.0.0.1:$np/1k.txt" 2>&1 | awk '/Requests\/sec/{print $2; exit}')
  rr=$($WRK -t"$T" -c"$C" -d"${D}s" "http://127.0.0.1:$rp/1k.txt" 2>&1 | awk '/Requests\/sec/{print $2; exit}')
  awk -v w="$w" -v n="$rn" -v r="$rr" 'BEGIN{printf "%-9s %-12.0f %-12.0f %.3f\n", w, n, r, r/n}'
  kill "$RP" 2>/dev/null
  "$NGINX_BIN" -c "$RUN/scale-nginx-$w.conf" -p "$NGINX_PREFIX" -s stop 2>/dev/null
  RP=""
  sleep 0.5
done
