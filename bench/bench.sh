#!/usr/bin/env bash
# Benchmark ngxrs against nginx on identical static-file configurations.
# Runs on the V100 host; requires nginx and wrk in PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/bench/run"
WWW="$ROOT/bench/www"
OUT="$ROOT/bench/results"
PORT_NGINX="${PORT_NGINX:-18080}"
PORT_NGXRS="${PORT_NGXRS:-18081}"
DUR="${DUR:-10}"
CONNS="${CONNS:-512}"
THREADS="${THREADS:-8}"
REPEAT="${REPEAT:-3}"

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
with open(os.path.join(www, "index.html"), "w") as f:
    f.write("<h1>ngxrs bench</h1>\n")
with open(os.path.join(www, "sub", "index.html"), "w") as f:
    f.write("<h1>sub</h1>\n")
PY

write_conf() {
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

write_conf "$PORT_NGINX" "$RUN/nginx.conf"
write_conf "$PORT_NGXRS" "$RUN/ngxrs.conf"

cleanup() {
  set +e
  [[ -n "${NGXRS_PID:-}" ]] && kill "$NGXRS_PID" 2>/dev/null
  [[ -n "${NGINX_PID:-}" ]] && kill "$NGINX_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

nginx -c "$RUN/nginx.conf" -p "$RUN" &
NGINX_PID=$!
"$ROOT/target/release/ngxrs" -c "$RUN/ngxrs.conf" -p "$ROOT" >"$RUN/ngxrs.stdout" 2>"$RUN/ngxrs.stderr" &
NGXRS_PID=$!

for port in "$PORT_NGINX" "$PORT_NGXRS"; do
  for _ in $(seq 1 100); do
    if curl -fsS -m 1 "http://127.0.0.1:$port/1k.txt" -o /dev/null 2>/dev/null; then break; fi
    sleep 0.1
  done
done

curl -fsS -m 2 "http://127.0.0.1:$PORT_NGINX/1k.txt" -o /dev/null || { echo "nginx did not start"; exit 1; }
curl -fsS -m 2 "http://127.0.0.1:$PORT_NGXRS/1k.txt" -o /dev/null || { echo "ngxrs did not start"; exit 1; }

field() { # $1=wrk output, $2=label regex
  awk -v k="$2" 'index($0, k) == 1 { print $2; exit }'
}

bench_one() { # $1=url $2=label
  local url="$1" label="$2"
  # warmup
  wrk -t"$THREADS" -c"$CONNS" -d3s "$url" >/dev/null 2>&1 || true
  local rps=() lat=() p99=()
  for _ in $(seq 1 "$REPEAT"); do
    local out
    out=$(wrk -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$url" 2>&1)
    rps+=("$(field "$out" "Requests/sec:")")
    lat+=("$(field "$out" "Latency")")
    p99+=("$(echo "$out" | awk '/ 99% /{print $2; exit}')")
  done
  local med
  med=$(printf '%s\n' "${rps[@]}" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  echo -e "$label\t$med\t${lat[0]}\t${p99[0]}" | tee -a "$RESULT_FILE"
}

RESULT_FILE="$OUT/bench-$(date +%Y%m%d-%H%M%S).tsv"
printf 'target\trequests_per_sec\tavg_latency\tp99\n' | tee "$RESULT_FILE" >/dev/null

echo "benchmark: t=$THREADS c=$CONNS d=${DUR}s repeat=$REPEAT" | tee "$RESULT_FILE".meta
for path in 1k.txt 64k.bin 1m.bin; do
  echo "== $path ==" | tee -a "$RESULT_FILE".meta
  bench_one "http://127.0.0.1:$PORT_NGINX/$path" "nginx/$path"
  bench_one "http://127.0.0.1:$PORT_NGXRS/$path" "ngxrs/$path"
done

echo
echo "results written to $RESULT_FILE"
column -t -s $'\t' "$RESULT_FILE"
