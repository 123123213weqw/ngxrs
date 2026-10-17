#!/usr/bin/env bash
# TLS throughput: nginx vs ngxrs on the same TLS config, ABBA interleaved.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

PT_NGINX=19443
PT_NGXRS=19444
D="${D:-6}"
ROUNDS="${ROUNDS:-3}"
T="${T:-8}"
CONNS="${CONNS:-128}"

make_fixtures
python3 - "$ROOT" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "tests"))
import tls_parity
tls_parity.ensure_certs()
PY

render() { sed -e "s|__ROOT__|$ROOT|g" -e "s|__WORKERS__|${WORKER_PROCESSES:-32}|" -e "s/listen 19443/listen $1/" "$ROOT/bench/tls.conf" > "$2"; }
render "$PT_NGINX" "$RUN/tlsb-nginx.conf"
render "$PT_NGXRS" "$RUN/tlsb-ngxrs.conf"

cleanup() { set +e; [[ -n "${NP:-}" ]] && kill "$NP" 2>/dev/null; [[ -n "${RP:-}" ]] && kill "$RP" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

"$NGINX_BIN" -c "$RUN/tlsb-nginx.conf" -p "$NGINX_PREFIX" 2>/dev/null & NP=$!
"$ROOT/target/release/ngxrs" -c "$RUN/tlsb-ngxrs.conf" -p "$ROOT" >/dev/null 2>"$RUN/tlsb.err" & RP=$!
sleep 1.5

med() { printf '%s\n' "$@" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
rps() {
  local out bad
  out=$($WRK -t"$T" -c"$CONNS" -d"${D}s" -H "Host: default.example" "$1" 2>&1)
  bad=$(echo "$out" | awk '/Non-2xx/{print $4; exit}')
  [ -n "${bad:-}" ] && [ "$bad" != "0" ] && { echo "ERROR: non-2xx=$bad" >&2; exit 1; }
  echo "$out" | awk '/Requests\/sec/{print $2; exit}'
}

a=(); b=()
for _ in $(seq 1 "$ROUNDS"); do
  a+=("$(rps "https://127.0.0.1:$PT_NGINX/1k.txt")")
  b+=("$(rps "https://127.0.0.1:$PT_NGXRS/1k.txt")")
  b+=("$(rps "https://127.0.0.1:$PT_NGXRS/1k.txt")")
  a+=("$(rps "https://127.0.0.1:$PT_NGINX/1k.txt")")
done
printf '%-10s %-12s %-12s %s\n' target rps ratio note
ma=$(med "${a[@]}"); mb=$(med "${b[@]}")
awk -v a="$ma" -v b="$mb" 'BEGIN{printf "%-10s %-12.0f %-12.3f %s\n", "nginx", a, 1.0, "tls1.3"}' 
awk -v a="$ma" -v b="$mb" 'BEGIN{printf "%-10s %-12.0f %-12.3f %s\n", "ngxrs", b, b/a, "tls1.3"}'
