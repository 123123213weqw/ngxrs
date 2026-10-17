#!/usr/bin/env bash
# Benchmark ngxrs against nginx on identical static-file configurations.
# Requires nginx and wrk in PATH (both present on the V100 host).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

DUR="${DUR:-10}"
CONNS="${CONNS:-512}"
THREADS="${THREADS:-8}"
REPEAT="${REPEAT:-3}"

trap stop_pair EXIT
start_pair

RESULT_FILE="$OUT/bench-$(date +%Y%m%d-%H%M%S).tsv"
printf 'target\trequests_per_sec\tavg_latency\tp99\n' >"$RESULT_FILE"
echo "commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" >>"$RESULT_FILE"

echo "benchmark: t=$THREADS c=$CONNS d=${DUR}s repeat=$REPEAT  (nginx :$PORT_NGINX, ngxrs :$PORT_NGXRS)"

field() { awk -v k="$1" 'index($0, k) == 1 { print $2; exit }'; }

bench_one() { # $1=url $2=label
  local url="$1" label="$2"
  $WRK -t"$THREADS" -c"$CONNS" -d3s "$url" >/dev/null 2>&1 || true
  local rps=() lat=() p99=()
  for _ in $(seq 1 "$REPEAT"); do
    local out
    out=$($WRK -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$url" 2>&1)
    rps+=("$(echo "$out" | field "Requests/sec:")")
    lat+=("$(echo "$out" | field "Latency")")
    p99+=("$(echo "$out" | awk '/ 99% /{print $2; exit}')")
  done
  local med
  med=$(printf '%s\n' "${rps[@]}" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  printf '%s\t%s\t%s\t%s\n' "$label" "$med" "${lat[0]}" "${p99[0]}" | tee -a "$RESULT_FILE"
}

for path in 1k.txt 64k.bin 1m.bin; do
  echo "== $path =="
  bench_one "http://127.0.0.1:$PORT_NGINX/$path" "nginx/$path"
  bench_one "http://127.0.0.1:$PORT_NGXRS/$path" "ngxrs/$path"
done

echo
echo "results written to $RESULT_FILE"
column -t -s $'\t' "$RESULT_FILE"
