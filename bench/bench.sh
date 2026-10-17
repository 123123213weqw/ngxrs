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
printf 'target\trequests_per_sec\tavg_latency\tp99\tratio\n' >"$RESULT_FILE"
echo "commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" >>"$RESULT_FILE"

echo "benchmark: t=$THREADS c=$CONNS d=${DUR}s repeat=$REPEAT  (nginx :$PORT_NGINX, ngxrs :$PORT_NGXRS)"

field() { awk -v k="$1" 'index($0, k) == 1 { print $2; exit }'; }

# One measurement round; echoes "rps latency p99".
round() { # $1=url
  local out
  out=$($WRK -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$1" 2>&1)
  local r l p bad
  r=$(echo "$out" | field "Requests/sec:")
  l=$(echo "$out" | field "Latency")
  p=$(echo "$out" | awk '/ 99% /{print $2; exit}')
  bad=$(echo "$out" | awk '/Non-2xx/{print $4; exit}')
  # A run that produced error responses measures nothing (e.g. EMFILE when the
  # fd limit is too low for CONNS) — make it loud instead of reporting it.
  if [ -n "${bad:-}" ] && [ "$bad" != "0" ]; then
    echo "ERROR: $1 returned $bad non-2xx responses" >&2
    exit 1
  fi
  echo "$r $l $p"
}

median() { printf '%s\n' "$@" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

# ABBA ordering neutralises drift on a shared machine: any load spike hits
# both targets roughly equally.
bench_pair() { # $1=path
  local path="$1"
  local ua="http://127.0.0.1:$PORT_NGINX/$path"
  local ub="http://127.0.0.1:$PORT_NGXRS/$path"

  $WRK -t"$THREADS" -c"$CONNS" -d3s "$ua" >/dev/null 2>&1 || true
  $WRK -t"$THREADS" -c"$CONNS" -d3s "$ub" >/dev/null 2>&1 || true

  local ra=() rb=() la=() lb=() pa=() pb=()
  local n=0
  while [ "$n" -lt "$REPEAT" ]; do
    # A B B A
    read -r r l p <<<"$(round "$ua")"; ra+=("$r"); la+=("$l"); pa+=("$p")
    read -r r l p <<<"$(round "$ub")"; rb+=("$r"); lb+=("$l"); pb+=("$p")
    read -r r l p <<<"$(round "$ub")"; rb+=("$r"); lb+=("$l"); pb+=("$p")
    read -r r l p <<<"$(round "$ua")"; ra+=("$r"); la+=("$l"); pa+=("$p")
    n=$((n + 1))
  done

  local ma mb
  ma=$(median "${ra[@]}")
  mb=$(median "${rb[@]}")
  printf '%-16s\t%s\t%s\t%s\t%s\n' "nginx/$path" "$ma" "$(median "${la[@]}")" "$(median "${pa[@]}")" \
    "$(awk -v a="$ma" -v b="$mb" 'BEGIN{printf "%.3f", b/a}')" | tee -a "$RESULT_FILE"
  printf '%-16s\t%s\t%s\t%s\t%s\n' "ngxrs/$path" "$mb" "$(median "${lb[@]}")" "$(median "${pb[@]}")" \
    "$(awk -v a="$ma" -v b="$mb" 'BEGIN{printf "%.3f", b/a}')" | tee -a "$RESULT_FILE"
}

for path in 1k.txt 64k.bin 1m.bin; do
  echo "== $path =="
  bench_pair "$path"
done

echo
echo "results written to $RESULT_FILE"
column -t -s $'\t' "$RESULT_FILE"
