#!/usr/bin/env bash
# ABBA benchmark that keeps the RAW wrk output for every sample, so the
# comparison can be audited rather than taken on trust.
#
#   CONNS=128 REPEAT=3 bash bench/abba_raw.sh
#   SENDFILE=off CONNS=128 REPEAT=3 bash bench/abba_raw.sh   # control
#
# Prints a per-scenario median table and writes every raw block to
# bench/results/raw-<stamp>.txt with the A/B label above each block.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

DUR="${DUR:-10}"; CONNS="${CONNS:-128}"; THREADS="${THREADS:-8}"; REPEAT="${REPEAT:-3}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$OUT/raw-$STAMP.txt"
mkdir -p "$OUT"

trap stop_pair EXIT
start_pair

{
  echo "# sendfile=${SENDFILE:-on} conns=$CONNS threads=$THREADS dur=${DUR}s repeat=$REPEAT"
  echo "# nginx :$PORT_NGINX   ngxrs :$PORT_NGXRS"
  echo "# commit ${NGXRS_COMMIT:-unknown}"
  echo "# command: CONNS=$CONNS REPEAT=$REPEAT SENDFILE=${SENDFILE:-on} bash bench/abba_raw.sh"
} >"$RAW"

# One wrk sample; echoes "rps avg p99" and appends the raw block to $RAW.
sample() { # $1=label $2=url $3=path
  local label="$1" url="$2" path="$3" out r l p bad
  out=$($WRK -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$url" 2>&1)
  { echo "===== $label $path ====="; echo "$out"; } >>"$RAW"
  r=$(echo "$out" | awk '{t=$0; sub(/^[ \t]+/,"",t); if (index(t,"Requests/sec:")==1) {print $2; exit}}')
  l=$(echo "$out" | awk '{t=$0; sub(/^[ \t]+/,"",t); if (index(t,"Latency")==1) {print $2; exit}}')
  p=$(echo "$out" | awk '{t=$0; sub(/^[ \t]+/,"",t); if (index(t,"99%")==1) {print $2; exit}}')
  bad=$(echo "$out" | awk '/Non-2xx/{print $4; exit}')
  if [ -n "${bad:-}" ] && [ "$bad" != "0" ]; then
    echo "ERROR: $url returned $bad non-2xx" >&2; exit 1
  fi
  if [ -z "${r:-}" ] || [ -z "${l:-}" ] || [ -z "${p:-}" ]; then
    echo "ERROR: unparsed wrk output for $url (rps='${r:-}' lat='${l:-}' p99='${p:-}')" >&2
    echo "$out" >&2; exit 1
  fi
  echo "$r $l $p"
}

to_us() { awk -v v="$1" 'BEGIN{
  if (v ~ /us$/) {sub(/us$/,"",v); print v+0}
  else if (v ~ /ms$/) {sub(/ms$/,"",v); print (v+0)*1000}
  else if (v ~ /s$/) {sub(/s$/,"",v); print (v+0)*1000000}
  else print v+0 }'; }
fmt_us() { awk -v v="$1" 'BEGIN{
  if (v>=1000000) printf "%.2fs", v/1000000; else if (v>=1000) printf "%.2fms", v/1000;
  else printf "%.0fus", v}'; }
med() { printf '%s\n' "$@" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
med_time() { local u=() v; for v in "$@"; do u+=("$(to_us "$v")"); done; u=("$(printf '%s\n' "${u[@]}" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')"); fmt_us "${u[0]}"; }

printf '%-14s %12s %10s %10s %8s\n' scenario nginx_rps ngxrs_rps ratio p99_a/p99_b
for path in 1k.txt 64k.bin 1m.bin; do
  ua="http://127.0.0.1:$PORT_NGINX/$path"; ub="http://127.0.0.1:$PORT_NGXRS/$path"
  # warm both, then A B B A per round
  $WRK -t"$THREADS" -c"$CONNS" -d3s "$ua" >/dev/null 2>&1 || true
  $WRK -t"$THREADS" -c"$CONNS" -d3s "$ub" >/dev/null 2>&1 || true
  ra=(); rb=(); pa=(); pb=(); n=0
  while [ "$n" -lt "$REPEAT" ]; do
    read -r r l p <<<"$(sample nginx "$ua" "$path")"; ra+=("$r"); pa+=("$p")
    read -r r l p <<<"$(sample ngxrs "$ub" "$path")"; rb+=("$r"); pb+=("$p")
    read -r r l p <<<"$(sample ngxrs "$ub" "$path")"; rb+=("$r"); pb+=("$p")
    read -r r l p <<<"$(sample nginx "$ua" "$path")"; ra+=("$r"); pa+=("$p")
    n=$((n+1))
  done
  ma=$(med "${ra[@]}"); mb=$(med "${rb[@]}")
  printf '%-14s %12s %10s %10.3f %s / %s\n' "$path" "$ma" "$mb" \
    "$(awk -v a="$ma" -v b="$mb" 'BEGIN{print b/a}')" "$(med_time "${pa[@]}")" "$(med_time "${pb[@]}")"
done
echo
echo "raw wrk output: $RAW"
