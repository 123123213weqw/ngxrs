#!/usr/bin/env bash
# A/B compare nginx vs ngxrs for one path, alternating, no client-side latency
# recording (so both sides see the same wrk overhead), 3 rounds, medians.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

T="${T:-24}"
CONNS_LIST="${CONNS_LIST:-512 1024}"
D="${D:-6}"
ROUNDS="${ROUNDS:-3}"

make_fixtures
WORKER_PROCESSES="${WORKER_PROCESSES:-auto}" start_pair
trap stop_pair EXIT

med() { printf '%s\n' "$@" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
rps() {
  local out bad r
  out=$($WRK -t"$T" -c"$1" -d"${D}s" "$2" 2>&1)
  bad=$(echo "$out" | awk '/Non-2xx/{print $4; exit}')
  if [ -n "${bad:-}" ] && [ "$bad" != "0" ]; then
    echo "ERROR: $2 returned $bad non-2xx responses (fd limit too low?)" >&2
    exit 1
  fi
  echo "$out" | awk '/Requests\/sec/{print $2; exit}'
}

printf '%-8s %-10s %-11s %-11s %s\n' conns accept nginx ngxrs ratio
for c in $CONNS_LIST; do
  na=(); nb=()
  for _ in $(seq 1 "$ROUNDS"); do
    na+=("$(rps "$c" "http://127.0.0.1:$PORT_NGINX/1k.txt")")
    nb+=("$(rps "$c" "http://127.0.0.1:$PORT_NGXRS/1k.txt")")
    nb+=("$(rps "$c" "http://127.0.0.1:$PORT_NGXRS/1k.txt")")
    na+=("$(rps "$c" "http://127.0.0.1:$PORT_NGINX/1k.txt")")
  done
  ma=$(med "${na[@]}"); mb=$(med "${nb[@]}")
  awk -v c="$c" -v a="$ma" -v b="$mb" -v m="${NGXRS_ACCEPT:-reuseport}" \
    'BEGIN{printf "%-8s %-10s %-11.0f %-11.0f %.3f\n", c, m, a, b, b/a}'
done
