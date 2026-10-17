#!/usr/bin/env bash
# Run every parity suite and print a summary. Exit non-zero if any fails.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

ulimit -n 65536 2>/dev/null || true
declare -a NAMES=() RESULTS=()
fail=0

run() { # $1=name $2=script
  echo
  echo "################ $1 ################"
  local out rc
  out=$(bash "$2" 2>&1)
  rc=$?
  echo "$out" | tail -4
  local line
  line=$(echo "$out" | grep -E "^[0-9]+/[0-9]+ cases match" | tail -1)
  NAMES+=("$1")
  if [ $rc -eq 0 ]; then
    RESULTS+=("PASS ${line:-ok}")
  else
    RESULTS+=("FAIL ${line:-error}")
    fail=1
  fi
}

run "static-protocol" "$ROOT/bench/pair.sh"
run "features(gzip/proxy/rewrite/cache)" "$ROOT/bench/feature.sh"
run "tls+sni+http2" "$ROOT/bench/tls.sh"
run "fastcgi+stream" "$ROOT/bench/fcgi.sh"

echo
echo "================ summary ================"
for i in "${!NAMES[@]}"; do
  printf '%-34s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}"
done
exit $fail
