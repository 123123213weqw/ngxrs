#!/usr/bin/env bash
# Scan many nginx-tests files in A/B mode and print only the ones where ngxrs
# does worse than nginx (i.e. real defects).
set -uo pipefail
source "$(dirname "$0")/lib.sh"

# nginx-tests checkout: `git clone https://github.com/nginx/nginx-tests`.
TESTS_DIR="${TESTS_DIR:-$HOME/nginx-tests}"
[[ -d "$TESTS_DIR" ]] || TESTS_DIR="$ROOT/../nginx-tests"
if [[ ! -d "$TESTS_DIR" ]]; then
  echo "TESTS_DIR not found; set it to your nginx-tests checkout" >&2
  exit 2
fi
REF_BIN="${REF_BIN:-$NGINX_BIN}"
BIN="$ROOT/target/release/ngxrs"
# Honour an `OUT=` from the environment: a plain assignment silently overwrote
# the previous run's results, which is how a baseline gets lost mid-comparison.
OUT="${OUT:-$ROOT/bench/run/ntscan}"
mkdir -p "$OUT"

LIMIT="${LIMIT:-40}"
# Default: every suite. The point of this scan is the *whole* remaining gap, so
# narrowing the pattern silently shrinks the headline.
PATTERN="${PATTERN:-*.t}"

# Suites the reference build cannot provide. Derived from
# `nginx-baseline/sbin/nginx -V` (see COMPAT.md); everything else -- dav, slice,
# secure_link, realip, auth_request, sub, stub_status, h2, ssl, grpc, mail,
# stream, resolver, proxy_protocol -- IS buildable there and therefore counts.
# An earlier version excluded dav/slice/secure_link/realip/h2/ssl/grpc/mail
# here as well, which hid whole families we implement and made the "what is
# left" list look shorter than it is.
OUT_OF_SCOPE="${OUT_OF_SCOPE:-addition auth_delay image_filter mp4 flv geoip random_index memcached perl lua js njs xslt mirror quic h3 http_v3 h3_ mp4_}"

# shellcheck disable=SC2086
files=$(cd "$TESTS_DIR" && ls $PATTERN 2>/dev/null \
  | grep -vE "^($(echo "$OUT_OF_SCOPE" | tr ' ' '|'))" \
  | head -n "$LIMIT")

outcomes() {
  grep -oE '^(ok|not ok) [0-9]+' "$1" 2>/dev/null \
    | awk '{print $NF, ($1=="ok"?"ok":"notok")}' | sort -n
}

worse_total=0; same=0; better=0; skipped=0; compared=0
better_total=0
worse_files=0
# Files where the reference served and we produced no assertion at all. These
# used to land in `same`: the worse-count is built from failing assertion ids,
# and a run that never started has none, so it looked identical to a pass.
unrun_files=0; unrun_lost=0
: > "$OUT/summary.txt"

for t in $files; do
  f="$TESTS_DIR/$t"
  ref="$OUT/${t%.t}.ref.log"
  our="$OUT/${t%.t}.log"
  TEST_NGINX_BINARY="$REF_BIN" timeout 90 prove -v "$f" > "$ref" 2>&1
  TEST_NGINX_BINARY="$BIN"     timeout 90 prove -v "$f" > "$our" 2>&1

  r_ok=$(grep -cE '^ok ' "$ref" || true); r_bad=$(grep -cE '^not ok ' "$ref" || true)
  o_ok=$(grep -cE '^ok ' "$our" || true); o_bad=$(grep -cE '^not ok ' "$our" || true)

  # Skip files neither server can run (missing modules in the reference too).
  if [ "$r_ok" -eq 0 ] && [ "$r_bad" -eq 0 ]; then
    skipped=$((skipped + 1))
    continue
  fi
  if [ "$o_ok" -eq 0 ] && [ "$o_bad" -eq 0 ]; then
    unrun_files=$((unrun_files + 1))
    unrun_lost=$((unrun_lost + r_ok))
    printf 'UNRUN  %-28s nginx %3s/%-3s  ngxrs never ran\n' \
      "$t" "$r_ok" "$((r_ok + r_bad))" | tee -a "$OUT/summary.txt"
    continue
  fi
  compared=$((compared + 1))

  outcomes "$ref" > "$OUT/${t%.t}.ref.out"
  outcomes "$our" > "$OUT/${t%.t}.out"
  worse=$(awk 'NR==FNR && $2=="ok" {ref[$1]=1; next}
               $2=="notok" && ($1 in ref) {n++} END{print n+0}' \
            "$OUT/${t%.t}.ref.out" "$OUT/${t%.t}.out")
  better=$(awk 'NR==FNR && $2=="notok" {ref[$1]=1; next}
                $2=="ok" && ($1 in ref) {n++} END{print n+0}' \
             "$OUT/${t%.t}.ref.out" "$OUT/${t%.t}.out")

  if [ "$worse" -gt 0 ]; then
    worse_total=$((worse_total + worse))
    worse_files=$((worse_files + 1))
    printf 'WORSE  %-28s nginx %3s/%-3s  ngxrs %3s/%-3s  (-%s)\n' \
      "$t" "$r_ok" "$((r_ok + r_bad))" "$o_ok" "$((o_ok + o_bad))" "$worse" \
      | tee -a "$OUT/summary.txt"
  elif [ "$better" -gt 0 ]; then
    better_total=$((better_total + 1))
    printf 'BETTER %-28s nginx %3s/%-3s  ngxrs %3s/%-3s\n' \
      "$t" "$r_ok" "$((r_ok + r_bad))" "$o_ok" "$((o_ok + o_bad))" | tee -a "$OUT/summary.txt"
  else
    same=$((same + 1))
    printf 'SAME   %-28s %3s/%-3s\n' "$t" "$o_ok" "$((o_ok + o_bad))" | tee -a "$OUT/summary.txt"
  fi
done

echo
printf 'files compared=%d same=%d better=%d worse=%d  (skipped=%d unrun=%d)\n' \
  "$compared" "$same" "$better_total" "$worse_files" "$skipped" "$unrun_files"
printf 'total assertions where ngxrs loses: %d\n' "$worse_total"
printf 'assertions the reference passed in files we never ran: %d\n' "$unrun_lost"
