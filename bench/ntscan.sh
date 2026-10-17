#!/usr/bin/env bash
# Scan many nginx-tests files in A/B mode and print only the ones where ngxrs
# does worse than nginx (i.e. real defects).
set -uo pipefail
source "$(dirname "$0")/lib.sh"

TESTS_DIR="${TESTS_DIR:-/home/wzu/nginx-tests}"
REF_BIN="${REF_BIN:-/home/wzu/nginx-baseline/sbin/nginx}"
BIN="$ROOT/target/release/ngxrs"
OUT="$ROOT/bench/run/ntscan"
mkdir -p "$OUT"

LIMIT="${LIMIT:-40}"
# Categories ngxrs actually implements.
PATTERN="${PATTERN:-http_*.t proxy_*.t upstream_*.t range_*.t fastcgi_*.t scgi_*.t uwsgi_*.t stream*.t}"

# shellcheck disable=SC2086
files=$(cd "$TESTS_DIR" && ls $PATTERN 2>/dev/null \
  | grep -vE '^(addition|sub|slice|auth_|dav|mirror|xslt|perl|lua|js|njs|image_filter|mp4|flv|geoip|random_index|limit_|secure_link|realip|rewrite_log|debug|h2|h3|quic|ssl|grpc|memcached|mail|proxy_protocol|resolver)' \
  | head -n "$LIMIT")

outcomes() {
  grep -oE '^(ok|not ok) [0-9]+' "$1" 2>/dev/null \
    | awk '{print $NF, ($1=="ok"?"ok":"notok")}' | sort -n
}

worse_total=0; same=0; better=0; skipped=0; compared=0
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
    printf 'WORSE  %-28s nginx %3s/%-3s  ngxrs %3s/%-3s  (-%s)\n' \
      "$t" "$r_ok" "$((r_ok + r_bad))" "$o_ok" "$((o_ok + o_bad))" "$worse" \
      | tee -a "$OUT/summary.txt"
  elif [ "$better" -gt 0 ]; then
    better=$((better + 1))
    printf 'BETTER %-28s nginx %3s/%-3s  ngxrs %3s/%-3s\n' \
      "$t" "$r_ok" "$((r_ok + r_bad))" "$o_ok" "$((o_ok + o_bad))" | tee -a "$OUT/summary.txt"
  else
    same=$((same + 1))
    printf 'SAME   %-28s %3s/%-3s\n' "$t" "$o_ok" "$((o_ok + o_bad))" | tee -a "$OUT/summary.txt"
  fi
done

echo
printf 'files compared=%d same=%d better=%d  (skipped=%d)\n' \
  "$compared" "$same" "$better" "$skipped"
printf 'total assertions where ngxrs loses: %d\n' "$worse_total"
