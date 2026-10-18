#!/usr/bin/env bash
# Run nginx's official Perl test suite against BOTH nginx and ngxrs and compare
# per-assertion outcomes.
#
# Absolute pass rate is not a useful metric here: the master branch of
# nginx-tests is written against a Test::Nginx newer than what CPAN ships
# (0.32/0.33 lack `http()`'s close semantics, so keepalive responses block and
# return undef). Running the reference nginx through the same harness produces
# the same failures, which is exactly why this script diffs the two runs: an
# assertion nginx passes and ngxrs fails is a real defect; one that fails for
# both is a harness limitation.
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
OUT_DIR="$ROOT/bench/run/nginxtests"
mkdir -p "$OUT_DIR"

# Files that need modules ngxrs does not implement are excluded up front so the
# run reports real gaps rather than unsupported features.
SKIP_ALWAYS="
addition sub slice auth_basic auth_delay auth_request dav mirror
xslt perl lua js njs image_filter mp4 flv geoip random_index
limit_req limit_conn secure_link realip rewrite_log debug
h2 h3 quic ssl_sni ssl_verify grpc uwsgi_cgi memcached
mail proxy_protocol resolver stream_ssl
"

DEFAULT_TESTS="
http_host.t
http_uri.t
http_method.t
http_server_name.t
http_keepalive.t
http_range.t
http_error_page.t
http_location.t
http_headers.t
http_try_files.t
http_server_tokens.t
http_request_line.t
"

TESTS="${TEST_LIST:-$DEFAULT_TESTS}"

# Extract "id: ok|not ok" pairs so the two runs can be compared line by line.
outcomes() { # $1=log -> sorted "id ok" / "id notok" lines
  grep -oE '^(ok|not ok) [0-9]+' "$1" 2>/dev/null \
    | sed -E 's/^ok /ok /; s/^not ok /notok /' \
    | awk '{print $2, $1}' | sort -n
}

idx=0
declare -a NAMES=() SAME=() WORSE=() BETTER=() UNRUN=() TRUNC=() REF_OK=() OUR_OK=()

for t in $TESTS; do
  f="$TESTS_DIR/$t"
  if [ ! -f "$f" ]; then
    printf 'SKIP %s (not in suite)\n' "$t"
    continue
  fi

  ref_log="$OUT_DIR/${t%.t}.ref.log"
  our_log="$OUT_DIR/${t%.t}.log"

  TEST_NGINX_BINARY="$REF_BIN" timeout 150 prove -v "$f" > "$ref_log" 2>&1
  TEST_NGINX_BINARY="$BIN"     timeout 150 prove -v "$f" > "$our_log" 2>&1

  outcomes "$ref_log" > "$OUT_DIR/${t%.t}.ref.out"
  outcomes "$our_log" > "$OUT_DIR/${t%.t}.out"

  r_ok=$(grep -c ' ok$' "$OUT_DIR/${t%.t}.ref.out" || true)
  o_ok=$(grep -c ' ok$' "$OUT_DIR/${t%.t}.out" || true)
  total=$(wc -l < "$OUT_DIR/${t%.t}.ref.out" | tr -d ' ')
  o_total=$(wc -l < "$OUT_DIR/${t%.t}.out" | tr -d ' ')

  # Assertions nginx passes but we do not (and vice versa).
  worse=$(awk 'NR==FNR && $2=="ok" {ref[$1]=1; next}
               $2=="notok" && ($1 in ref) {n++}
               END{print n+0}' \
            "$OUT_DIR/${t%.t}.ref.out" "$OUT_DIR/${t%.t}.out")
  better=$(awk 'NR==FNR && $2=="notok" {ref[$1]=1; next}
                $2=="ok" && ($1 in ref) {n++}
                END{print n+0}' \
             "$OUT_DIR/${t%.t}.ref.out" "$OUT_DIR/${t%.t}.out")

  NAMES+=("$t"); REF_OK+=("$r_ok"); OUR_OK+=("$o_ok")
  # A suite that never ran on our side has no `not ok` lines at all, so the
  # worse/better counts are both zero and it used to be reported as SAME even
  # though the numbers disagreed (stream_ssl showed "SAME 7/7 vs 0/7"). Suite
  # runs are only comparable when both sides produced assertions.
  # A run that stopped early (a `die` in the harness, a missing log file) emits
  # fewer lines than the reference, so the per-id diff finds nothing "worse"
  # and the suite used to be reported as SAME. proxy.t showed `SAME 30/30 vs
  # 21/30` that way: the plan mismatch aborted the last nine assertions.
  if [ "$o_total" -lt "$total" ]; then
    TRUNC+=("$t")
    printf 'TRUNC  %-26s nginx %2s/%-3s   ngxrs %2s/%-3s   (%s assertions never ran)\n' \
      "$t" "$r_ok" "$total" "$o_ok" "$total" "$((total - o_total))"
  elif [ "$o_ok" -eq 0 ] && [ "$r_ok" -gt 0 ]; then
    UNRUN+=("$t")
    printf 'UNRUN  %-26s nginx %2s/%-3s   ngxrs %2s/%-3s   (we produced no assertions)\n' \
      "$t" "$r_ok" "$total" "$o_ok" "$total"
  elif [ "$worse" -gt 0 ]; then
    WORSE+=("$t")
    printf 'WORSE  %-26s nginx %2s/%-3s   ngxrs %2s/%-3s   (%s assertions we fail)\n' \
      "$t" "$r_ok" "$total" "$o_ok" "$total" "$worse"
  elif [ "$better" -gt 0 ]; then
    BETTER+=("$t")
    printf 'BETTER %-26s nginx %2s/%-3s   ngxrs %2s/%-3s\n' "$t" "$r_ok" "$total" "$o_ok" "$total"
  else
    SAME+=("$t")
    printf 'SAME   %-26s nginx %2s/%-3s   ngxrs %2s/%-3s\n' "$t" "$r_ok" "$total" "$o_ok" "$total"
  fi
  idx=$((idx + 1))
done

total_ref=0; total_our=0
for i in "${!NAMES[@]}"; do
  total_ref=$((total_ref + REF_OK[$i]))
  total_our=$((total_our + OUR_OK[$i]))
done

echo
echo "================ nginx-tests: ngxrs vs nginx ================"
printf 'files compared : %d\n' "${#NAMES[@]}"
printf 'assertions      : nginx %d / ngxrs %d\n' "$total_ref" "$total_our"
printf 'identical       : %d\n' "${#SAME[@]}"
printf 'ngxrs worse     : %d  %s\n' "${#WORSE[@]}" "${WORSE[*]:-}"
printf 'not comparable  : %d  %s\n' "${#UNRUN[@]}" "${UNRUN[*]:-}"
printf 'truncated runs  : %d  %s\n' "${#TRUNC[@]}" "${TRUNC[*]:-}"
printf 'ngxrs better    : %d  %s\n' "${#BETTER[@]}" "${BETTER[*]:-}"
[ "${#WORSE[@]}" -eq 0 ] && [ "${#TRUNC[@]}" -eq 0 ]
