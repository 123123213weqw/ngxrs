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

TESTS_DIR="${TESTS_DIR:-/home/wzu/nginx-tests}"
REF_BIN="${REF_BIN:-/home/wzu/nginx-baseline/sbin/nginx}"
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
declare -a NAMES=() SAME=() WORSE=() BETTER=() REF_OK=() OUR_OK=()

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
  if [ "$worse" -gt 0 ]; then
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
printf 'ngxrs better    : %d  %s\n' "${#BETTER[@]}" "${BETTER[*]:-}"
[ "${#WORSE[@]}" -eq 0 ]
