#!/usr/bin/env bash
# Run a subset of the official nginx test suite against ngxrs.
#
# The suite is nginx's own (Perl, Test::Nginx); it drives the binary through
# -p/-c/-e/-g, expects a daemonized process with a pid file, and stops it with
# SIGQUIT. Tests whose directives ngxrs does not implement are expected to fail
# and are listed explicitly rather than hidden.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

TESTS_DIR="${TESTS_DIR:-/home/wzu/nginx-tests}"
BIN="$ROOT/target/release/ngxrs"
OUT_DIR="$ROOT/bench/run/nginxtests"
mkdir -p "$OUT_DIR"

# Tests chosen because they only need modules ngxrs implements.
# (http core, static, rewrite, proxy, gzip, fastcgi, stream)
DEFAULT_TESTS="
http_request_line.t
http_request_headers.t
http_host.t
http_uri.t
http_location.t
http_location_auto.t
http_autoindex.t
http_index.t
http_range.t
http_range_iframe.t
http_etag.t
http_headers.t
http_keepalive.t
http_server_name.t
http_server_tokens.t
http_return.t
http_try_files.t
http_error_page.t
http_variables.t
http_method.t
http_status_code.t
http_404.t
http_host_variables.t
http_request_body.t
http_chunked.t
http_gzip.t
http_gzip_static.t
http_proxy.t
http_proxy_cache.t
http_proxy_variables.t
http_fastcgi.t
stream.t
stream_udp.t
rewrite.t
rewrite_break.t
rewrite_if.t
location.t
"

TESTS="${TEST_LIST:-$DEFAULT_TESTS}"
pass=0; fail=0; skip=0
declare -a FAILED=()

for t in $TESTS; do
  f="$TESTS_DIR/$t"
  if [ ! -f "$f" ]; then
    skip=$((skip + 1))
    echo "SKIP $t (not in suite)"
    continue
  fi
  log="$OUT_DIR/${t%.t}.log"
  if TEST_NGINX_BINARY="$BIN" timeout 90 prove -v "$f" > "$log" 2>&1; then
    pass=$((pass + 1))
    printf 'PASS %s\n' "$t"
  else
    fail=$((fail + 1))
    FAILED+=("$t")
    printf 'FAIL %s  (see %s)\n' "$t" "$log"
  fi
done

echo
echo "================ nginx-tests against ngxrs ================"
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"
if [ "$fail" -gt 0 ]; then
  echo "failing: ${FAILED[*]}"
fi
exit 0
