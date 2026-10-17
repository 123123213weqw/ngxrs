#!/usr/bin/env bash
# Start nginx + ngxrs with the same fastcgi/stream config and compare.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

make_fixtures
render() { sed -e "s|__ROOT__|$ROOT|g" -e "s/listen 19500/listen $1/" -e "s/listen 19510/listen $2/" -e "s/listen 19520 udp/listen $3 udp/" "$ROOT/bench/fcgi_stream.conf" > "$4"; }
render 19500 19510 19520 "$RUN/fcgi-nginx.conf"
render 19501 19511 19521 "$RUN/fcgi-ngxrs.conf"

cleanup() { set +e; [[ -n "${NP:-}" ]] && kill "$NP" 2>/dev/null; [[ -n "${RP:-}" ]] && kill "$RP" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

"$NGINX_BIN" -c "$RUN/fcgi-nginx.conf" -p "$NGINX_PREFIX" 2>"$RUN/fcgi-nginx.err" & NP=$!
"$ROOT/target/release/ngxrs" -c "$RUN/fcgi-ngxrs.conf" -p "$ROOT" >"$RUN/fcgi-ngxrs.out" 2>"$RUN/fcgi-ngxrs.err" & RP=$!
sleep 1.5

echo "--- ngxrs startup ---"; tail -4 "$RUN/fcgi-ngxrs.err"
echo "--- nginx startup ---"; tail -2 "$RUN/fcgi-nginx.err"

python3 "$ROOT/tests/fcgi_stream_parity.py"
