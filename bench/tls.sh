#!/usr/bin/env bash
# Start nginx and ngxrs with the same TLS config (different ports) and compare.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

PORT_NGINX_TLS=19443
PORT_NGXRS_TLS=19444

make_fixtures
# Certificates must exist before either server starts.
python3 - "$ROOT" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "tests"))
import tls_parity
tls_parity.ensure_certs()
PY

render() { # $1=port $2=out $3=backend port
  sed -e "s|__ROOT__|$ROOT|g" -e "s|__WORKERS__|${WORKER_PROCESSES:-auto}|" \
      -e "s/listen 19443/listen $1/" \
      -e "s/listen 19450/listen $3/" \
      -e "s|127.0.0.1:19450|127.0.0.1:$3|" "$ROOT/bench/tls.conf" > "$2"
}
render "$PORT_NGINX_TLS" "$RUN/tls-nginx.conf" 19450
render "$PORT_NGXRS_TLS" "$RUN/tls-ngxrs.conf" 19451

cleanup() {
  set +e
  [[ -n "${NPID:-}" ]] && kill "$NPID" 2>/dev/null
  [[ -n "${RPID:-}" ]] && kill "$RPID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

"$NGINX_BIN" -c "$RUN/tls-nginx.conf" -p "$NGINX_PREFIX" 2>"$RUN/tls-nginx.err" &
NPID=$!
"$ROOT/target/release/ngxrs" -c "$RUN/tls-ngxrs.conf" -p "$ROOT" \
  >"$RUN/tls-ngxrs.out" 2>"$RUN/tls-ngxrs.err" &
RPID=$!
sleep 1.2

echo "--- ngxrs startup ---"
tail -3 "$RUN/tls-ngxrs.err" 2>/dev/null
echo "--- nginx startup ---"
tail -3 "$RUN/tls-nginx.err" 2>/dev/null

python3 "$ROOT/tests/tls_parity.py" --nginx "$PORT_NGINX_TLS" --ngxrs "$PORT_NGXRS_TLS"
