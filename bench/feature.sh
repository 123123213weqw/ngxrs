#!/usr/bin/env bash
# Start nginx and ngxrs with the same feature config and run the parity tests.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

PORT_NGINX_FEATURE=19300
PORT_NGXRS_FEATURE=19301

make_fixtures

# both servers get the identical config file, only `listen` differs
render() { # $1=port $2=out
  sed -e "s|__ROOT__|$ROOT|g" -e "s/listen 19300/listen $1/" "$ROOT/bench/feature.conf" > "$2"
}
render "$PORT_NGINX_FEATURE" "$RUN/feature-nginx.conf"
render "$PORT_NGXRS_FEATURE" "$RUN/feature-ngxrs.conf"

cleanup() {
  set +e
  [[ -n "${NPID:-}" ]] && kill "$NPID" 2>/dev/null
  [[ -n "${RPID:-}" ]] && kill "$RPID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

"$NGINX_BIN" -c "$RUN/feature-nginx.conf" -p "$NGINX_PREFIX" &
NPID=$!
"$ROOT/target/release/ngxrs" -c "$RUN/feature-ngxrs.conf" -p "$ROOT" \
  >"$RUN/feature-ngxrs.stdout" 2>"$RUN/feature-ngxrs.stderr" &
RPID=$!

for _ in $(seq 1 100); do
  if curl -fsS -m 1 "http://127.0.0.1:$PORT_NGXRS_FEATURE/gzip/data.json" -o /dev/null 2>/dev/null; then break; fi
  sleep 0.1
done

echo "--- ngxrs startup ---"
tail -3 "$RUN/feature-ngxrs.stderr" || true

python3 "$ROOT/tests/feature_parity.py" \
  --nginx "$PORT_NGINX_FEATURE" --ngxrs "$PORT_NGXRS_FEATURE"
