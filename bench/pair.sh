#!/usr/bin/env bash
# Differential parity check between nginx and ngxrs on the same tree.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

DUR="${DUR:-10}"
CONNS="${CONNS:-512}"
THREADS="${THREADS:-8}"
REPEAT="${REPEAT:-3}"

trap stop_pair EXIT
start_pair

echo "parity: nginx :$PORT_NGINX  vs  ngxrs :$PORT_NGXRS"
python3 "$ROOT/tests/parity.py" --nginx "$PORT_NGINX" --ngxrs "$PORT_NGXRS" --www "$WWW"
