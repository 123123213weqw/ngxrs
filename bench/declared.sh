#!/usr/bin/env bash
# Run the declared conformance list and enforce the acceptance criterion:
# no assertion may pass on nginx while failing on ngxrs (WORSE = 0), and no run
# may be truncated on our side (TRUNC = 0). A suite that skips on both sides
# proves nothing, so it counts as a failure to declare it (SKIP = 0).
set -uo pipefail
DIR="$(dirname "$0")"

LIST="$(grep -vE '^[[:space:]]*(#|$)' "$DIR/declared.txt" | tr '\n' ' ')"
if [ -z "$LIST" ]; then
  echo "declared.txt is empty" >&2
  exit 2
fi
COUNT=$(grep -vcE '^[[:space:]]*(#|$)' "$DIR/declared.txt")
echo "declared list: $COUNT files"

TEST_LIST="$LIST" bash "$DIR/nginxtests.sh"
rc=$?

if [ "$rc" -ne 0 ]; then
  echo
  echo "DECLARED LIST FAILED: a suite is WORSE, TRUNC or UNRUN (see above)"
  exit 1
fi
echo
echo "DECLARED LIST PASSED: WORSE=0 TRUNC=0"
