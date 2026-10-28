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
echo "declared.txt: $(cd "$DIR" && pwd)/declared.txt"

# Self-check. Two mistakes have silently produced a green run from a stale list:
#
#   * `rsync -az bench/declared.txt host:~/ngxrs/` drops the file at
#     `~/ngxrs/declared.txt`, leaving the real list untouched, so the run
#     measures the previous contents and still prints PASS;
#   * a name that no longer exists in the nginx-tests checkout makes the harness
#     skip the file, and a skip is not a pass.
#
# Printing the resolved path plus checking every name against
# `$TESTS_DIR` turns both into a hard failure instead of a silent one.
TESTS_DIR="${TESTS_DIR:-$HOME/nginx-tests}"
[[ -d "$TESTS_DIR" ]] || TESTS_DIR="$DIR/../nginx-tests"
missing=0
while IFS= read -r f; do
  case "$f" in ""|"#"*) continue ;; esac
  if [[ ! -f "$TESTS_DIR/$f" ]]; then
    echo "MISSING from $TESTS_DIR: $f" >&2
    missing=$((missing + 1))
  fi
done < "$DIR/declared.txt"
if [ "$missing" -ne 0 ]; then
  echo "declared.txt names $missing file(s) the test checkout does not have" >&2
  exit 2
fi

TEST_LIST="$LIST" bash "$DIR/nginxtests.sh"
rc=$?

if [ "$rc" -ne 0 ]; then
  echo
  echo "DECLARED LIST FAILED: a suite is WORSE, TRUNC or UNRUN (see above)"
  exit 1
fi
echo
echo "DECLARED LIST PASSED: WORSE=0 TRUNC=0"
