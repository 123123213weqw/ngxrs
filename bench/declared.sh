#!/usr/bin/env bash
# Run the declared conformance list and enforce the acceptance criterion:
# no assertion may pass on nginx while failing on ngxrs (WORSE = 0), and no run
# may be truncated on our side (TRUNC = 0). A suite that skips on both sides
# proves nothing, so it counts as a failure to declare it (SKIP = 0).
#
# A failing suite is retried once by itself before the gate fails; see the
# comment above the retry block. STRICT=1 turns that off.
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

# A single run is not a reliable verdict.
#
# Measured: `proxy_cache_error.t` reported 2/3 in one full pass and 3/3 when run
# alone, with no source change in between -- it asserts on a one-second cache
# timing, so on a shared host it can lose a race. Treating that as a regression
# would make the gate useless (it would fail at random), and treating every
# failure as a flake would hide real defects. So: run the list, and re-run
# *only the suites that failed*, once, in isolation. A suite that passes the
# retry is reported as FLAKY and does not fail the gate; a suite that fails
# again is a deterministic failure and does.
#
# STRICT=1 disables the retry, for when a past flake has to be re-adjudicated.
RUN_LOG="$(mktemp)"
TEST_LIST="$LIST" bash "$DIR/nginxtests.sh" 2>&1 | tee "$RUN_LOG"
rc=${PIPESTATUS[0]}

if [ "$rc" -ne 0 ] && [ "${STRICT:-0}" != "1" ]; then
  # Verdict lines look like: "WORSE  name.t   nginx 3/3   ngxrs 2/3  (..)".
  RETRY="$(awk '$1=="WORSE"||$1=="TRUNC"||$1=="UNRUN" {print $2}' "$RUN_LOG" | tr '\n' ' ')"
  if [ -n "${RETRY// /}" ]; then
    echo
    echo "=== retrying ${RETRY} once, in isolation ==="
    RETRY_LOG="$(mktemp)"
    TEST_LIST="$RETRY" bash "$DIR/nginxtests.sh" 2>&1 | tee "$RETRY_LOG"
    rrc=${PIPESTATUS[0]}
    if [ "$rrc" -eq 0 ]; then
      echo
      echo "FLAKY (passed on retry, not a regression): $RETRY"
      echo "DECLARED LIST PASSED: WORSE=0 TRUNC=0 (with flakes re-run: $RETRY)"
      rm -f "$RUN_LOG" "$RETRY_LOG"
      exit 0
    fi
    echo
    echo "DECLARED LIST FAILED: still failing after a retry (deterministic)"
    awk '$1=="WORSE"||$1=="TRUNC"||$1=="UNRUN" {print}' "$RETRY_LOG" >&2
    rm -f "$RUN_LOG" "$RETRY_LOG"
    exit 1
  fi
fi

rm -f "$RUN_LOG"

if [ "$rc" -ne 0 ]; then
  echo
  echo "DECLARED LIST FAILED: a suite is WORSE, TRUNC or UNRUN (see above)"
  exit 1
fi
echo
echo "DECLARED LIST PASSED: WORSE=0 TRUNC=0"
