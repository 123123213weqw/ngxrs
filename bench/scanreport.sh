#!/usr/bin/env bash
# Classify a finished ntscan run by *why* each file falls short.
#
# ntscan.sh answers "how many assertions does ngxrs lose", which is the right
# headline but a poor work list: a file that fails because our config parser
# rejected a directive needs a different fix from one that answers wrongly, and
# a run that died halfway (TRUNC) is not a behaviour difference at all -- it
# only looks like fewer assertions.
#
# It also re-derives the headline, because ntscan.sh counted a file where we
# emitted *no* assertions at all as SAME: its worse-count comes from failing
# assertion ids, and a run that never started has none to fail. On the
# 2026-10-27 scan that inflated `same` by 68 files carrying 988 assertions that
# nginx passed and we never attempted.
#
# Usage:
#   OUT=bench/run/ntscan bash bench/scanreport.sh
#
set -uo pipefail
DIR="$(dirname "$0")"
ROOT="$(cd "$DIR/.." && pwd)"
OUT="${OUT:-$ROOT/bench/run/ntscan}"
# Skip logs older than this file/explicit timestamp. A reused OUT directory
# keeps the previous run's logs, and a file the new run never reached would
# otherwise be reported with stale contents.
MIN_MTIME="${MIN_MTIME:-}"
ROWS="$(mktemp)"

[[ -d "$OUT" ]] || { echo "no scan output at $OUT" >&2; exit 2; }

nok()  { local n; n=$(grep -cE "^ok " "$1" 2>/dev/null); echo "${n:-0}"; }
nbad() { local n; n=$(grep -cE "^not ok " "$1" 2>/dev/null); echo "${n:-0}"; }

ids() {
  grep -oE '^(ok|not ok) [0-9]+' "$1" 2>/dev/null \
    | awk '{print $NF, ($1=="ok"?"ok":"notok")}' | sort -n
}

reason() { # $1 = our log -> "KIND|detail"
  if grep -qE 'unknown directive|invalid number of arguments|invalid parameter|is not allowed here|too many arguments' "$1" 2>/dev/null; then
    local d
    d=$(grep -ohE '(unknown directive|invalid parameter)[^,]*' "$1" 2>/dev/null | sort -u | head -2 | tr '\n' ' ')
    echo "CONFIG|$d"
  elif grep -qE "can't start|no listening|bind\(\) to|Address already in use|still could not bind" "$1" 2>/dev/null; then
    echo "STARTUP|"
  else
    echo "OTHER|"
  fi
}

declare -A sum
for k in BEHAVIOUR CONFIG CONFIG_NORUN STARTUP OTHER_NORUN TRUNC LOGINVALID; do sum[$k]=0; done
nsame=0; nbetter=0; nskip=0; nfiles=0

for our in "$OUT"/*.log; do
  base="$(basename "$our" .log)"
  ref="$OUT/$base.ref.log"
  [[ -f "$ref" ]] || continue
  case "$base" in *ref*) continue ;; esac

  if [[ -n "$MIN_MTIME" && "$our" -ot "$MIN_MTIME" ]]; then nskip=$((nskip + 1)); continue; fi

  r_ok=$(nok "$ref"); r_bad=$(nbad "$ref")
  o_ok=$(nok "$our"); o_bad=$(nbad "$our")
  r_tot=$((r_ok + r_bad)); o_tot=$((o_ok + o_bad))

  if [[ "$r_tot" -eq 0 && "$o_tot" -eq 0 ]]; then
    # Our side produced diagnostics but no TAP at all: the assertion lines were
    # lost, so the file cannot be judged either way.
    if [[ "$r_tot" -gt 0 ]] && grep -qE 'Failed test|Can.t start' "$our" 2>/dev/null; then
      sum[LOGINVALID]=$(( ${sum[LOGINVALID]:-0} + r_tot ))
      printf 'LOGINVALID   %-32s ref %3s  ours   0  (no TAP lines in our log)\n' "$base" "$r_tot" >>"$ROWS"
    else
      nskip=$((nskip + 1))
    fi
    continue
  fi
  nfiles=$((nfiles + 1))

  # The reference ran and we produced nothing at all: not "same", and not a
  # behaviour difference either -- usually a directive we reject.
  if [[ "$o_tot" -eq 0 ]]; then
    IFS='|' read -r kind detail <<<"$(reason "$our")"
    case "$kind" in
      CONFIG)  key=CONFIG_NORUN ;;
      STARTUP) key=STARTUP ;;
      *)       key=OTHER_NORUN ;;
    esac
    sum[$key]=$(( ${sum[$key]} + r_ok ))
    printf '%-12s %-32s ref %3s  ours   0  (-%s) %s\n' "$key" "$base" "$r_tot" "$r_ok" "$detail" >>"$ROWS"
    continue
  fi

  worse=$(awk 'NR==FNR && $2=="ok" {ref[$1]=1; next}
               $2=="notok" && ($1 in ref) {n++} END{print n+0}' \
            <(ids "$ref") <(ids "$our"))
  better=$(awk 'NR==FNR && $2=="notok" {ref[$1]=1; next}
                $2=="ok" && ($1 in ref) {n++} END{print n+0}' \
             <(ids "$ref") <(ids "$our"))

  if [[ "$o_tot" -lt "$r_tot" ]]; then
    sum[TRUNC]=$(( ${sum[TRUNC]} + worse ))
    printf 'TRUNC        %-32s ref %3s  ours %3s  (-%s)\n' "$base" "$r_tot" "$o_tot" "$worse" >>"$ROWS"
    continue
  fi

  if [[ "$worse" -eq 0 ]]; then
    if [[ "$better" -gt 0 ]]; then nbetter=$((nbetter + 1)); else nsame=$((nsame + 1)); fi
    continue
  fi

  IFS='|' read -r kind detail <<<"$(reason "$our")"
  case "$kind" in
    CONFIG)  key=CONFIG ;;
    STARTUP) key=STARTUP ;;
    *)       key=BEHAVIOUR; detail="" ;;
  esac
  sum[$key]=$(( ${sum[$key]} + worse ))
  printf '%-12s %-32s ref %3s  ours %3s  (-%s) %s\n' "$key" "$base" "$r_tot" "$o_tot" "$worse" "$detail" >>"$ROWS"
done

echo "=================== by root cause ==================="
printf 'BEHAVIOUR    %5d   ran to completion, answered wrongly\n' "${sum[BEHAVIOUR]}"
printf 'CONFIG       %5d   ran, but our parser rejected something (see rows)\n' "${sum[CONFIG]}"
printf 'CONFIG_NORUN %5d   parser rejected it, so nothing ran at all\n' "${sum[CONFIG_NORUN]}"
printf 'STARTUP      %5d   config parsed, listener never came up\n' "${sum[STARTUP]}"
printf 'OTHER_NORUN  %5d   nothing ran, not a directive problem\n' "${sum[OTHER_NORUN]}"
printf 'TRUNC        %5d   our run stopped early (short of the reference)\n' "${sum[TRUNC]}"
printf 'LOGINVALID   %5d   our log lost its TAP lines, cannot be judged\n' "${sum[LOGINVALID]:-0}"
echo "----------------------------------------------------"
total=0
for k in "${!sum[@]}"; do total=$((total + sum[$k])); done
printf 'assertions where nginx passes and we do not: %d\n' "$total"
printf 'files compared=%d same=%d better=%d skipped=%d\n' "$nfiles" "$nsame" "$nbetter" "$nskip"
echo
echo "worst files per bucket:"
for k in BEHAVIOUR CONFIG_NORUN CONFIG STARTUP OTHER_NORUN TRUNC LOGINVALID; do
  printf -- "--- %s\n" "$k"
  grep -E "^$k " "$ROWS" 2>/dev/null \
    | sed -E 's/.*\(-([0-9]+)\).*/\1 &/' | sort -rn | head -6 | cut -d' ' -f2- || true
done
rm -f "$ROWS"
