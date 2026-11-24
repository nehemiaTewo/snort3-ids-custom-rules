#!/usr/bin/env bash
# Run Snort 3 against every capture in pcaps/ with both rule versions.
# Output: alerts/<version>/<capture>.txt  (alert_fast format)
#
# Usage:  ./scripts/run_tests.sh            (uses `snort` on PATH)
#         SNORT=/path/to/snort ./scripts/run_tests.sh
set -u
cd "$(dirname "$0")/.."

SNORT="${SNORT:-snort}"
CONF_V1="config/snort_eval.lua"; CONF_V2="config/snort_eval_v2.lua"

for VER in v1 v2; do
  if [ "$VER" = v1 ]; then RULES="rules/local_v1.rules"; CONF="$CONF_V1"; else RULES="rules/local.rules"; CONF="$CONF_V2"; fi
  mkdir -p "alerts/$VER"
  for P in pcaps/*; do
    case "$P" in *.pcap|*.cap|*.pcapng) ;; *) continue ;; esac
    NAME="$(basename "$P")"
    "$SNORT" -c "$CONF" -R "$RULES" -r "$P" -A alert_fast -q -k none \
      > "alerts/$VER/$NAME.txt" 2> "alerts/$VER/$NAME.err"
    N=$(grep -c '\[\*\*\]' "alerts/$VER/$NAME.txt")
    printf '%-4s %-40s %5s alerts\n' "$VER" "$NAME" "$N"
  done
done
