#!/usr/bin/env bash
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "Usage: oom_disposable <command> [args...]"
  exit 1
fi

SLICE_NAME=oomdisposable.slice
UNIT_NAME="oomjob-$$-$(date +%s%N)"

# Use --wait (to block), but not --pty (so signals and stdout/stderr work)
exec systemd-run --user \
  --unit="$UNIT_NAME" \
  --slice="$SLICE_NAME" \
  --working-directory="$(pwd)" \
  -p OOMPolicy=kill \
  -p CPUWeight=1 \
  -p IOWeight=1 \
  -p ManagedOOMMemoryPressure=kill \
  --wait \
  --collect \
  --quiet \
  "$@"
