#!/usr/bin/env bash
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "Usage: oom_disposable <command> [args...]"
  exit 1
fi

# Cgroup v2 root
CGROUP_ROOT="/sys/fs/cgroup/user.slice/user-$(id -u).slice"
CGROUP_NAME="oomdisposable-$$"
CGROUP_PATH="${CGROUP_ROOT}/${CGROUP_NAME}"

# Create the cgroup
mkdir -p "$CGROUP_PATH"

# Move this process into it
echo $$ > "$CGROUP_PATH/cgroup.procs"

# Deprioritize CPU and IO (ignore errors if unsupported)
echo 1 > "$CGROUP_PATH/cpu.weight" 2>/dev/null || true
echo 1 > "$CGROUP_PATH/io.weight" 2>/dev/null || true

# Run the command
exec "$@" &

child_pid=$!
wait $child_pid
exit_code=$?

# Clean up the cgroup if no more procs are inside
if [ ! "$(ls -A "$CGROUP_PATH"/cgroup.procs)" ]; then
  rmdir "$CGROUP_PATH" 2>/dev/null || true
fi

exit "$exit_code"
