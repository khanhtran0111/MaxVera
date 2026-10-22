#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail
pipeline_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
pipeline_session="maxvera-b9-v2"
if tmux has-session -t "$pipeline_session" 2>/dev/null; then
  printf 'Session exists; inspect its controller before resuming: tmux attach -t %s\n' "$pipeline_session"
  exit 1
fi
cd "$pipeline_root"
if [[ $# -eq 0 ]]; then
  printf 'Usage: bash scripts/tools/run_b9_v2_tmux.sh --mode pilot|full --run-id ID [--resume] --confirm-api-spend\n' >&2
  exit 2
fi
mkdir -p logs/pipeline_v2
printf -v pipeline_command 'cd %q && bash scripts/10_run_b9_full_useg.sh --pipeline-v2' "$pipeline_root"
for pipeline_argument in "$@"; do
  printf -v pipeline_quoted ' %q' "$pipeline_argument"
  pipeline_command+="$pipeline_quoted"
done
pipeline_command+=' >> logs/pipeline_v2/b9_end_to_end.log 2>&1; pipeline_exit=$?; printf "Controller exit code: %s\n" "$pipeline_exit"; exec bash'
tmux new-session -d -s "$pipeline_session" "$pipeline_command"
printf 'Started: tmux attach -t %s\nLog: logs/pipeline_v2/b9_end_to_end.log\n' "$pipeline_session"
