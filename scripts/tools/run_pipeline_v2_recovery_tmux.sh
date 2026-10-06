#!/usr/bin/env bash
set -Eeuo pipefail

pipeline_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
pipeline_session="maxvera-pipeline-v2-recovery"

if tmux has-session -t "$pipeline_session" 2>/dev/null; then
  printf 'Session already exists. Attach with: tmux attach -t %s\n' "$pipeline_session"
  exit 0
fi

cd "$pipeline_root"
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf 'A full run requires a clean, committed implementation snapshot.\n' >&2
  exit 1
fi
if [[ -d results/pipeline_v2/dev_restart_v2_002 ]]; then
  printf 'The immutable controller has already completed. Review its STATUS and lock.\n' >&2
  exit 1
fi

pipeline_resume=()
if [[ -d results/pipeline_v2/.dev_restart_v2_002.inprogress ]]; then
  pipeline_resume=(--resume)
fi
mkdir -p logs/pipeline_v2
printf -v pipeline_command 'cd %q && uv run --frozen python -m src.pipeline_v2 auto --config configs/experiments/pipeline_v2_recovery.yaml --confirm-api-spend' "$pipeline_root"
if [[ ${#pipeline_resume[@]} -gt 0 ]]; then
  pipeline_command+=' --resume'
fi
pipeline_command+=' >> logs/pipeline_v2/development_recovery_002.log 2>&1; pipeline_exit=$?; printf "Controller exit code: %s\n" "$pipeline_exit"; exec bash'
tmux new-session -d -s "$pipeline_session" "$pipeline_command"
printf 'Started. Attach: tmux attach -t %s\nLog: %s/logs/pipeline_v2/development_recovery_002.log\n' "$pipeline_session" "$pipeline_root"
