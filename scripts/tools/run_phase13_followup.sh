#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
export MAXVERA_DATA_ROLE=evaluator
export PYTHONUNBUFFERED=1
run_id="${1:-p13_test_analysis_001}"
mkdir -p logs .cache
exec 9>.cache/phase13_followup.lock
if ! flock -n 9; then
  printf '%s\n' 'Another Phase 13 follow-up is already running.' >&2
  exit 1
fi
log_path="logs/${run_id}_followup_$(date -u +%Y%m%d_%H%M%S).log"
set +e
uv run --frozen python -m src.experiments.phase13_followup \
  --repo-root "$repo_root" --run-id "$run_id" 2>&1 | tee "$log_path"
exit_code="${PIPESTATUS[0]}"
set -e
printf '%s\n' "$exit_code" > "${log_path}.exit"
exit "$exit_code"
