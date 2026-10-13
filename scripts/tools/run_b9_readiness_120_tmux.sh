#!/usr/bin/env bash
# Durable, local-only maintenance. This script never starts paid synthesis.
set -Eeuo pipefail
readiness_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$readiness_root"

if [[ ${1:-} != --worker ]]; then
  readiness_name="${1:-b9_full_pipeline_readiness_$(date -u +%Y%m%dT%H%M%SZ)}"
  if [[ ! "$readiness_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    printf 'Output name must contain only letters, numbers, underscores or hyphens.\n' >&2
    exit 2
  fi
  if [[ -e "results/diagnostics/$readiness_name" ]]; then
    printf 'Output already exists: %s\n' "$readiness_name" >&2
    exit 2
  fi
  printf -v readiness_command 'cd %q && bash scripts/tools/run_b9_readiness_120_tmux.sh --worker %q' \
    "$readiness_root" "$readiness_name"
  if [[ ${2:-} == --inputs-only ]]; then
    readiness_command+=' --inputs-only'
  fi
  if tmux has-session -t maxvera-b9-readiness-120 2>/dev/null; then
    readiness_window="$(tmux new-window -P -F '#{window_id}' \
      -t maxvera-b9-readiness-120 -n repair "$readiness_command")"
  else
    readiness_window="$(tmux new-session -d -P -F '#{window_id}' \
      -s maxvera-b9-readiness-120 -n repair "$readiness_command")"
  fi
  tmux set-option -w -t "$readiness_window" remain-on-exit on
  printf 'Started maintenance: tmux attach -t maxvera-b9-readiness-120\n'
  exit 0
fi

readiness_name="$2"
readiness_output="results/diagnostics/$readiness_name"
mkdir -p "$readiness_output"
readiness_started="$(date -u +%FT%TZ)"
readiness_exit=0
readiness_state=RUNNING
finish_readiness() {
  readiness_exit=$?
  printf '{"status":"%s","exit_code":%s,"started_at":"%s","finished_at":"%s"}\n' \
    "$readiness_state" "$readiness_exit" "$readiness_started" "$(date -u +%FT%TZ)" \
    > "$readiness_output/launcher_status.json.tmp"
  mv "$readiness_output/launcher_status.json.tmp" "$readiness_output/launcher_status.json"
  printf 'Maintenance exit code: %s; status: %s\n' "$readiness_exit" "$readiness_state"
}
trap finish_readiness EXIT
printf '{"status":"RUNNING","pid":%s,"started_at":"%s"}\n' \
  "$$" "$readiness_started" > "$readiness_output/launcher_status.json"
set +e
MAXVERA_DATA_ROLE=evaluator PYTHONUNBUFFERED=1 uv run --frozen python -m src.pipeline_v2.readiness \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --output "$readiness_output" --repair --workers 2 \
  2>&1 | tee "$readiness_output/progress.log"
readiness_repair_exit=${PIPESTATUS[0]}
printf 'Repair process exit code: %s\n' "$readiness_repair_exit"
# Always inspect the entire population after a normal PASS/BLOCKED return.
# Exceptions or signals leave evidence and require diagnosis before continuing.
readiness_lifecycle="$(uv run --frozen python -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["status"])' \
  "$readiness_output/lifecycle.json" 2>/dev/null)"
if [[ "$readiness_lifecycle" != PASS && "$readiness_lifecycle" != BLOCKED ]]; then
  readiness_state=FAILED
  if [[ "$readiness_lifecycle" == INTERRUPTED ]]; then
    readiness_state=INTERRUPTED
  fi
  if [[ "$readiness_repair_exit" -eq 0 ]]; then
    readiness_repair_exit=1
  fi
  exit "$readiness_repair_exit"
fi
MAXVERA_DATA_ROLE=evaluator PYTHONUNBUFFERED=1 uv run --frozen python -m src.pipeline_v2.readiness \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --output "${readiness_output}_final" --workers 2 \
  2>&1 | tee "$readiness_output/final_scan.log"
readiness_scan_exit=${PIPESTATUS[0]}
if [[ "$readiness_scan_exit" -ne 0 ]]; then
  readiness_state=BLOCKED
  printf 'Input readiness remains BLOCKED; no LLM calls were made.\n'
  exit "$readiness_scan_exit"
fi
readiness_state=INPUTS_READY
if [[ ${3:-} == --inputs-only ]]; then
  printf 'All 120 inputs passed; input-only maintenance complete. No LLM calls.\n'
  exit 0
fi
printf 'All inputs passed. Starting no-API pipeline validation.\n'
uv run --frozen python -m src.pipeline_v2.benchmark \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --run-id "${readiness_name}_validate" --validate-only \
  2>&1 | tee "$readiness_output/validation.log"
readiness_validation_exit=${PIPESTATUS[0]}
if [[ "$readiness_validation_exit" -ne 0 ]]; then
  readiness_state=VALIDATION_FAILED
  exit "$readiness_validation_exit"
fi
readiness_state=NO_API_VALIDATION_PASSED
