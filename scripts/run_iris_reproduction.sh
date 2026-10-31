#!/usr/bin/env bash
# Experiment wrapper executed INSIDE the tmux session (see start_iris_tmux.sh).
# Usage: scripts/run_iris_reproduction.sh <run_id> [--retry-failed]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$1"; shift || true
RUN_DIR="$ROOT/runs/$RUN_ID"
mkdir -p "$RUN_DIR/logs"
LOG="$RUN_DIR/logs/orchestrator.log"

# conda activation hooks reference unset variables, so nounset is disabled around them
set +u
# shellcheck disable=SC1091
source "$ROOT/tools/miniforge3/bin/activate" iris || { echo "[run] conda activation failed" | tee -a "$LOG"; echo 77 > "$RUN_DIR/exit_status"; exit 77; }
set -u
export IRIS_REPRO_DOTENV="$ROOT/.env"   # the key is read from this file at request time, never exported
export PYTHONUNBUFFERED=1
cd "$ROOT"

echo "[run] $(date -u +%FT%TZ) start run_id=$RUN_ID python=$(command -v python) args=$*" | tee -a "$LOG"
echo "{\"event\":\"wrapper_start\",\"ts\":\"$(date -u +%FT%TZ)\",\"host\":\"$(hostname)\"}" >> "$RUN_DIR/events.jsonl"
python iris_repro/harness/orchestrate.py --run-id "$RUN_ID" "$@" 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
echo "[run] $(date -u +%FT%TZ) orchestrator exit code $RC" | tee -a "$LOG"
echo "$RC" > "$RUN_DIR/exit_status"
echo "$(date -u +%FT%TZ) $RC" >> "$RUN_DIR/exit_status_history"
echo "{\"event\":\"wrapper_end\",\"ts\":\"$(date -u +%FT%TZ)\",\"exit_code\":$RC}" >> "$RUN_DIR/events.jsonl"
exit "$RC"
