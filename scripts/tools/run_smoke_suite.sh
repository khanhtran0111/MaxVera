#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID=""
FAIL_AFTER=""
TEST_MODE=false
PORT="${MAXVERA_SMOKE_PORT:-18080}"

usage() {
  echo "Usage: $0 --run-id RUN_ID [--fail-after setup|analysis|evaluation] [--test-mode]" >&2
}

while (($#)); do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --fail-after)
      FAIL_AFTER="${2:-}"
      shift 2
      ;;
    --test-mode)
      TEST_MODE=true
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "ERROR: unsafe or empty smoke run ID." >&2
  exit 2
fi
if [[ -n "$FAIL_AFTER" && "$FAIL_AFTER" != "setup" && "$FAIL_AFTER" != "analysis" \
  && "$FAIL_AFTER" != "evaluation" ]]; then
  echo "ERROR: unsupported failure-injection stage: $FAIL_AFTER" >&2
  exit 2
fi

cd "$ROOT_DIR"
bash scripts/tools/assert_no_smoke_artifacts.sh

RESULT_DIR="$ROOT_DIR/results/smoke/$RUN_ID"
INTERIM_DIR="$ROOT_DIR/data/interim/smoke/$RUN_ID"
CACHE_DIR="$ROOT_DIR/.cache/experiments/smoke/$RUN_ID"
LOG_DIR="$ROOT_DIR/logs/smoke/$RUN_ID"

cleanup_on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if ! bash scripts/tools/cleanup_smoke.sh --run-id "$RUN_ID" --strict; then
    exit 1
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

mkdir -p "$RESULT_DIR" "$INTERIM_DIR" "$CACHE_DIR" "$LOG_DIR"
printf '{"schema_version":1,"mode":"smoke","run_id":"%s"}\n' "$RUN_ID" \
  > "$RESULT_DIR/manifest.json"
printf '%s\n' "$RUN_ID" > "$CACHE_DIR/run-id"

if [[ "$FAIL_AFTER" == "setup" ]]; then
  echo "Injected smoke failure after setup." >&2
  exit 97
fi

if [[ "$TEST_MODE" == true ]]; then
  printf '{"technical_pass":true}\n' > "$RESULT_DIR/test-mode.json"
  echo "Smoke test-mode path passed; cleanup gate will run now."
  exit 0
fi

bash scripts/tools/preflight.sh --profile full > "$LOG_DIR/preflight.log"

readarray -t PHASE3_PATHS < <(
  uv run --frozen python - <<'PY'
from pathlib import Path
from src.common.envfile import effective_env
values = effective_env(Path(".env"))
print(values.get("MAXVERA_LLAMA_SERVER_BIN", ""))
print(values.get("MAXVERA_MODEL_PATH", ""))
PY
)
LLAMA_SERVER_BIN="${PHASE3_PATHS[0]:-}"
MODEL_PATH="${PHASE3_PATHS[1]:-}"
if [[ ! -x "$LLAMA_SERVER_BIN" || ! -f "$MODEL_PATH" ]]; then
  echo "ERROR: llama-server or Qwen model is not configured." >&2
  exit 1
fi

uv run --frozen python - "$PORT" <<'PY'
import socket
import sys
port = int(sys.argv[1])
with socket.socket() as probe:
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    probe.bind(("127.0.0.1", port))
PY

"$LLAMA_SERVER_BIN" \
  --model "$MODEL_PATH" \
  --alias qwen-smoke \
  --host 127.0.0.1 \
  --port "$PORT" \
  --ctx-size 8192 \
  --n-predict 256 \
  --temp 0 \
  --seed 1234 \
  --threads 6 \
  --threads-batch 8 \
  --n-gpu-layers 0 \
  > "$LOG_DIR/llama-server.log" 2>&1 &
SERVER_PID=$!
printf '%s\n' "$SERVER_PID" > "$INTERIM_DIR/llama-server.pid"

uv run --frozen python -m src.smoke.harness analyze \
  --repo-root "$ROOT_DIR" \
  --run-id "$RUN_ID" \
  --result-dir "$RESULT_DIR" \
  --log-dir "$LOG_DIR" \
  --endpoint "http://127.0.0.1:$PORT"

if [[ "$FAIL_AFTER" == "analysis" ]]; then
  echo "Injected smoke failure after analysis." >&2
  exit 98
fi

# Evaluator-only data is first opened in this separate process, after analysis.
MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m src.smoke.harness evaluate \
  --repo-root "$ROOT_DIR" \
  --result-dir "$RESULT_DIR"

if [[ "$FAIL_AFTER" == "evaluation" ]]; then
  echo "Injected smoke failure after evaluation." >&2
  exit 99
fi

uv run --frozen python -m src.smoke.harness validate \
  --repo-root "$ROOT_DIR" \
  --result-dir "$RESULT_DIR"

echo "Phase 3 smoke validated; cleanup gate will run now."
