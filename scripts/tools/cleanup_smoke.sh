#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID=""
STRICT=false

usage() {
  echo "Usage: $0 --run-id RUN_ID [--strict]" >&2
}

while (($#)); do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --strict)
      STRICT=true
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

RESULT_DIR="$ROOT_DIR/results/smoke/$RUN_ID"
INTERIM_DIR="$ROOT_DIR/data/interim/smoke/$RUN_ID"
CACHE_DIR="$ROOT_DIR/.cache/experiments/smoke/$RUN_ID"
LOG_DIR="$ROOT_DIR/logs/smoke/$RUN_ID"

validate_target() {
  local candidate="$1"
  local resolved
  resolved="$(realpath -m -- "$candidate")"
  if [[ "$resolved" != */smoke/"$RUN_ID" ]]; then
    echo "ERROR: cleanup target escaped the smoke allowlist: $resolved" >&2
    return 1
  fi
}

for target in "$RESULT_DIR" "$INTERIM_DIR" "$CACHE_DIR" "$LOG_DIR"; do
  validate_target "$target"
done

PID_FILE="$INTERIM_DIR/llama-server.pid"
if [[ -f "$PID_FILE" ]]; then
  SERVER_PID="$(tr -d '[:space:]' < "$PID_FILE")"
  if [[ "$SERVER_PID" =~ ^[0-9]+$ ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    COMMAND_LINE="$(tr '\0' ' ' < "/proc/$SERVER_PID/cmdline" 2>/dev/null || true)"
    if [[ "$COMMAND_LINE" != *llama-server* ]]; then
      echo "ERROR: refusing to signal non-llama process $SERVER_PID." >&2
      exit 1
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    for _attempt in {1..50}; do
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
  fi
fi

for target in "$RESULT_DIR" "$INTERIM_DIR" "$CACHE_DIR" "$LOG_DIR"; do
  if [[ -e "$target" ]]; then
    rm -rf -- "$target"
  fi
done

if [[ "$STRICT" == true ]]; then
  exec bash "$ROOT_DIR/scripts/tools/assert_no_smoke_artifacts.sh" --run-id "$RUN_ID"
fi

echo "Smoke artifacts removed for run: $RUN_ID"
