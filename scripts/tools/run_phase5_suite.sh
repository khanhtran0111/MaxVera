#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

MODE="pilot"
RUN_PREFIX=""
LIMIT="1"
CONFIRM="false"
BUDGET_MODE="budget_matched"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --run-prefix) RUN_PREFIX="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --budget-mode) BUDGET_MODE="$2"; shift 2 ;;
    --confirm-api-spend) CONFIRM="true"; shift ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ -z "$RUN_PREFIX" ]]; then
  echo "ERROR: --run-prefix is required." >&2
  exit 64
fi
if [[ "$CONFIRM" != "true" ]]; then
  echo "ERROR: --confirm-api-spend is required for the B3/B4 suite." >&2
  exit 64
fi

COMMON=(--mode "$MODE" --budget-mode "$BUDGET_MODE" --confirm-api-spend)
if [[ "$MODE" != "full" ]]; then
  COMMON+=(--limit "$LIMIT")
fi

bash scripts/04_run_b3_raw_context_gptoss20b.sh \
  "${COMMON[@]}" --run-id "${RUN_PREFIX}_b3"
bash scripts/05_run_b4_text_rag_gptoss20b.sh \
  "${COMMON[@]}" --run-id "${RUN_PREFIX}_b4"
B5_ARGS=(--mode "$MODE" --budget-mode "$BUDGET_MODE")
if [[ "$MODE" != "full" ]]; then
  B5_ARGS+=(--limit "$LIMIT")
fi
bash scripts/06_run_b5_static_hypothesis.sh \
  "${B5_ARGS[@]}" --run-id "${RUN_PREFIX}_b5"
