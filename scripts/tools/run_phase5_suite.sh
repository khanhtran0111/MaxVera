#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

MODE="pilot"
RUN_PREFIX=""
LIMIT="1"
CONFIRM="false"
BUDGET_MODE="budget_matched"
SKIP_EXISTING="false"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --run-prefix) RUN_PREFIX="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --budget-mode) BUDGET_MODE="$2"; shift 2 ;;
    --confirm-api-spend) CONFIRM="true"; shift ;;
    --skip-existing) SKIP_EXISTING="true"; shift ;;
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

FAILURES=()
run_baseline() {
  local label="$1"
  local run_root="$2"
  shift 2
  if [[ -e "$run_root" && "$SKIP_EXISTING" == "true" ]]; then
    if [[ ! -f "$run_root/STATUS" ]]; then
      echo "ERROR: cannot skip incomplete run root: $run_root" >&2
      FAILURES+=("$label:incomplete")
      return
    fi
    local existing_status
    existing_status="$(<"$run_root/STATUS")"
    echo "SKIP: $label already finalized with STATUS=$existing_status: $run_root"
    if [[ "$existing_status" != "SUCCESS" ]]; then
      FAILURES+=("$label:existing-$existing_status")
    fi
    return
  fi
  if "$@"; then
    echo "COMPLETE: $label"
  else
    local exit_code="$?"
    echo "WARNING: $label exited $exit_code; continuing with the remaining baselines." >&2
    FAILURES+=("$label:exit-$exit_code")
  fi
}

run_baseline B3 "results/baselines/raw_context_gptoss20b/${RUN_PREFIX}_b3" \
  bash scripts/04_run_b3_raw_context_gptoss20b.sh \
  "${COMMON[@]}" --run-id "${RUN_PREFIX}_b3"
run_baseline B4 "results/baselines/text_rag_gptoss20b/${RUN_PREFIX}_b4" \
  bash scripts/05_run_b4_text_rag_gptoss20b.sh \
  "${COMMON[@]}" --run-id "${RUN_PREFIX}_b4"
B5_ARGS=(--mode "$MODE" --budget-mode "$BUDGET_MODE")
if [[ "$MODE" != "full" ]]; then
  B5_ARGS+=(--limit "$LIMIT")
fi
run_baseline B5 "results/baselines/static_hypothesis/${RUN_PREFIX}_b5" \
  bash scripts/06_run_b5_static_hypothesis.sh \
  "${B5_ARGS[@]}" --run-id "${RUN_PREFIX}_b5"

if ((${#FAILURES[@]})); then
  echo "Suite completed with recorded analysis/run failures: ${FAILURES[*]}" >&2
  echo "Evaluate every finalized run; validated failures remain misses in intention-to-analyze."
  exit 1
fi
echo "Suite completed successfully: B3, B4, B5"
