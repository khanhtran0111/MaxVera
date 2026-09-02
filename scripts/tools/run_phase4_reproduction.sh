#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID=""
MODE="pilot"
LIMIT=""
RESUME=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --limit) LIMIT="${2:-}"; shift 2 ;;
    --resume) RESUME=true; shift ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ -z "$RUN_ID" || ( "$MODE" != "pilot" && "$MODE" != "full" ) ]]; then
  echo "Usage: $0 --run-id ID --mode pilot|full [--limit N] [--resume]" >&2
  exit 64
fi
if [[ "$MODE" == "full" && -n "$LIMIT" ]]; then
  echo "ERROR: --limit cannot be used with --mode full." >&2
  exit 64
fi

cd "$ROOT_DIR"
bash scripts/tools/assert_no_smoke_artifacts.sh
bash scripts/tools/validate_phase2.sh
bash scripts/tools/preflight.sh --profile phase4
bash scripts/tools/validate_openrouter.sh

COMMON_ARGS=(--run-id "$RUN_ID" --mode "$MODE")
if [[ -n "$LIMIT" ]]; then COMMON_ARGS+=(--limit "$LIMIT"); fi
if [[ "$RESUME" == true ]]; then COMMON_ARGS+=(--resume); fi

echo "Running Phase 4 B0 with the existing Phase 2 databases..."
bash scripts/01_run_b0_codeql_zero_hint.sh "${COMMON_ARGS[@]}"
echo "Running Phase 4 B1 CWE-oracle CodeQL reference..."
bash scripts/02_run_b1_codeql_oracle_cwe.sh "${COMMON_ARGS[@]}"

echo "Running Phase 4 B2: IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter..."
bash scripts/03_run_b2_iris_gptoss20b.sh "${COMMON_ARGS[@]}"

MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m src.reproduction.evaluation \
  --run-id "$RUN_ID"
uv run --frozen python -m src.reproduction.report --run-id "$RUN_ID"
VALIDATE_ARGS=(--run-id "$RUN_ID")
if [[ "$MODE" == "full" ]]; then VALIDATE_ARGS+=(--require-full); fi
uv run --frozen python -m src.reproduction.validate "${VALIDATE_ARGS[@]}"
echo "Phase 4 $MODE run validated: $RUN_ID"
