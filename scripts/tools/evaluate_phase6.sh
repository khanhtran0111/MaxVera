#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

if [[ "${MAXVERA_DATA_ROLE:-}" != "evaluator" ]]; then
  echo "ERROR: export MAXVERA_DATA_ROLE=evaluator before Phase 6 evaluation." >&2
  exit 64
fi

exec uv run --frozen python -m src.hypotheses.evaluation --repo-root "$ROOT_DIR" "$@"
