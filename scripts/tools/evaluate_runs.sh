#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

if [[ "${MAXVERA_DATA_ROLE:-}" != "evaluator" ]]; then
  echo "ERROR: export MAXVERA_DATA_ROLE=evaluator before evaluation." >&2
  exit 64
fi

exec uv run --frozen python -m src.baselines.evaluation --repo-root "$ROOT_DIR" "$@"
