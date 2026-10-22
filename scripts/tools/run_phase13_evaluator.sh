#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
export MAXVERA_DATA_ROLE=evaluator
export PYTHONUNBUFFERED=1
exec uv run --frozen python -m src.experiments.phase13_evaluator \
  --repo-root "$repo_root" \
  --run-id "${1:-p13_test_analysis_001}" \
  --stage "${2:-all}"
