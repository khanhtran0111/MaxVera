#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

if [[ "${MAXVERA_DATA_ROLE:-}" != "evaluator" ]]; then
  echo "ERROR: export MAXVERA_DATA_ROLE=evaluator before Phase 12 calibration." >&2
  exit 64
fi

exec uv run --frozen python -m src.calibration.runner --repo-root "$repo_root" "$@"
