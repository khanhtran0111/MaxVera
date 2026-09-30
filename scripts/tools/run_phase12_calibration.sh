#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

if [[ "${MAXVERA_DATA_ROLE:-}" != "evaluator" ]]; then
  echo "ERROR: export MAXVERA_DATA_ROLE=evaluator before Phase 12 calibration." >&2
  exit 64
fi

exec uv run --frozen python -m src.calibration.runner --repo-root "$repo_root" "$@"
