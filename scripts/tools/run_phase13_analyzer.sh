#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

run_id="${1:-p13_test_analysis_001}"
stage="${2:-all}"

export MAXVERA_DATA_ROLE=analyzer
exec uv run --frozen python -m src.experiments.phase13 \
  --repo-root "$repo_root" \
  --run-id "$run_id" \
  --stage "$stage" \
  --confirm-open-locked-test \
  --confirm-api-spend
