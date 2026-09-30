#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

if [[ "${MAXVERA_DATA_ROLE:-}" != "evaluator" ]]; then
  echo "ERROR: export MAXVERA_DATA_ROLE=evaluator before Phase 12 full run." >&2
  exit 64
fi

run_id="${1:-p12_calibration_dev_full_001}"
bash scripts/tools/run_phase12_calibration.sh --mode full --run-id "$run_id"
bash scripts/tools/validate_phase12.sh \
  --run-root "results/calibration/phase12/$run_id"
