#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

run_id="${1:-p11_diff_dev_full_001}"
if [[ "$#" -gt 0 ]]; then
  shift
fi
runner_args=("$@")
fixed_root="data/interim/phase11_fixed_codeql_databases"
run_root="results/verification/phase11/$run_id"
mkdir -p "$fixed_root" results/verification/phase11

export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/prepare_phase11_fixed_databases.sh \
  2>&1 | tee "$fixed_root/full_preparation.log"
preparation_status=${PIPESTATUS[0]}
unset MAXVERA_DATA_ROLE

if [[ "$preparation_status" -gt 1 ]]; then
  printf 'Fixed database preparation stopped with fatal status %s.\n' \
    "$preparation_status" >&2
  exit "$preparation_status"
fi
if [[ "$preparation_status" -eq 1 ]]; then
  printf 'Some fixed databases are unavailable; continuing with explicit failure accounting.\n'
fi

bash scripts/tools/run_phase11_verification.sh \
  --run-id "$run_id" \
  --mode full \
  --verification-mode differential \
  "${runner_args[@]}" \
  2>&1 | tee "$fixed_root/full_verification.log"
runner_status=${PIPESTATUS[0]}
if [[ "$runner_status" -ne 0 ]]; then
  exit "$runner_status"
fi

bash scripts/tools/validate_phase11.sh \
  --run-root "$run_root" \
  2>&1 | tee -a "$fixed_root/full_verification.log"
