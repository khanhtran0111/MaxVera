#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

log_dir="results/phase13/p13_test_analysis_001/evaluation/logs"
mkdir -p "$log_dir"
exec > >(tee -a "$log_dir/phase13_verifier_v2_corrective.log") 2>&1
echo "[$(date --iso-8601=seconds)] starting Phase 13 verifier v2 corrective run"

test_run="results/phase13/p13_test_analysis_001/evaluation/verification/p13_test_verification_v2_corrective_001"
test_parent="results/phase13/p13_test_analysis_001/evaluation/verification/p13_test_analysis_001_verification"
dev_run="results/verification/phase11/p11_diff_dev_full_v2_corrective_001"
dev_parent="results/verification/phase11/p11_diff_dev_full_002"

if [[ ! -d "$test_run" ]]; then
  MAXVERA_DATA_ROLE=evaluator .venv/bin/python -m src.verification.runner \
    --repo-root . \
    --config results/phase13/p13_test_analysis_001/configs/phase13_verification.yaml \
    --output-root results/phase13/p13_test_analysis_001/evaluation/verification \
    --run-id p13_test_verification_v2_corrective_001 \
    --mode full \
    --verification-mode differential \
    --fixed-endpoint-remapping \
    --reuse-vulnerable-from "$test_parent"
fi
MAXVERA_DATA_ROLE=evaluator .venv/bin/python -m src.verification.validate \
  --repo-root . \
  --run-root "$test_run"

if [[ ! -d "$dev_run" ]]; then
  env -u MAXVERA_DATA_ROLE .venv/bin/python -m src.verification.runner \
    --repo-root . \
    --config configs/experiments/phase11_static_verification.yaml \
    --output-root results/verification/phase11 \
    --run-id p11_diff_dev_full_v2_corrective_001 \
    --mode full \
    --verification-mode differential \
    --fixed-endpoint-remapping \
    --reuse-vulnerable-from "$dev_parent"
fi
env -u MAXVERA_DATA_ROLE .venv/bin/python -m src.verification.validate \
  --repo-root . \
  --run-root "$dev_run"
echo "[$(date --iso-8601=seconds)] Phase 13 verifier v2 corrective run completed"
