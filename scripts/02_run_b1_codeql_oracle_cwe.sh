#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT_DIR/scripts/tools/run_baseline_entrypoint.sh" B1 configs/baselines/b1_codeql_oracle_cwe.yaml "$@"
