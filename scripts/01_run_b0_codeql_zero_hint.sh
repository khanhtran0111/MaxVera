#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT_DIR/scripts/tools/run_baseline_entrypoint.sh" B0 configs/baselines/b0_codeql_zero_hint.yaml "$@"
