#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT_DIR/scripts/tools/run_baseline_entrypoint.sh" B3 configs/baselines/b3_raw_context.yaml "$@"
