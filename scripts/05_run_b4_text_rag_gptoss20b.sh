#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT_DIR/scripts/tools/run_baseline_entrypoint.sh" B4 \
  configs/baselines/b4_text_rag.yaml "$@"
