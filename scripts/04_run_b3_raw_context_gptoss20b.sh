#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT_DIR/scripts/tools/run_baseline_entrypoint.sh" B3 \
  configs/baselines/b3_raw_context.yaml "$@"
