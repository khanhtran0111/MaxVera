#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -Eeuo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "ERROR: internal baseline entrypoint requires ID and config." >&2
  exit 64
fi

BASELINE_ID="$1"
CONFIG_PATH="$2"
shift 2
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

bash "$ROOT_DIR/scripts/tools/assert_no_smoke_artifacts.sh"

exec uv run --frozen python -m src.cli.run_baseline \
  --baseline-id "$BASELINE_ID" \
  --config "$CONFIG_PATH" \
  -- "$@"
