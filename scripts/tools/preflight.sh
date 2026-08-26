#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/Scripts/python.exe" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/Scripts/python.exe"
elif command -v uv >/dev/null 2>&1; then
  exec uv run --frozen python -m src.common.preflight --repo-root "$ROOT_DIR" "$@"
else
  echo "ERROR: run scripts/tools/setup_environment.sh first (uv/.venv missing)." >&2
  exit 1
fi

exec "$PYTHON_BIN" -m src.common.preflight --repo-root "$ROOT_DIR" "$@"
