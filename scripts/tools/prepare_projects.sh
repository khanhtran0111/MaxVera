#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

bash "$ROOT_DIR/scripts/tools/setup_codeql.sh"

uv run --frozen python -m src.data.toolchains \
  --repo-root "$ROOT_DIR" \
  --install-jdks \
  --require-jdks

uv run --frozen python -m src.data.build_projects \
  --repo-root "$ROOT_DIR" \
  "$@"
