#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

exec uv run --frozen python -m src.static_analysis.setup_codeql --repo-root "$ROOT_DIR"
