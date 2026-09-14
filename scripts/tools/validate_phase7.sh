#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
exec uv run --frozen python -m src.graphs.program.validate --repo-root "$ROOT_DIR" "$@"
