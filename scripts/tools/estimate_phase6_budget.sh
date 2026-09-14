#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

exec uv run --frozen python -m src.hypotheses.budget --repo-root "$ROOT_DIR" "$@"
