#!/usr/bin/env bash
# DEPRECATED COMPATIBILITY: use python -m maxvera pipeline reproduce|research.
printf '%s\n' 'Deprecated compatibility command; use python -m maxvera (see README).' >&2
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
exec uv run --frozen python -m src.graphs.program.runner --repo-root "$ROOT_DIR" "$@"
