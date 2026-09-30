#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

exec uv run --frozen python -m src.experiments.phase13 \
  --repo-root "$repo_root" \
  --stage preflight
