#!/usr/bin/env bash
set -Eeuo pipefail
pipeline_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$pipeline_root"
exec uv run --frozen python -m src.pipeline_v2.validate "$@"
