#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

uv run --frozen python -m src.data.phase2 materialize \
  --repo-root "$ROOT_DIR" \
  --config configs/datasets/cwe_bench_v1.yaml

uv run --frozen python -m src.data.phase2 materialize \
  --repo-root "$ROOT_DIR" \
  --config configs/datasets/cwe_bench_extended.yaml \
  --with-splits
