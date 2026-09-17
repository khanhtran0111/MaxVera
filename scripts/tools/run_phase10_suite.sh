#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for script in \
  scripts/07_run_b6_program_graph_only.sh \
  scripts/08_run_b7_security_kg_only.sh \
  scripts/09_run_b8_useg_no_pruning.sh \
  scripts/10_run_b9_full_useg.sh; do
  bash "$script" "$@"
done
