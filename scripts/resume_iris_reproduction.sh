#!/usr/bin/env bash
# Resume a run in tmux. Completed configurations are not re-run; completed LLM calls are
# replayed from the run's response cache. Usage: scripts/resume_iris_reproduction.sh RUN_ID [--retry-failed]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-$(cat "$ROOT/runs/LATEST")}"; shift || true
exec "$ROOT/scripts/start_iris_tmux.sh" --resume "$RUN_ID" "$@"
