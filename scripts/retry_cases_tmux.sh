#!/usr/bin/env bash
# Re-run B2 for specific rows of an existing run (inside tmux), then recompute metrics/report.
# Usage (via tmux): scripts/retry_cases_tmux.sh RUN_ID "SLUG:CWE" ...
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$1"; shift
set +u; source "$ROOT/tools/miniforge3/bin/activate" iris; set -u
export IRIS_REPRO_DOTENV="$ROOT/.env" PYTHONUNBUFFERED=1
cd "$ROOT"; H=iris_repro/harness; RC=0
for item in "$@"; do
  slug="${item%%:*}"; cwe="${item##*:}"
  python $H/run_case.py --run-id "$RUN_ID" --config b2 --slug "$slug" --cwe "$cwe" --eval-id "$slug"; r=$?
  echo "[retry] $slug b2 exit=$r"; [ $r -ge 75 ] && { RC=$r; break; }
done
for s in evaluate.py label_diagnostics.py verify_metrics.py report.py; do python $H/$s --run-id "$RUN_ID"; done
echo "$RC" > "runs/$RUN_ID/retry_exit_status"; echo "[retry] done rc=$RC"
