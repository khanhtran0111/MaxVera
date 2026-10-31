#!/usr/bin/env bash
# Validate environment + dataset + API, create (or resume) a run, and launch it in a detached
# tmux session named iris_repro_v1.
#
#   scripts/start_iris_tmux.sh --smoke [--projects SLUG ...] [--cost-limit USD] [--run-id ID]
#   scripts/start_iris_tmux.sh --full  [--cost-limit USD] [--run-id ID]
#   scripts/start_iris_tmux.sh --resume RUN_ID [--retry-failed]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="${IRIS_TMUX_SESSION:-iris_repro_v1}"
PY="$ROOT/tools/miniforge3/envs/iris/bin/python"
H="$ROOT/iris_repro/harness"
MODE=""; RUN_ID=""; COST=""; PROJECTS=(); EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) MODE=smoke; shift;;
    --full) MODE=full; shift;;
    --resume) MODE=resume; RUN_ID="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --cost-limit) COST="$2"; shift 2;;
    --retry-failed) EXTRA+=(--retry-failed); shift;;
    --projects) shift; while [ $# -gt 0 ] && [[ "$1" != --* ]]; do PROJECTS+=("$1"); shift; done;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
[ -n "$MODE" ] || { echo "specify --smoke, --full or --resume RUN_ID"; exit 2; }

# 0. Refuse duplicate launches (a session whose pane has exited is cleaned up)
if tmux has-session -t "$SESSION" 2>/dev/null; then
  if [ "$(tmux display-message -p -t "$SESSION" '#{pane_dead}')" = "1" ]; then
    echo "[start] removing finished session $SESSION"; tmux kill-session -t "$SESSION"
  else
    echo "[start] tmux session '$SESSION' is already running; attach with: tmux attach -t $SESSION"; exit 1
  fi
fi

# 1. Environment validation
IRIS="$ROOT/vendor/iris-v1"
[ "$(git -C "$IRIS" rev-parse HEAD)" = "$("$PY" -c "import json;print(json.load(open('$ROOT/iris_repro/config/pins.json'))['iris']['commit'])")" ] || { echo "IRIS commit mismatch"; exit 1; }
git -C "$IRIS" apply --reverse --check "$ROOT/iris_repro/patches/iris-v1-compat.patch" || { echo "compat patch not applied (run scripts/setup_iris_env.sh)"; exit 1; }
"$IRIS/codeql/codeql" version --format=terse | grep -q '^2\.15\.' || { echo "patched CodeQL missing"; exit 1; }
"$PY" -c "import sys; assert sys.version_info[:2]==(3,10)" || { echo "conda env 'iris' (py3.10) missing"; exit 1; }
grep -q '^OPENROUTER_API_KEY=.\+' "$ROOT/.env" || { echo "OPENROUTER_API_KEY missing from .env"; exit 1; }
for d in jdk1.7.0_80 jdk1.8.0_202 jdk-17.0.12 apache-maven-3.5.0 apache-maven-3.9.8; do
  [ -d "$IRIS/data/cwe-bench-java/java-env/$d" ] || { echo "missing toolchain $d"; exit 1; }; done
echo "[start] environment ok"

# 2. Dataset validation
"$PY" "$H/dataset_manifest.py" || { echo "dataset manifest invalid"; exit 1; }

# 3. Run creation
if [ "$MODE" != resume ]; then
  EXP="$ROOT/iris_repro/config/experiment.json"
  [ -n "$COST" ] || COST=$("$PY" -c "import json;d=json.load(open('$EXP'));print(d['${MODE}_cost_limit_usd'])")
  [ -n "$RUN_ID" ] || RUN_ID="iris-v1_gptoss20b_${MODE}_$(date -u +%Y%m%dT%H%M%SZ)"
  ARGS=(--run-id "$RUN_ID" --cohort "$MODE" --cost-limit-usd "$COST")
  [ ${#PROJECTS[@]} -gt 0 ] && ARGS+=(--projects "${PROJECTS[@]}")
  "$PY" "$H/init_run.py" "${ARGS[@]}"
fi
RUN_DIR="$ROOT/runs/$RUN_ID"
[ -f "$RUN_DIR/run_manifest.json" ] || { echo "no such run $RUN_ID"; exit 1; }

# 4. API preflight with the run's own configuration (cost is charged to the run ledger)
IRIS_REPRO_LLM_CONFIG="$RUN_DIR/config/llm_config.json" IRIS_REPRO_DOTENV="$ROOT/.env" \
  "$PY" "$H/preflight_openrouter.py" --run-dir "$RUN_DIR" > "$RUN_DIR/manifests/api_preflight.stdout" 2>&1 \
  || { echo "API preflight failed; see $RUN_DIR/manifests/api_preflight.json"; exit 77; }
echo "[start] API preflight ok"

# 5. Detached tmux session; the pane is kept after exit so the final status stays visible
tmux new-session -d -s "$SESSION" -x 220 -y 50 "bash '$ROOT/scripts/run_iris_reproduction.sh' '$RUN_ID' ${EXTRA[*]:-}"
tmux set-option -t "$SESSION" remain-on-exit on >/dev/null
echo "$RUN_ID" > "$ROOT/runs/LATEST"
echo "[start] launched run $RUN_ID in tmux session '$SESSION'"
echo "  monitor: scripts/check_iris_status.sh $RUN_ID | tmux attach -t $SESSION | tmux capture-pane -pt $SESSION | tail"
