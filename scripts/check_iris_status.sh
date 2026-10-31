#!/usr/bin/env bash
# Status of a run: tmux session, progress, per-status counts, cost, last log lines.
# Usage: scripts/check_iris_status.sh [RUN_ID]
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="${IRIS_TMUX_SESSION:-iris_repro_v1}"
RUN_ID="${1:-$(cat "$ROOT/runs/LATEST" 2>/dev/null)}"
RUN_DIR="$ROOT/runs/$RUN_ID"
echo "== tmux"; tmux list-sessions 2>/dev/null || echo "(no tmux server)"
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "pane_dead=$(tmux display-message -p -t "$SESSION" '#{pane_dead}') pane_pid=$(tmux display-message -p -t "$SESSION" '#{pane_pid}')"
fi
echo "== run $RUN_ID"
[ -f "$RUN_DIR/exit_status" ] && echo "last exit status: $(cat "$RUN_DIR/exit_status")"
"$ROOT/tools/miniforge3/envs/iris/bin/python" - "$RUN_DIR" <<'PY'
import json, os, sys, collections
rd = sys.argv[1]
p = os.path.join(rd, "status", "progress.json")
if os.path.exists(p): print("progress:", json.load(open(p)))
s = os.path.join(rd, "status", "execution_status.json")
if os.path.exists(s):
    t = json.load(open(s))
    for k in ("db_status", "b0_status", "b2_status"):
        print(f"{k:10s}", dict(collections.Counter(r[k] for r in t)))
led = os.path.join(rd, "llm", "ledger.jsonl")
if os.path.exists(led):
    n = c = hits = 0; cost = 0.0; pt = ct = rt = 0
    for l in open(led):
        r = json.loads(l)
        if r.get("cache_hit"): hits += 1; continue
        n += 1; cost += r.get("cost_usd") or 0; pt += r.get("prompt_tokens") or 0
        ct += r.get("completion_tokens") or 0; rt += r.get("reasoning_tokens") or 0
    lim = json.load(open(os.path.join(rd, "config", "llm_config.json")))["accounting"]["cost_limit_usd"]
    print(f"llm: requests={n} cache_hits={hits} prompt_tokens={pt} completion_tokens={ct} reasoning_tokens={rt} cost=${cost:.4f} / limit ${lim}")
PY
echo "== last orchestrator log lines"; tail -n 15 "$RUN_DIR/logs/orchestrator.log" 2>/dev/null
if tmux has-session -t "$SESSION" 2>/dev/null; then echo "== tmux pane"; tmux capture-pane -pt "$SESSION" | grep -v '^$' | tail -n 8; fi
