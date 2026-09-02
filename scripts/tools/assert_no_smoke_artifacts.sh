#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ID=""

if (($#)); then
  if [[ "$1" != "--run-id" || -z "${2:-}" || $# -ne 2 ]]; then
    echo "Usage: $0 [--run-id RUN_ID]" >&2
    exit 2
  fi
  RUN_ID="$2"
  if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    echo "ERROR: unsafe smoke run ID." >&2
    exit 2
  fi
fi

SMOKE_ROOTS=(
  "$ROOT_DIR/results/smoke"
  "$ROOT_DIR/data/interim/smoke"
  "$ROOT_DIR/.cache/experiments/smoke"
  "$ROOT_DIR/logs/smoke"
)
FAILURES=0

for root in "${SMOKE_ROOTS[@]}"; do
  if [[ -n "$RUN_ID" ]]; then
    if [[ -e "$root/$RUN_ID" ]]; then
      echo "ERROR: smoke artifact remains: $root/$RUN_ID" >&2
      FAILURES=$((FAILURES + 1))
    fi
  elif [[ -d "$root" ]] && find "$root" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    echo "ERROR: smoke artifact root is not empty: $root" >&2
    FAILURES=$((FAILURES + 1))
  fi
done

MODE_PATTERN='"mode"[[:space:]]*:[[:space:]]*"smoke"'
MODE_HITS="$(
  rg -l --hidden --glob '!smoke/**' "$MODE_PATTERN" "$ROOT_DIR/results" \
    "$ROOT_DIR/.cache/experiments" 2>/dev/null || true
)"
if [[ -n "$MODE_HITS" ]]; then
  echo "ERROR: a non-smoke result/cache contains mode=smoke." >&2
  FAILURES=$((FAILURES + 1))
fi

if [[ -n "$RUN_ID" ]]; then
  RUN_HITS="$(
    rg -l --hidden --fixed-strings --glob '!smoke/**' "$RUN_ID" "$ROOT_DIR/results" \
      "$ROOT_DIR/.cache/experiments" 2>/dev/null || true
  )"
  if [[ -n "$RUN_HITS" ]]; then
    echo "ERROR: a full-run result/cache references smoke run ID $RUN_ID." >&2
    FAILURES=$((FAILURES + 1))
  fi
fi

if ((FAILURES)); then
  exit 1
fi
echo "No smoke artifacts remain${RUN_ID:+ for run $RUN_ID}."
