#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IRIS_DIR="$ROOT_DIR/third_party/iris"
IRIS_URL="https://github.com/iris-sast/iris.git"
IRIS_COMMIT="67140e84e6a01da2b44803a6208be2ea7bd4bd51"
cd "$ROOT_DIR"

uv sync --frozen --group dev --python 3.10.16

if [[ ! -d "$IRIS_DIR/.git" ]]; then
  TEMP_DIR="$(mktemp -d)"
  cleanup_setup() {
    rm -rf -- "$TEMP_DIR"
  }
  trap cleanup_setup EXIT
  git clone --filter=blob:none --no-checkout "$IRIS_URL" "$TEMP_DIR/iris"
  git -C "$TEMP_DIR/iris" checkout --detach "$IRIS_COMMIT"
  mkdir -p -- "$ROOT_DIR/third_party"
  mv -- "$TEMP_DIR/iris" "$IRIS_DIR"
  cleanup_setup
  trap - EXIT
fi

ACTUAL_COMMIT="$(git -C "$IRIS_DIR" rev-parse HEAD)"
DIRTY="$(git -C "$IRIS_DIR" status --porcelain=v1 --untracked-files=all)"
if [[ "$ACTUAL_COMMIT" != "$IRIS_COMMIT" || -n "$DIRTY" ]]; then
  echo "ERROR: third_party/iris must be clean at $IRIS_COMMIT." >&2
  exit 1
fi

bash scripts/tools/validate_phase2.sh
bash scripts/tools/assert_no_smoke_artifacts.sh
bash scripts/tools/preflight.sh --profile phase4
bash scripts/tools/validate_openrouter.sh
echo "Phase 4 dependencies are ready. IRIS is pinned at $IRIS_COMMIT."
