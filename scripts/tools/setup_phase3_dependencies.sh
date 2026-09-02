#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
UV_VERSION="0.11.32"
UV_INSTALLER_SHA256="43aff33a967fe40e8c17949d8c85c65bc43f3b5c94742393c957f56ab5ba80f4"

cd "$ROOT_DIR"

if [[ "$(uv --version 2>/dev/null || true)" != "uv ${UV_VERSION}"* ]]; then
  TEMP_DIR="$(mktemp -d)"
  cleanup_installer() {
    rm -f -- "$TEMP_DIR/install.sh"
    rmdir -- "$TEMP_DIR"
  }
  trap cleanup_installer EXIT
  curl --proto '=https' --tlsv1.2 -LsSf \
    "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    -o "$TEMP_DIR/install.sh"
  echo "${UV_INSTALLER_SHA256}  $TEMP_DIR/install.sh" | sha256sum --check --status
  sh "$TEMP_DIR/install.sh"
  cleanup_installer
  trap - EXIT
  export PATH="$HOME/.local/bin:$PATH"
fi

if [[ "$(uv --version)" != "uv ${UV_VERSION}"* ]]; then
  echo "ERROR: uv ${UV_VERSION} was not activated." >&2
  exit 1
fi

uv sync --frozen --group dev --python 3.10.16
uv run --frozen python -m src.common.setup_phase3 --repo-root "$ROOT_DIR"
bash "$ROOT_DIR/scripts/tools/preflight.sh" --profile full
