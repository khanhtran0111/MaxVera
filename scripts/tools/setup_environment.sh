#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
UV_VERSION="0.11.32"
UV_INSTALLER_SHA256="43aff33a967fe40e8c17949d8c85c65bc43f3b5c94742393c957f56ab5ba80f4"

cd "$ROOT_DIR"

if ! command -v uv >/dev/null 2>&1; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required to install pinned uv ${UV_VERSION}." >&2
    exit 1
  fi
  echo "Installing uv ${UV_VERSION} from the versioned official installer."
  SETUP_TEMP_DIR="$(mktemp -d)"
  cleanup_setup_temp() {
    rm -f -- "$SETUP_TEMP_DIR/install.sh"
    rmdir -- "$SETUP_TEMP_DIR"
  }
  trap cleanup_setup_temp EXIT
  curl --proto '=https' --tlsv1.2 -LsSf \
    "https://astral.sh/uv/${UV_VERSION}/install.sh" \
    -o "$SETUP_TEMP_DIR/install.sh"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${UV_INSTALLER_SHA256}  $SETUP_TEMP_DIR/install.sh" | sha256sum --check --status
  else
    actual_sha="$(shasum -a 256 "$SETUP_TEMP_DIR/install.sh" | awk '{print $1}')"
    [[ "$actual_sha" == "$UV_INSTALLER_SHA256" ]]
  fi
  sh "$SETUP_TEMP_DIR/install.sh"
  cleanup_setup_temp
  trap - EXIT
  export PATH="${HOME}/.local/bin:${PATH}"
fi

installed_uv="$(uv --version)"
if [[ "$installed_uv" != "uv ${UV_VERSION}"* ]]; then
  echo "ERROR: expected uv ${UV_VERSION}; found ${installed_uv}." >&2
  echo "Install the pinned version or use the digest-pinned Docker image." >&2
  exit 1
fi

uv lock --check
uv sync --frozen --group dev --python 3.10.16
uv run --frozen python -c \
  'from pathlib import Path; from src.common.envfile import initialize_env_file; initialize_env_file(Path(".env"))'

echo "Python environment is synchronized from uv.lock."
bash "$ROOT_DIR/scripts/tools/preflight.sh" --profile phase1
