#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

# The build and CodeQL tracing must use the identical successful command, so
# Phase 2 intentionally exposes one sequential entrypoint for both operations.
exec bash "$ROOT_DIR/scripts/tools/prepare_projects.sh" "$@"
