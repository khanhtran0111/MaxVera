#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IMAGE=""
NETWORK_MODE="none"

usage() {
  echo "Usage: $0 --image IMAGE [--network host] -- COMMAND [ARG ...]" >&2
}

while (($#)); do
  case "$1" in
    --image)
      IMAGE="${2:-}"
      shift 2
      ;;
    --network)
      NETWORK_MODE="${2:-}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$IMAGE" || $# -eq 0 ]]; then
  usage
  exit 2
fi
if [[ "$NETWORK_MODE" != "none" && "$NETWORK_MODE" != "host" ]]; then
  echo "ERROR: --network must be 'none' or 'host'." >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required; refusing to run analysis without filesystem isolation." >&2
  exit 1
fi

mkdir -p \
  "$ROOT_DIR/data/processed/analysis_input/projects" \
  "$ROOT_DIR/data/interim/project_sources" \
  "$ROOT_DIR/data/interim/codeql_databases"

# evaluator_only, canonical manifests, raw metadata, and the host repository
# root are deliberately not mounted into this container.
exec docker run --rm --read-only --network "$NETWORK_MODE" \
  --tmpfs /tmp:rw,noexec,nosuid,size=2g \
  --mount "type=bind,src=$ROOT_DIR/src,dst=/workspace/src,readonly" \
  --mount "type=bind,src=$ROOT_DIR/data/processed/analysis_input,dst=/workspace/data/analysis_input,readonly" \
  --mount "type=bind,src=$ROOT_DIR/data/interim/project_sources,dst=/workspace/data/analysis_input/projects,readonly" \
  --mount "type=bind,src=$ROOT_DIR/data/interim/codeql_databases,dst=/workspace/data/codeql_databases,readonly" \
  --workdir /workspace \
  --env MAXVERA_DATA_ROLE=analysis \
  "$IMAGE" "$@"
