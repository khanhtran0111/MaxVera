#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf '%s\n' \
    'Usage: run-iris.sh --project SLUG --query QUERY --model MODEL --model-id HF_ID' \
    '                   --model-revision SHA --run-id ID --seed N' \
    '                   --iris-commit SHA [batch/thread options]'
}

project=''
query=''
model=''
model_id=''
model_revision=''
run_id=''
seed=''
iris_commit=''
label_api_batch_size='30'
label_func_param_batch_size='20'
num_threads='1'

while (($#)); do
  case "$1" in
    --project) project="$2"; shift 2 ;;
    --query) query="$2"; shift 2 ;;
    --model) model="$2"; shift 2 ;;
    --model-id) model_id="$2"; shift 2 ;;
    --model-revision) model_revision="$2"; shift 2 ;;
    --run-id) run_id="$2"; shift 2 ;;
    --seed) seed="$2"; shift 2 ;;
    --iris-commit) iris_commit="$2"; shift 2 ;;
    --label-api-batch-size) label_api_batch_size="$2"; shift 2 ;;
    --label-func-param-batch-size) label_func_param_batch_size="$2"; shift 2 ;;
    --num-threads) num_threads="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

for required in project query model model_id model_revision run_id seed iris_commit; do
  if [[ -z "${!required}" ]]; then
    printf 'Missing required argument: %s\n' "$required" >&2
    usage >&2
    exit 2
  fi
done

if [[ ! "$model_revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Model revision must be a full lowercase 40-hex commit: %s\n' "$model_revision" >&2
  exit 2
fi

readonly work_root='/work/iris'
readonly retained='/outputs/upstream_output'
readonly retained_common='/outputs/upstream_common'
readonly retained_log='/outputs/upstream_log'

retain_output() {
  local status=$?
  mkdir -p "$retained"
  if [[ -d "$work_root/output/$project/$run_id" ]]; then
    cp -a "$work_root/output/$project/$run_id/." "$retained/"
  fi
  if [[ -d "$work_root/output/common/$run_id" ]]; then
    mkdir -p "$retained_common"
    cp -a "$work_root/output/common/$run_id/." "$retained_common/"
  fi
  if [[ -d "$work_root/log" ]]; then
    mkdir -p "$retained_log"
    cp -a "$work_root/log/." "$retained_log/"
  fi
  exit "$status"
}
trap retain_output EXIT

actual_commit="$(git -c safe.directory=/inputs/iris -C /inputs/iris rev-parse HEAD)"
if [[ "$actual_commit" != "$iris_commit" ]]; then
  printf 'IRIS commit mismatch: expected %s, found %s\n' "$iris_commit" "$actual_commit" >&2
  exit 3
fi

mkdir -p "$work_root"
# Exclude checkout metadata and embedded benchmark/output trees.  Only the
# pinned implementation is copied; inputs cross their explicit mount points.
tar -C /inputs/iris \
  --exclude='./.git' \
  --exclude='./codeql' \
  --exclude='./data' \
  --exclude='./output' \
  -cf - . | tar -C "$work_root" -xf -

cp -a /opt/codeql "$work_root/codeql"
mkdir -p \
  "$work_root/data/codeql-dbs" \
  "$work_root/data/cwe-bench-java/data" \
  "$work_root/data/cwe-bench-java/package-names" \
  "$work_root/data/cwe-bench-java/project-sources"
cp -a /inputs/database "$work_root/data/codeql-dbs/$project"
cp -a /inputs/repository "$work_root/data/cwe-bench-java/project-sources/$project"
cp -a /inputs/evaluator/project_info.csv "$work_root/data/cwe-bench-java/data/project_info.csv"
cp -a /inputs/evaluator/fix_info.csv "$work_root/data/cwe-bench-java/data/fix_info.csv"
cp -a /inputs/evaluator/package-names.txt \
  "$work_root/data/cwe-bench-java/package-names/$project.txt"

test -x "$work_root/codeql/codeql"
test -d "$work_root/data/codeql-dbs/$project/db-java"
test -f "$work_root/data/cwe-bench-java/data/project_info.csv"
test -f "$work_root/data/cwe-bench-java/data/fix_info.csv"

# Upstream IRIS calls from_pretrained() without a revision.  Fetch the exact
# immutable snapshot, point the cache's main ref at it, and then prohibit any
# network fallback so the unmodified upstream call resolves deterministically.
python - "$model_id" "$model_revision" <<'PY'
import os
import sys
import json
from pathlib import Path

from huggingface_hub import snapshot_download
from huggingface_hub.file_download import repo_folder_name

model_id, revision = sys.argv[1:]
hf_home = Path(os.environ["HF_HOME"])
hub_cache = Path(os.environ.get("HF_HUB_CACHE", hf_home / "hub"))
snapshot = Path(
    snapshot_download(
        repo_id=model_id,
        revision=revision,
        cache_dir=hub_cache,
    )
).resolve()
if snapshot.name != revision:
    raise RuntimeError(f"unexpected Hugging Face snapshot path: {snapshot}")
repo_cache = hub_cache / repo_folder_name(repo_id=model_id, repo_type="model")
refs = repo_cache / "refs"
refs.mkdir(parents=True, exist_ok=True)
(refs / "main").write_text(revision, encoding="utf-8")
with Path("/outputs/model_snapshot.json").open("x", encoding="utf-8") as handle:
    json.dump(
        {
            "model_id": model_id,
            "requested_revision": revision,
            "resolved_snapshot": snapshot.name,
            "offline_after_resolution": True,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
print(f"Pinned Hugging Face snapshot: {model_id}@{revision}")
PY
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1

cd "$work_root"
python src/neusym_vul.py "$project" \
  --query "$query" \
  --llm "$model" \
  --run-id "$run_id" \
  --seed "$seed" \
  --label-api-batch-size "$label_api_batch_size" \
  --label-func-param-batch-size "$label_func_param_batch_size" \
  --num-threads "$num_threads" \
  --skip-posthoc-filter
