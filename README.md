# MaxVera / OpenIRIS research harness

This repository now contains the Phase 0 reproducibility layer for the research
plan in `plan/ke_hoach_trien_khai_openiris_research.md`. It freezes both
CWE-Bench-Java tracks, enforces a zero-hint runtime/evaluator boundary, pins the
legacy IRIS/CodeQL toolchain, evaluates SARIF with IRIS-v1-compatible semantics,
and stores every local baseline run in an append-only registry.

## Current Phase 0 scope

- Legacy reproduction snapshot: IRIS `7aa94755...` with its exact benchmark
  submodule `698fb724...` (120 instances, 77 repositories, 4 CWEs).
- V2 research snapshot: IRIS `3a12f457...` (213 instances, 135 repositories,
  49 raw labels / 45 normalized CWEs).
- Docker smoke toolchain: JDK 17, IRIS patched CodeQL release, Java query pack
  0.8.3, and a legacy GPU-backed Qwen2.5-Coder-1.5B compatibility configuration.
- Primary research LLM: local Qwen2.5-Coder-3B-Instruct `Q4_K_M` GGUF via
  pinned llama.cpp/CUDA 12.4. The model download is revision- and SHA-256-verified.
- Published IRIS tables are imported only as comparison references. They are
  explicitly separate from local reruns.

The generated gate report is
[results/phases/phase_00/report.md](results/phases/phase_00/report.md).

## Notebook quick start

Phase 0 now has one canonical end-to-end notebook. On the experimental machine:

```powershell
uv sync --extra dev --extra notebook --locked
uv run python -m ipykernel install --user --name maxvera-openiris
```

Open [workflows/notebooks/phase_00_reproducibility.ipynb](workflows/notebooks/phase_00_reproducibility.ipynb), select the `maxvera-openiris` kernel, then use **Restart Kernel and Run All**. Every execution cell renders a status and links its output artifacts.

The target Quadro P2000 is Pascal (`sm_61`). Use the pinned llama.cpp `b10590` Windows CUDA 12 build with its CUDA 12.4 DLL package; CUDA 13 must not be used because it dropped Pascal library/offline compilation support. Make `llama-server` available on `PATH` before running the local-model smoke cell.

See [docs/local_llm_p2000.md](docs/local_llm_p2000.md) for the pinned download names, verification command and 4 GB VRAM fallback policy.

## Headless quick start

```powershell
uv sync --extra dev --locked
uv run python scripts/data/bootstrap_upstream.py
uv run python scripts/data/prepare_phase0.py
uv run python scripts/toolchain/fetch_codeql.py
uv run python scripts/toolchain/fetch_qwen_gguf.py
docker build --platform linux/amd64 -t maxvera-phase0:jdk17 docker/phase0
docker build --platform linux/amd64 -f docker/phase0/Dockerfile.codeql `
  -t maxvera-phase0:codeql tools/downloads
docker build --platform linux/amd64 -f docker/phase0/Dockerfile.iris `
  -t maxvera-phase0:iris-local docker/phase0
uv run openiris-doctor --config configs/toolchain/phase0.yaml --strict
uv run pytest
uv run python scripts/phase0.py
```

The bootstrap commands accept only the pinned commits/archive digest. See
[docker/phase0/README.md](docker/phase0/README.md) for the container build
contract and [docs/reproducibility.md](docs/reproducibility.md) for checkout
safety behavior.

Run the reproducible CodeQL smoke:

```powershell
$phase0Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$codeqlRunId = "phase0_codeql_smoke_$phase0Stamp"
uv run python scripts/baselines/run_codeql_docker.py `
  --config configs/experiments/phase0_codeql_smoke.yaml `
  --run-id $codeqlRunId
```

After that database exists, run the pinned local IRIS configuration:

```powershell
# Keep $codeqlRunId from the preceding command.
$irisStamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$irisRunId = "phase0_iris_qwen15b_$irisStamp"
uv run python scripts/baselines/run_iris_docker.py `
  --config configs/experiments/phase0_iris_local_smoke.yaml `
  --instance-id oi_d67309725ca108a035d5bb04a9b302b4 `
  --runtime-manifest data/runtime_views/cwe_bench_java_legacy_698fb724/manifest.jsonl `
  --runtime-repository data/runtime_views/cwe_bench_java_legacy_698fb724/oi_d67309725ca108a035d5bb04a9b302b4/repository `
  --ground-truth data/ground_truth/cwe_bench_java_legacy_698fb724/ground_truth.jsonl `
  --codeql-database "runs/$codeqlRunId/workspace/database" `
  --image maxvera-phase0:iris-local `
  --run-id $irisRunId
```

Run IDs are append-only and must never be reused, including after a failed run.

Third-party checkouts, materialized source, databases, models, and run logs are
ignored by Git. Frozen manifests, schemas, protocols, inventory reports, and
aggregate baseline records remain source-controlled.

## Artifact map

| Purpose | Location |
|---|---|
| Frozen dataset/toolchain identities | `data/manifests/` |
| Sanitized runtime records | `data/runtime_views/` (ignored) |
| Evaluator-only labels | `data/ground_truth/` (ignored) |
| Dataset inventory and gate reports | `reports/` |
| Append-only local run evidence | `runs/<run_id>/` (ignored) |
| Canonical phase notebooks and wrappers | `workflows/` |
| Phase results, reports and frozen baselines | `results/phases/phase_<NN>/` |
| Artifact contracts | `schemas/` |
| Research protocol | `docs/` |

See [docs/reproducibility.md](docs/reproducibility.md) and
[docs/leakage_policy.md](docs/leakage_policy.md) before adding a new experiment.
