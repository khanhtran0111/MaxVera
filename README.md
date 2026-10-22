# MaxVera

Pipeline-first Java vulnerability research with two separate tracks:

1. **reproduce**: pinned IRIS v1 with oracle CWE and GPT-OSS-20B through OpenRouter, plus an independent CodeQL reference.
2. **research**: zero-hint static/graph candidate discovery with opaque inputs and an OS filesystem firewall.
3. **evaluate / compare**: independent evaluation of immutable raw output; labels stay outside research.

**Current acceptance status:** reproduction adapter and graph-only core are implemented with explicit validation gaps. Research LLM/verification variants are gated on a measured graph-only dev signal. Full reproduction `repro_fast_20261021T142440Z` is running with the measured fast profile (fixed Groq route, no artificial completion delay) after 393 tests and live API checks; no successful full result is claimed. Read [implementation status](docs/IMPLEMENTATION_STATUS.md) and the [execution record](docs/reproduction_full_2026-10-21.md).

## Safe checks — actually executed during this refactor

From this workspace, using its existing Python 3.10 environment:

```bash
.venv/bin/python -m maxvera doctor --config configs/runtime.yaml
.venv/bin/python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode full --run-id repro_dry_001 --dry-run
.venv/bin/python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode full --run-id graph_dry_001 --dry-run
.venv/bin/python -m pytest -q
```

Doctor checks local binaries/key presence and makes no network request; it does not claim the provider route is live. Dry-run prints the DAG, resolved redacted config, case count and configured request/cost ceilings without creating a run. Default `dry_run_default: true` requires `--execute` to enable real work.

## Prepare and run — operational examples, not executed benchmark results

The commands below are **not end-to-end benchmark validated in this migration**. Metadata preparation reuses the existing pinned dataset implementation. `--sources` downloads sources and can consume substantial disk space; preparation is trusted and may read labels.

```bash
# Metadata only, or add --sources explicitly to fetch/materialize source snapshots.
python -m maxvera dataset prepare --config configs/datasets/cwe_bench_java_v1.yaml
python -m maxvera dataset prepare --config configs/datasets/cwe_bench_extended.yaml --sources

# Reproduction: begin with 1–2 cases; hosted-model calls require existing .env credentials.
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode smoke --limit 2 --run-id repro_smoke_001 --execute
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode full --run-id repro_gptoss20b_001 --execute
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode full --run-id repro_gptoss20b_001 --resume --execute

# Research: the default is the existing frozen 96-project development split.
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode smoke --limit 2 --run-id graph_smoke_001 --execute
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant static_only --mode full --run-id zh_static_001 --execute
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode full --run-id zh_graph_001 --execute
```

A new run ID cannot overwrite an existing run. Full mode rejects `--limit` and accounts for every selected case. `--resume` requires matching source/code/tool/config/schema fingerprints and verified checkpoints. Paid stages interrupted at an uncertain remote-call boundary stop for journal inspection instead of repeating charges automatically.

```bash
# These CLI handlers are tested on temporary frozen fixture runs; real run IDs must exist.
python -m maxvera status --run-id repro_gptoss20b_001
python -m maxvera evaluate --run-id repro_gptoss20b_001 --protocol iris_paper
python -m maxvera evaluate --run-id zh_graph_001 --protocol zero_hint
python -m maxvera compare --runs zh_static_001,zh_graph_001 --output results/aggregate/graph_discovery_comparison
```

`text_only`, `graph_llm` and `graph_llm_verify` are reserved variants in the shared catalogue. They currently return an explicit `NOT_IMPLEMENTED` error. Follow the plan's graph-only dev gate before implementing them at scale.

## Data and output

Research receives only opaque `data/processed/analysis_input` snapshots and generic build/runtime metadata. A Linux Landlock ABI >=3 worker denies reads and writes of `.env`, raw metadata, canonical manifests, reproduction output and `evaluator_only`, including symlink access. Only the current run/private caches are writable; build copies preserve the shared source snapshots. Unsupported kernels fail closed. Keep original sources free of oracle hints before publishing zero-hint claims.

Full runs live at `results/reproduction/<run_id>` or `results/research/<run_id>`. Smoke uses `results/_smoke/<pipeline>/<run_id>` and never populates full-run caches. Runs retain manifests, per-case/stage statuses, private model journals, findings, usage and checksums. Evaluator output lives separately at `results/evaluations/<run_id>/<protocol>`.

Graph paths are candidate evidence, not verified exploits. Location-only matches are weak; unreviewed findings are unknown, not automatic false positives. Oracle reproduction and zero-hint methods belong in separate comparison panels.

## Development and migration

```bash
# Explicit opt-in: tiny local Java/CodeQL extractor fixture, no benchmark or model calls.
MAXVERA_RUN_CODEQL_FIXTURE=1 .venv/bin/python -m pytest -q tests/integration/test_pipeline_codeql_fixture.py
```

The default test suite requires no external model calls. The opt-in fixture additionally requires the retained local CodeQL 2.26.2 and Java 17 toolchains. See [validation report](docs/validation_report.md).

[Migration inventory](docs/migration_inventory.md) records the pre-edit SHA and destination of every old source/config/script/test. Existing `src` implementations are reused internally; phase/baseline shell entrypoints are deprecated compatibility commands. Historical phase runbooks have been removed from the current docs; their backups remain in the local documentation-cleanup log.

The user's cleanup request reclaimed **81.39 GiB** of old generated data. Compact tracked Phase 4 exports remain unchanged; historical raw outputs were removed and cannot be reconstructed from aggregate CSVs. See [cleanup record](docs/storage_cleanup.json) and [legacy evidence index](docs/legacy_reproduction_index.json).

Start with the [documentation index](docs/README.md). Protocol details: [reproduction](docs/reproduction_protocol.md), [research](docs/research_protocol.md), [evaluation](docs/evaluation_protocol.md). The [authoritative implementation plan](ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md) governs remaining acceptance gates.
