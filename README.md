# MaxVera

Pipeline-first Java vulnerability research with two separate tracks:

1. **reproduce**: pinned IRIS v1 with oracle CWE and GPT-OSS-20B through OpenRouter, plus an independent CodeQL reference.
2. **research**: zero-hint static/graph candidate discovery with opaque inputs and an OS filesystem firewall.
3. **evaluate / compare**: independent evaluation of immutable raw output; labels stay outside research.

**Full-cohort inputs are ready: 120/120 verified source snapshots and build recipes.** The [full research runbook](docs/research_full_runbook_2026-10-24.md) uses the corrected tracked-source view and separates execution readiness from truth evaluability and scientific approval. An independent Git audit covers all 120 cases without missing Java/build inputs. Builds across the benchmark remain unproven. Truth aligns for 6/120 cases, so whole-cohort recall remains unavailable and scientific acceptance remains NO-GO. Full LLM execution supports a prospective exploratory protocol after actual paired development measurements; it keeps graph approval false. See the [enablement report](docs/research_full_enablement_2026-10-24.md) and the unchanged [confirmatory pilot criteria](docs/research_pilot_acceptance_2026-10-24.md).

The [actual fixed10 pilot results from 25 October](docs/research_pilot_result_2026-10-25.md) retain all ten cases in both variants: static completes seven, graph completes six, and both runs end with case failures. Evaluations share the same condition and compare successfully; evaluable-subset strong discovery Recall@5 is 2/6 for static and 1/6 for graph. Engineering acceptance remains false, and this pilot does not execute LLM or targeted verification.

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

# Versioned preparation preserves the existing frozen release and snapshots.
python -m maxvera dataset prepare --config configs/datasets/cwe_bench_extended.yaml --sources --view full_20261024_v2 --fetch-timeout 900
python -m maxvera preflight --config configs/pipelines/research_full120_execution.yaml --variant graph_only --mode full --require execution

# Reproduction: begin with 1–2 cases; hosted-model calls require existing .env credentials.
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode smoke --limit 2 --run-id repro_smoke_001 --execute
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode full --run-id repro_gptoss20b_001 --execute
python -m maxvera pipeline reproduce --config configs/pipelines/reproduce.yaml --mode full --run-id repro_gptoss20b_001 --resume --execute

# Research: the default is the existing frozen 96-project development split.
python -m maxvera preflight --config configs/pipelines/research.yaml --variant graph_only --mode full
python -m maxvera preflight --config configs/pipelines/research_pilot10.yaml --variant graph_only --mode full
python -m maxvera preflight --config configs/pipelines/research_full120.yaml --variant graph_only --mode full
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode smoke --limit 2 --run-id graph_smoke_001 --execute
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant static_only --mode full --run-id zh_static_001 --execute
python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode full --run-id zh_graph_001 --execute
```

A new run ID cannot overwrite an existing run. Full mode rejects `--limit` and accounts for every selected case. `--resume` requires matching source/code/tool/config/schema fingerprints and verified checkpoints. Paid stages interrupted at an uncertain remote-call boundary stop for journal inspection instead of repeating charges automatically.

Research execution checks every selected source, build recipe and preparation manifest before tool/model work. `preflight` additionally reports evaluator truth coverage and experiment gates. `research.yaml` selects 96 development cases, `research_pilot10.yaml` selects ten frozen development IDs, and `research_full120.yaml` selects exactly 120; `full` means the complete configured cohort. A frozen run's `quality_report.json` accounts separately for reasoning, endpoint evidence, traversal limits and verification coverage.

```bash
# These CLI handlers are tested on temporary frozen fixture runs; real run IDs must exist.
python -m maxvera status --run-id repro_gptoss20b_001
python -m maxvera evaluate --run-id repro_gptoss20b_001 --protocol iris_paper
python -m maxvera evaluate --run-id repro_gptoss20b_001 --protocol paper_formula_path
python -m maxvera evaluate --run-id zh_graph_001 --protocol zero_hint
python -m maxvera compare --runs zh_static_001,zh_graph_001 --output results/aggregate/graph_discovery_comparison
```

`graph_llm` and `graph_llm_verify` support smoke runs of at most two cases. Full LLM runs use either the reviewed-signal policy or an explicit `--experiment-protocol` registered prospectively from real paired pilot measurements. Registration freezes input/code/tool/model/config identity, preserves unknown truth, and grants no scientific approval. The [runbook](docs/research_full_runbook_2026-10-24.md) documents registration and full execution/resume. `text_only` remains `NOT_IMPLEMENTED`. Earlier engineering smokes are historical evidence; the [GO report](docs/research_go_execution_2026-10-24.md) records smoke02's repaired endpoint verification separately from scientific recall.

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

[Migration inventory](docs/migration_inventory.md) records the pre-edit SHA and destination of every old source/config/script/test. Existing `src` implementations are reused internally; phase/baseline shell entrypoints are deprecated compatibility commands. Historical phase runbooks and their old log backups have been removed.

Earlier cleanup records describe historical storage recovery. The 23 October request also removed all previous run outputs/logs, tracked Phase 4 exports and superseded smoke attempts. Only the current r3 smoke and its audit remain; this task removed another **3.51 GiB**, with approximately **300.30 GiB free**. See the [current report](docs/research_smoke_2026-10-23.md). Deleted raw evidence cannot support new reproduction claims.

Start with the [documentation index](docs/README.md). Protocol details: [reproduction](docs/reproduction_protocol.md), [research](docs/research_protocol.md), [evaluation](docs/evaluation_protocol.md). The [authoritative implementation plan](ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md) governs remaining acceptance gates.
