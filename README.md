# MaxVera

Project state and phase handoff memory:
[`PROJECT_MEMORY.md`](PROJECT_MEMORY.md).

MaxVera is a reproducible research scaffold for graph-grounded, zero-hint,
repository-level vulnerability discovery in Java. The analysis pipeline uses
CodeQL for static verification and `openai/gpt-oss-20b` through a pinned
OpenRouter provider route for bounded, evidence-grounded reasoning.

Phase 0 (protocol), Phase 1 (environment/provenance), Phase 2 (data/build),
Phase 3 (disposable smoke harness), the Phase 4 reproduction runner, and the
immediately runnable Phase 5 context baselines B3-B5 are implemented.
The Phase 6 development-only hypothesis generator is locked at static
family-balanced v2 with Top-k=10; optional GPT-OSS reranking is exploratory; see
[`docs/11_PHASE6_RUNBOOK.md`](docs/11_PHASE6_RUNBOOK.md).
The Phase 7 CodeQL program graph is locked at canonical development run
`p7_pg_dev_full_004` with 81/96 successful graphs and 15 recorded
intention-to-analyze misses; its extractor, integrity validator, and
neighborhood/slice query CLI are documented in
[`docs/12_PHASE7_RUNBOOK.md`](docs/12_PHASE7_RUNBOOK.md).
Phase 8 implements a global, versioned Security Knowledge Graph from pinned
MITRE CWE 4.20, OWASP Top 10:2021 and CodeQL Java API semantics. It separates
deterministic and inferred facts, requires per-fact provenance/confidence, runs
offline with zero LLM calls, and is documented in
[`docs/13_PHASE8_RUNBOOK.md`](docs/13_PHASE8_RUNBOOK.md).
Canonical development run `p8_skg_global_full_002`, built from clean commit
`50ed53e`, contains 2,619 nodes and 5,285 edges (7,904 deterministic facts).
Its graph digest matches the final pilot and dirty-tree diagnostic full 001;
source, dependency, provenance, checksum and per-CWE audit gates all pass.
Phase 9 implements the iteration-0 Evidence Graph/USEG that joins locked Phase 6
hypotheses, Phase 7 source-backed Program nodes, and Phase 8 Security facts while
keeping confidence components and provenance separate. Run
`p9_useg_dev_full_003`, built from clean commit `2395d21`, is the locked
canonical development run. It covers all 96 statuses (81 graphs and 15
inherited misses), with 7,527 nodes, 16,398 edges, 823/823 candidate taint paths
traceable across Program and Security layers, zero cycles, and lossless JSONL
round-trip. See [`docs/14_PHASE9_RUNBOOK.md`](docs/14_PHASE9_RUNBOOK.md).
Phase 10 implements and locks B6/B7/B8 graph retrieval and the synthesis-only
portion of B9. The canonical full development runs are
`p10_b6_dev_full_001` through `p10_b9_dev_full_001`; B9 emits 801/806 grounded
specifications for the 81 usable Phase 9 projects and all 801 final templates
compile. The separate evaluator-only annotated gate
`p10_dev_spec_eval_003` reports paper-compatible fix-location proxy metrics on
91 development projects without modifying the immutable synthesis artifacts.
These metrics are not static verification. Outputs remain
`SYNTHESIZED_UNVERIFIED`; see
[`docs/15_PHASE10_RUNBOOK.md`](docs/15_PHASE10_RUNBOOK.md).
Phase 11 is implemented as deterministic CodeQL global-taint verification. It
records endpoint resolution, SARIF taint paths, explicit negative evidence and
an acyclic USEG iteration-1 delta. Vulnerable-only results remain unverified;
only vulnerable-path/fixed-no-path differential results may be verified. The
locked development run `p11_diff_dev_full_002` covers all 96 projects, retains
18 inherited analysis misses, and produces 28 `VERIFIED_DIFFERENTIAL` plus 748
explicit unverified specification states with zero LLM calls. See
[`docs/16_PHASE11_RUNBOOK.md`](docs/16_PHASE11_RUNBOOK.md).
The frozen 120-row release has 120 final build statuses and 104 successful
CodeQL databases. Phase 4 provides B0-B2 results. Phase 5 enables B3 raw
context, B4 text-RAG, and B5 static hypotheses. B6-B8 and B9 synthesis are
locked for development; Phase 11 differential findings are locked as Phase 12
input, while final routed decisions remain fail-closed until calibration is
locked.
Phase 12 implements development-only grouped calibration over differential
findings, compares Platt/isotonic/logistic models, reports ECE/Brier/AURC and
materializes `ACCEPT`/`VERIFY`/`ABSTAIN` without treating abstention as a
negative. Canonical run `p12_calibration_dev_full_001` locks Platt calibration
and fail-closed thresholds for Phase 13: zero `ACCEPT`, 25 `VERIFY`, and 3
`ABSTAIN`. See [`docs/17_PHASE12_RUNBOOK.md`](docs/17_PHASE12_RUNBOOK.md).
Every entrypoint fails closed if any smoke artifact remains.

## Bootstrap

Prerequisites for the Phase 1 profile are Git, Bash, `curl`, and enough disk
and memory for the research workload. The setup script installs the pinned
Python environment and creates a local, ignored `.env` when needed.

```bash
bash scripts/tools/setup_environment.sh
bash scripts/tools/preflight.sh --profile phase1
```

Run the quality gate:

```bash
uv run --frozen pytest
uv run --frozen ruff check .
uv run --frozen mypy src
```

Materialize and validate Phase 2:

```bash
make phase2-data
make phase2-build       # requires pinned JDK 7u80, 8u202, 17 and CodeQL
make phase2-validate
```

`phase2-validate` intentionally fails while any project remains `PENDING` or a
successful build lacks its CodeQL database. See `docs/02_DATA_CARD.md` for the
split, checksums, leakage boundary, and pinned-extended snapshot caveat.

The Phase 3 smoke profile checks the disposable technical harness:

```bash
bash scripts/tools/preflight.sh --profile full
```

It reports missing variable **names**, never their values. Put machine-specific
paths or secrets only in `.env`; reproducible non-secret settings belong under
`configs/`.

Install the pinned Phase 3 dependencies and run the pass/failure cleanup gate:

```bash
make setup-phase3
make phase3-smoke
```

The smoke command exercises a disposable endpoint contract, strict candidate JSON,
four Java CodeQL databases, SARIF parsing, and the separate evaluator. It then
injects a failure after analysis. Both paths must end with zero files under the
smoke output allowlist; no smoke finding is retained or reusable.

Prepare Phase 4 and run a one-project pilot:

```bash
bash scripts/tools/preflight.sh --profile phase4
bash scripts/tools/validate_openrouter.sh \
  --model-config configs/models/gpt_oss_20b_openrouter_groq.yaml
make setup-phase4
make phase4-pilot
```

Set `OPENROUTER_API_KEY` by editing `.env` directly; do not paste the real key
into shell history. A historical Phase 4 rerun also requires temporarily setting
`MAXVERA_OPENROUTER_PROVIDER=groq`; Phase 5 uses `akashml`. The Phase 4 runner reuses the 104
Phase 2 databases, calls GPT-OSS 20B through OpenRouter, and records both the
CodeQL and hosted-model substitutions explicitly. See
`docs/05_REPRODUCTION_REPORT.md` for its outputs and validation gate.

## Phase 4 reproduction baselines

Phase 4 compares three conditions on the same frozen 120-project release. The
104 projects with a successful Phase 2 CodeQL database are selected for
analysis; the remaining build/database failures stay in the 120-row metrics as
misses.

| Baseline | Condition | CWE ground truth available to analyzer | LLM |
|---|---|---:|---:|
| **B0** | CodeQL zero-hint reference | No | No |
| **B1** | CodeQL CWE-oracle reference | Yes | No |
| **B2** | IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter | Yes | Yes |

- **B0** runs the zero-hint CodeQL reference without providing CVE/CWE labels.
- **B1** receives the known CWE for query selection, so it is an oracle
  reference rather than a zero-hint condition.
- **B2** reproduces the IRIS stages with the known CWE and replaces the paper's
  model with pinned `openai/gpt-oss-20b`/OpenRouter inference. It is a
  method-reproduction condition, not an exact-model or zero-hint baseline.

Run `phase4_gptoss20b_full_001` produced canonical metrics for all 120 statuses:
B0 completed 104 analyses and detected 36 projects; B1 completed 104 and
detected 21; B2 completed 99, recorded 5 analysis failures, and detected 36.
Failures remain explicit misses. The B2 strict all-selected-success gate is
therefore not passed, even though the independently recomputed metrics and
checksums are complete.

The curated export is indexed at
[`results/reproduction/phase4_gptoss20b_full_001__README.md`](results/reproduction/phase4_gptoss20b_full_001__README.md),
with the cross-baseline table at
[`results/reproduction/phase4_gptoss20b_full_001__table_reproduction.csv`](results/reproduction/phase4_gptoss20b_full_001__table_reproduction.csv).

## Phase 5 controlled context baselines

B3-B5 use the frozen `D_repro_v1` analysis view so they can be evaluated beside
the completed Phase 4 release without rebuilding or exposing evaluator labels.
B3 and B4 share the same prompt, GPT-OSS 20B route, schema and protocol caps;
the OpenRouter provider is pinned to `akashml`, and only context selection
differs. B5 is deterministic and does not call an API. The completed Phase 4
artifact remains the historical protocol 1.1.1/Groq snapshot and is not
provider-controlled against the new Phase 5 runs.

No Phase 5 baseline execution contacts OpenRouter unless
`--confirm-api-spend` is supplied. The optional connection validator makes one
small billed request.
Estimate the token/cost envelope offline and follow the pilot-to-full sequence:

```bash
bash scripts/tools/estimate_phase5_budget.sh
bash scripts/04_run_b3_raw_context_gptoss20b.sh \
  --mode pilot --limit 1 --dry-run --run-id p5_b3_dry_001
```

See [`docs/10_PHASE5_RUNBOOK.md`](docs/10_PHASE5_RUNBOOK.md) for the complete
execution, evaluator and validation commands.

## Frozen protocol

Read these files before changing research code or configuration:

- [`docs/00_RESEARCH_SCOPE.md`](docs/00_RESEARCH_SCOPE.md)
- [`docs/01_EXPERIMENT_PROTOCOL.md`](docs/01_EXPERIMENT_PROTOCOL.md)
- [`docs/07_DECISION_LOG.md`](docs/07_DECISION_LOG.md)

Any change to research questions, datasets, splits, budgets, metrics, model,
tool versions, or thresholds requires a decision-log entry and a new protocol
version. `data/raw/` is immutable, test labels are evaluator-only, smoke output
cannot be promoted, and full results are never overwritten.

## Repository policy

- `scripts/` contains exactly the ten numbered B0-B9 entrypoints.
- Supporting automation lives only in `scripts/tools/`.
- Generated data, models, databases, caches, secrets, and raw experiment
  artifacts are ignored by Git. Only explicitly allowlisted compact result
  exports are versioned.
- Every future run must carry an immutable manifest, environment report,
  project statuses, logs, and checksums.

The source implementation plan is
[`ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md`](ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md).
