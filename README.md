# MaxVera

MaxVera is a reproducible research scaffold for graph-grounded, zero-hint,
repository-level vulnerability discovery in Java. The analysis pipeline uses
CodeQL for static verification and `openai/gpt-oss-20b` through a pinned
OpenRouter provider route for bounded, evidence-grounded reasoning.

Phase 0 (protocol), Phase 1 (environment/provenance), Phase 2 (data/build),
Phase 3 (disposable smoke harness), and the Phase 4 reproduction runner are implemented.
The frozen 120-row release has 120 final build statuses and 104 successful
CodeQL databases. Phase 4 enables numbered entrypoints B0-B2; B3-B9 remain
disabled until their implementation phases. Every entrypoint fails closed if
any smoke artifact remains.

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
bash scripts/tools/validate_openrouter.sh
make setup-phase4
make phase4-pilot
```

Set `OPENROUTER_API_KEY` by editing `.env` directly; do not paste the real key
into shell history. The Phase 4 runner reuses the 104
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
