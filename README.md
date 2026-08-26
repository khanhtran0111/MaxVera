# MaxVera

MaxVera is a reproducible research scaffold for graph-grounded, zero-hint,
repository-level vulnerability discovery in Java. The analysis pipeline uses
CodeQL for static verification and a local Qwen2.5-Coder-3B-Instruct GGUF model
for bounded, evidence-grounded reasoning.

Phase 0 (the frozen research protocol) and Phase 1 (repository, environment,
and provenance) are implemented. Dataset acquisition and analysis execution
start in Phase 2; the numbered baseline entrypoints deliberately refuse to run
until their implementation phases are complete.

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

The stricter full-analysis check also inspects Java toolchains, Maven, Gradle,
CodeQL, llama.cpp, the Qwen model file, and the optional NVIDIA GPU:

```bash
bash scripts/tools/preflight.sh --profile full
```

It reports missing variable **names**, never their values. Put machine-specific
paths or secrets only in `.env`; reproducible non-secret settings belong under
`configs/`.

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
- Generated data, models, databases, caches, secrets, and experiment results
  are ignored by Git.
- Every future run must carry an immutable manifest, environment report,
  project statuses, logs, and checksums.

The source implementation plan is
[`ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md`](ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md).
