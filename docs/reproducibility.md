# Reproducibility

Install the orchestration environment with:

```bash
uv sync --extra dev
```

Bootstrap all Phase 0 upstream sources from the commits declared in the
versioned dataset and toolchain configs:

```bash
uv run python scripts/data/bootstrap_upstream.py
```

This creates three detached, clean checkouts without resolving a branch or tag:

- CWE-Bench-Java legacy at `698fb7248ae30cb7f7782d59c841f05ad70ea9cc`;
- the IRIS v2 dataset snapshot at `3a12f45750f58135bcc58c7fdf4c20786b600e31`;
- IRIS v1 at `7aa94755d43898a623307935e853b954afc79a5d`.

Running the command again is idempotent when origin, detached `HEAD`, and the
clean worktree all match. It refuses a mismatched checkout, a dirty checkout,
or a nonempty directory that is not the expected Git repository; it never
deletes or replaces those directories.

Inspect the host and frozen upstream checkouts:

```bash
uv run openiris-doctor --config configs/toolchain/phase0.yaml
```

Prepare dataset manifests, inventory reports, runtime/ground-truth boundaries,
and deterministic split manifests:

```bash
uv run python scripts/data/prepare_phase0.py
```

Runs are append-only directories under `runs/<run_id>/`. A completed run has a
manifest, resolved config, environment capture, metrics, usage log, and error
log. A failed run is retained for audit and never silently dropped.

See `results/phases/phase_00/report.md` for the exact commands and current gate status.
