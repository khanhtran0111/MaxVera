# Phase 0 execution report

> This frozen report records the completed legacy CodeQL + IRIS smoke. Running the revised canonical notebook adds the primary Qwen 3B Q4_K_M CUDA smoke and regenerates `status.json`/`report.md` on the experimental machine.

Generated: `2026-08-23T14:20:20.608340Z`
Status: **SMOKE_PASS**

`SMOKE_PASS` means the reproducible single-project CodeQL and IRIS paths work. It does not mean that the 120-case paper baseline has been rerun.

## Frozen datasets

| Track | Commit | Instances | Repositories | Raw CWE labels | Semantic CWEs |
|---|---|---:|---:|---:|---:|
| legacy | `698fb7248ae3` | 120 | 77 | 4 | 4 |
| v2 | `3a12f45750f5` | 213 | 135 | 49 | 45 |

Build-success counts in the inventory reproduce upstream metadata; they are not local build results.

## Gate checks

| Check | Status |
|---|---|
| `frozen_legacy_and_v2_snapshots` | PASS |
| `runtime_ground_truth_boundary_materialized` | PASS |
| `toolchain_ready_for_smoke` | PASS |
| `evaluator_implementation_and_regressions_present` | PASS |
| `published_reference_alignment_understood` | PASS |
| `local_codeql_smoke_complete` | PASS |
| `local_codeql_smoke_matches_published_case` | PASS |
| `local_iris_configuration_complete` | PASS |
| `local_iris_token_usage_accounted` | PASS |
| `paper_scale_local_build_coverage` | PENDING |
| `paper_scale_codeql_baseline_complete` | PENDING |

## Local execution scope

- CodeQL: 1/1 complete records.
- IRIS: 1/1 complete records.
- IRIS token usage: 44,970 prompt + 46,053 completion = 91,023 tokens (post-hoc pinned-tokenizer receipt).
- Locally exercised projects: 1/120 legacy cases.

| Baseline | Run | Status | Project | Paths | Recall@method | Runtime (s) |
|---|---|---|---|---:|---|---:|
| codeql | `phase0_codeql_smoke_local_001` | COMPLETE | `testng-team__testng_CVE-2022-4065_7.5` | 36 | True | 1557.4 |
| iris | `phase0_iris_qwen15b_local_001` | COMPLETE | `testng-team__testng_CVE-2022-4065_7.5` | 45 | True | 1427.0 |

## Declared limitations

- The local scope is a reproducibility smoke, not the 120-case paper rerun; paper-scale checks stay pending until local evidence reaches their thresholds.
- Upstream build-success metadata is inventory evidence only and is never reported as local build coverage.
- Pinned IRIS v1 requires an oracle CWE query, a semantic project slug, and evaluator fix metadata. This is the declared `iris-v1-oracle-interface` compatibility exception, not a zero-hint run.
- The legacy IRIS Qwen 1.5B smoke follows upstream FP16 loading and effective temperature 0.01 with sampling disabled; the configured 4-bit field is retained as an unforwarded request, not claimed as the executed precision.
- The upstream local-model path emits no counters. Zeroes in the immutable run usage stream are explicit sentinels; `results/phases/phase_00/audits/iris_qwen15b_token_usage.json` contains the audited post-hoc count.

## Published comparison references

The files under `results/phases/phase_00/baselines/published_reference/` are imported from the pinned IRIS commit. They are never counted as local reruns.

| Source | Published rows | Published detected | Frozen-pair rows | Frozen-pair detected | Source commit |
|---|---:|---:|---:|---:|---|
| codeql | 121 | 27 | 120 | 27 | `7aa94755d438` |
| iris_gpt4 | 121 | 55 | 120 | 54 | `7aa94755d438` |
| iris_qwen_32b | 121 | 47 | 120 | 47 | `7aa94755d438` |

The pinned tables contain 121 project-CWE evaluation rows over 120 distinct projects. They cover all 120 frozen `(CVE, CWE)` pairs.
The sole additional published evaluation is `CVE-2021-21345::CWE-094`: the same x-stream 1.4.15 project is evaluated as CWE-094 in addition to its frozen CWE-078 label. Published files remain verbatim; paper-scale denominators use the frozen 120 pairs.

## Reproduce

```powershell
uv sync --extra dev --locked
uv run python scripts/data/bootstrap_upstream.py
uv run python scripts/data/prepare_phase0.py
uv run python scripts/toolchain/fetch_codeql.py
docker build --platform linux/amd64 -t maxvera-phase0:jdk17 docker/phase0
docker build --platform linux/amd64 -f docker/phase0/Dockerfile.codeql -t maxvera-phase0:codeql tools/downloads
docker build --platform linux/amd64 -f docker/phase0/Dockerfile.iris -t maxvera-phase0:iris-local docker/phase0
uv run openiris-doctor --config configs/toolchain/phase0.yaml --strict
uv run pytest
uv run python scripts/phase0.py
```

Use the append-only CodeQL and IRIS commands in `README.md` to create new local baseline records; every rerun needs fresh run IDs.
