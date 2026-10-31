# Run report: iris-v1_gptoss20b_smoke_20261028T023424Z

Generated 2026-10-28T02:53:37Z by `iris_repro/harness/report.py`. Cohort: **smoke** (NOT official — smoke/diagnostic only). IRIS commit `67140e84e6a01da2b44803a6208be2ea7bd4bd51`, compatibility patch sha256 `af4fd0bffd9268af…`.

Independent verification: **PASS** (row mismatches: 0, aggregate mismatches: 0).

## Model / API

- Requested model `openai/gpt-oss-20b`; returned model(s) {'openai/gpt-oss-20b': 75}; provider(s) {'Groq': 75} (pinned `['groq']`, fallbacks=False, ZDR=True, data_collection=deny).
- Decoding: {'temperature': 0.0, 'top_p': 1.0, 'seed': 1234, 'max_tokens': 2048, 'reasoning_effort': 'low'}; concurrency 1.
- Preflight: ok=True, served by Groq / openai/gpt-oss-20b.
- Requests 75 (cache hits 1, HTTP retries 0, identical re-requests for empty/truncated JSON 2, responses without parseable JSON 3); tokens: prompt 78,373, completion 42,569 (reasoning 10,610); cost **$0.0182** (limit $3.0). Finish reasons: {'stop': 72, 'length': 3}.

- CodeQL: {
  "productName" : "CodeQL",
  "vendor" : "GitHub",
  "version" : "2.15.5",
  "sha" : "3accc2e1995dacca50d0740785725079…

## Paper-compatible aggregate (artifact rows)

Rows: every evaluation row of the run, including x-stream CVE-2021-21345 evaluated under CWE-094 (121 rows in a full run, matching vendor/iris-v1/results/*.csv).

| Configuration | Rows | Completed | #Detected | Detection rate | AvgFDR | AvgF1 | AvgF1 (completed only) | MicroFDR (not paper metric) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 CodeQL baseline | 4 | 4 | 1 | 25.00% | 76.92% | 0.094 | 0.094 | 76.92% |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 4 | 4 | 2 | 50.00% | 44.44% | 0.300 | 0.300 | 72.73% |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 4 | 4 | 1 | 25.00% | 50.00% | 0.250 | 0.250 | 81.82% |

Per CWE (#Detected / rows):

| Configuration | CWE-022 | CWE-078 | CWE-079 | CWE-094 |
|---|---:|---:|---:|---:|
| B0 CodeQL baseline | 1/1 | 0/1 | 0/1 | 0/1 |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 0/1 | 1/1 | 1/1 | 0/1 |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 0/1 | 1/1 | 0/1 | 0/1 |

## Canonical aggregate (120-case cohort)

Rows: the 120 canonical CWE-Bench-Java cases, each evaluated only under its dataset CWE.

| Configuration | Rows | Completed | #Detected | Detection rate | AvgFDR | AvgF1 | AvgF1 (completed only) | MicroFDR (not paper metric) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 CodeQL baseline | 4 | 4 | 1 | 25.00% | 76.92% | 0.094 | 0.094 | 76.92% |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 4 | 4 | 2 | 50.00% | 44.44% | 0.300 | 0.300 | 72.73% |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 4 | 4 | 1 | 25.00% | 50.00% | 0.250 | 0.250 | 81.82% |

Per CWE (#Detected / rows):

| Configuration | CWE-022 | CWE-078 | CWE-079 | CWE-094 |
|---|---:|---:|---:|---:|
| B0 CodeQL baseline | 1/1 | 0/1 | 0/1 | 0/1 |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 0/1 | 1/1 | 1/1 | 0/1 |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 0/1 | 1/1 | 0/1 | 0/1 |

## Comparison with IRIS Table 1 (reference values, not targets)

| Method | Policy | Detected | AvgFDR | AvgF1 | Paper method | Paper Detected/120 | Paper AvgFDR | Paper AvgF1 |
|---|---|---:|---:|---:|---|---:|---:|---:|
| CodeQL | artifact_compatible | 1/4 | 76.92% | 0.094 | CodeQL | 27 | 90.03% | 0.076 |
| CodeQL | dataset_canonical | 1/4 | 76.92% | 0.094 | CodeQL | 27 | 90.03% | 0.076 |
| IRIS (filtered) | artifact_compatible | 1/4 | 50.00% | 0.250 | IRIS + GPT-4 | 55 | 84.82% | 0.177 |
| IRIS (filtered) | dataset_canonical | 1/4 | 50.00% | 0.250 | IRIS + GPT-4 | 55 | 84.82% | 0.177 |

Metric calibration on the original artifact CSVs (same formulas):

- CodeQL: 121 rows → 27 detected, AvgFDR 90.04%, AvgF1 0.076; canonical 120 rows → 27, 90.04%, 0.077. Paper: 27, 90.03%, 0.076.
- IRIS + GPT-4: 121 rows → 55 detected, AvgFDR 84.94%, AvgF1 0.177; canonical 120 rows → 54, 84.84%, 0.178. Paper: 55, 84.82%, 0.177.

## Operational metrics

- source_acquisition_success: 4/4 (100.00%)
- build_and_codeql_db_success: 4/4 (100.00%)
- b0_codeql_analysis_success: 4/4 (100.00%)
- b2_candidate_extraction_success: 4/4 (100.00%)
- b2_spec_generation_success: 4/4 (100.00%)
- b2_query_generation_success: 4/4 (100.00%)
- b2_codeql_query_compile_and_run_success: 4/4 (100.00%)
- b2_contextual_analysis_success: 4/4 (100.00%)
- b2_end_to_end_success: 4/4 (100.00%)
- Runtime (s): {'b0': {'n': 4, 'total': 241.5, 'mean': 60.375, 'max': 72.0}, 'b2': {'n': 4, 'total': 559.6, 'mean': 139.9, 'max': 151.5}}
- Failure causes: none
- B2 (filtered) miss causes among completed rows: {'no CodeQL alerts with inferred specifications': 2, 'true-positive path removed by contextual filtering': 1}
- Structurally undetectable cases in cohort (no evaluable fixed method): 0

## Artifacts

- `status/execution_status.csv` — per-row execution status (source, DB, B0, B2)
- `cases/<eval_id>/{b0,b2}.json` — commands, exit codes, stage flags, artifact paths + sha256, evaluator output, LLM usage
- `metrics/project_metrics.csv`, `metrics/per_cwe_results.csv`, `metrics/raw_vs_filtered.csv`
- `metrics/metrics_artifact_compatible.json`, `metrics/metrics_dataset_canonical.json`, `metrics/verification.json`
- `metrics/token_cost_report.json`, `metrics/token_cost_by_project.csv`, `metrics/operational_metrics.json`
- `manifests/` — environment, model/API (no secrets), preflight, dataset manifest snapshot
- IRIS per-project outputs (specs, generated .qll, SARIF): `vendor/iris-v1/output/<slug>/<run_id>[-b0]/`
