# Run report: iris-v1_gptoss20b_full_20261028T025416Z

Generated 2026-10-31T06:29:22Z by `iris_repro/harness/report.py`. Cohort: **full** (official). IRIS commit `67140e84e6a01da2b44803a6208be2ea7bd4bd51`, compatibility patch sha256 `3cd099b04364777f…`.

Independent verification: **PASS** (row mismatches: 0, aggregate mismatches: 0).

## Model / API

- Requested model `openai/gpt-oss-20b`; returned model(s) {'openai/gpt-oss-20b': 18992}; provider(s) {'Groq': 18992} (pinned `['groq']`, fallbacks=False, ZDR=True, data_collection=deny).
- Decoding: {'temperature': 0.0, 'top_p': 1.0, 'seed': 1234, 'max_tokens': 2048, 'reasoning_effort': 'low'}; concurrency 1.
- Preflight: ok=True, served by Groq / openai/gpt-oss-20b.
- Requests 18992 (cache hits 2027, HTTP retries 253, identical re-requests for empty/truncated JSON 374, responses without parseable JSON 572); tokens: prompt 20,233,369, completion 7,084,780 (reasoning 1,851,328); cost **$3.3756** (limit $40.0). Finish reasons: {'stop': 18424, 'length': 568}.

- CodeQL: {
  "productName" : "CodeQL",
  "vendor" : "GitHub",
  "version" : "2.15.5",
  "sha" : "3accc2e1995dacca50d0740785725079…

## Paper-compatible aggregate (artifact rows)

Rows: every evaluation row of the run, including x-stream CVE-2021-21345 evaluated under CWE-094 (121 rows in a full run, matching vendor/iris-v1/results/*.csv).

| Configuration | Rows | Completed | #Detected | Detection rate | AvgFDR | AvgF1 | AvgF1 (completed only) | MicroFDR (not paper metric) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 CodeQL baseline | 121 | 112 | 27 | 22.31% | 89.44% | 0.075 | 0.081 | 91.48% |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 121 | 109 | 44 | 36.36% | 91.37% | 0.099 | 0.110 | 95.94% |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 121 | 109 | 32 | 26.45% | 96.79% | 0.043 | 0.048 | 99.09% |

Per CWE (#Detected / rows):

| Configuration | CWE-022 | CWE-078 | CWE-079 | CWE-094 |
|---|---:|---:|---:|---:|
| B0 CodeQL baseline | 22/55 | 1/13 | 4/31 | 0/22 |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 29/55 | 0/13 | 8/31 | 7/22 |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 25/55 | 0/13 | 5/31 | 2/22 |

B2 rows not completed (12): `apache__activemq_CVE-2014-3576_5.10.2`, `apache__camel_CVE-2018-8041_2.20.3`, `apache__camel_CVE-2019-0194_2.21.4`, `apache__nifi_CVE-2022-33140_1.16.2`, `asf__james-project_CVE-2022-22931_3.6.0`, `asf__nifi_CVE-2023-34468_1.21.0`, `asf__nifi_CVE-2023-36542_1.22.0`, `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE`, `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2`, `testng-team__testng_CVE-2022-4065_7.5`, `x-stream__xstream_CVE-2020-26217_1.4.14-java7`, `xwiki__xwiki-commons_CVE-2022-24897_12.6.6`

B0 rows not completed (9): `apache__activemq_CVE-2014-3576_5.10.2`, `apache__camel_CVE-2018-8041_2.20.3`, `apache__camel_CVE-2019-0194_2.21.4`, `asf__james-project_CVE-2022-22931_3.6.0`, `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE`, `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2`, `testng-team__testng_CVE-2022-4065_7.5`, `x-stream__xstream_CVE-2020-26217_1.4.14-java7`, `xwiki__xwiki-commons_CVE-2022-24897_12.6.6`

## Canonical aggregate (120-case cohort)

Rows: the 120 canonical CWE-Bench-Java cases, each evaluated only under its dataset CWE.

| Configuration | Rows | Completed | #Detected | Detection rate | AvgFDR | AvgF1 | AvgF1 (completed only) | MicroFDR (not paper metric) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 CodeQL baseline | 120 | 111 | 27 | 22.50% | 89.44% | 0.076 | 0.082 | 91.48% |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 120 | 108 | 43 | 35.83% | 91.32% | 0.099 | 0.110 | 95.94% |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 120 | 108 | 32 | 26.67% | 96.76% | 0.044 | 0.049 | 99.09% |

Per CWE (#Detected / rows):

| Configuration | CWE-022 | CWE-078 | CWE-079 | CWE-094 |
|---|---:|---:|---:|---:|
| B0 CodeQL baseline | 22/55 | 1/13 | 4/31 | 0/21 |
| B2 IRIS+GPT-OSS-20B (before contextual filtering) | 29/55 | 0/13 | 8/31 | 6/21 |
| B2 IRIS+GPT-OSS-20B (after contextual filtering) | 25/55 | 0/13 | 5/31 | 2/21 |

B2 rows not completed (12): `apache__activemq_CVE-2014-3576_5.10.2`, `apache__camel_CVE-2018-8041_2.20.3`, `apache__camel_CVE-2019-0194_2.21.4`, `apache__nifi_CVE-2022-33140_1.16.2`, `asf__james-project_CVE-2022-22931_3.6.0`, `asf__nifi_CVE-2023-34468_1.21.0`, `asf__nifi_CVE-2023-36542_1.22.0`, `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE`, `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2`, `testng-team__testng_CVE-2022-4065_7.5`, `x-stream__xstream_CVE-2020-26217_1.4.14-java7`, `xwiki__xwiki-commons_CVE-2022-24897_12.6.6`

B0 rows not completed (9): `apache__activemq_CVE-2014-3576_5.10.2`, `apache__camel_CVE-2018-8041_2.20.3`, `apache__camel_CVE-2019-0194_2.21.4`, `asf__james-project_CVE-2022-22931_3.6.0`, `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE`, `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2`, `testng-team__testng_CVE-2022-4065_7.5`, `x-stream__xstream_CVE-2020-26217_1.4.14-java7`, `xwiki__xwiki-commons_CVE-2022-24897_12.6.6`

## Comparison with IRIS Table 1 (reference values, not targets)

| Method | Policy | Detected | AvgFDR | AvgF1 | Paper method | Paper Detected/120 | Paper AvgFDR | Paper AvgF1 |
|---|---|---:|---:|---:|---|---:|---:|---:|
| CodeQL | artifact_compatible | 27/121 | 89.44% | 0.075 | CodeQL | 27 | 90.03% | 0.076 |
| CodeQL | dataset_canonical | 27/120 | 89.44% | 0.076 | CodeQL | 27 | 90.03% | 0.076 |
| IRIS (filtered) | artifact_compatible | 32/121 | 96.79% | 0.043 | IRIS + GPT-4 | 55 | 84.82% | 0.177 |
| IRIS (filtered) | dataset_canonical | 32/120 | 96.76% | 0.044 | IRIS + GPT-4 | 55 | 84.82% | 0.177 |

Metric calibration on the original artifact CSVs (same formulas):

- CodeQL: 121 rows → 27 detected, AvgFDR 90.04%, AvgF1 0.076; canonical 120 rows → 27, 90.04%, 0.077. Paper: 27, 90.03%, 0.076.
- IRIS + GPT-4: 121 rows → 55 detected, AvgFDR 84.94%, AvgF1 0.177; canonical 120 rows → 54, 84.84%, 0.178. Paper: 55, 84.82%, 0.177.

## Operational metrics

- source_acquisition_success: 120/120 (100.00%)
- build_and_codeql_db_success: 111/120 (92.50%)
- b0_codeql_analysis_success: 112/121 (92.56%)
- b2_candidate_extraction_success: 112/121 (92.56%)
- b2_spec_generation_success: 112/121 (92.56%)
- b2_query_generation_success: 112/121 (92.56%)
- b2_codeql_query_compile_and_run_success: 109/121 (90.08%)
- b2_contextual_analysis_success: 109/121 (90.08%)
- b2_end_to_end_success: 109/121 (90.08%)
- Runtime (s): {'b0': {'n': 112, 'total': 20583.200000000004, 'mean': 183.77857142857147, 'max': 1940.3}, 'b2': {'n': 109, 'total': 86169.8, 'mean': 790.548623853211, 'max': 15184.1}}
- Failure causes: {'b2:failed:codeql_analysis': 3, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/apache__activemq_CVE-2014-3576_5.10.2', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/apache__activemq_CVE-2014-3576_5.10.2', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/apache__camel_CVE-2018-8041_2.20.3', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/apache__camel_CVE-2018-8041_2.20.3', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/apache__camel_CVE-2019-0194_2.21.4', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/apache__camel_CVE-2019-0194_2.21.4', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/asf__james-project_CVE-2022-22931_3.6.0', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/asf__james-project_CVE-2022-22931_3.6.0', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/testng-team__testng_CVE-2022-4065_7.5', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/testng-team__testng_CVE-2022-4065_7.5', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/x-stream__xstream_CVE-2020-26217_1.4.14-java7', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/x-stream__xstream_CVE-2020-26217_1.4.14-java7', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1, "db:CalledProcessError: Command '['codeql', 'database', 'create', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/codeql-dbs/xwiki__xwiki-commons_CVE-2022-24897_12.6.6', '--source-root', '/home/khanhtg/Documents/MaxVera/vendor/iris-v1/data/cwe-bench-java/project-sources/xwiki__xwiki-commons_CVE-2022-24897_12.6.6', '--language', 'java', '--overwrite']' returned non-zero exit status 2.": 1}
- B2 (filtered) miss causes among completed rows: {'alerts found but no path through a fixed method': 43, 'true-positive path removed by contextual filtering': 12, 'no CodeQL alerts with inferred specifications': 11, 'no evaluable fixed method in fix_info.csv (undetectable under evaluator)': 11}
- Structurally undetectable cases in cohort (no evaluable fixed method): 13

## Artifacts

- `status/execution_status.csv` — per-row execution status (source, DB, B0, B2)
- `cases/<eval_id>/{b0,b2}.json` — commands, exit codes, stage flags, artifact paths + sha256, evaluator output, LLM usage
- `metrics/project_metrics.csv`, `metrics/per_cwe_results.csv`, `metrics/raw_vs_filtered.csv`
- `metrics/metrics_artifact_compatible.json`, `metrics/metrics_dataset_canonical.json`, `metrics/verification.json`
- `metrics/token_cost_report.json`, `metrics/token_cost_by_project.csv`, `metrics/operational_metrics.json`
- `manifests/` — environment, model/API (no secrets), preflight, dataset manifest snapshot
- IRIS per-project outputs (specs, generated .qll, SARIF): `vendor/iris-v1/output/<slug>/<run_id>[-b0]/`
