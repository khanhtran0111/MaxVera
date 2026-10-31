# IRIS (ICLR 2025) reproduction with GPT-OSS 20B — reproduction report

**Status (2026-10-28):** the environment, dataset pipeline, OpenRouter integration and evaluation
chain are implemented and validated end-to-end on a 4-case smoke cohort. The official full run
`iris-v1_gptoss20b_full_20261028T025416Z` (121 evaluation rows × {B0, B2}) has been **launched in
tmux and is in progress**; its numbers are not reported here until its artifacts exist. Live status:
`scripts/check_iris_status.sh iris-v1_gptoss20b_full_20261028T025416Z`. When it finishes, the
machine-generated tables are written to `runs/<run_id>/reports/RUN_REPORT.md` and
`runs/<run_id>/metrics/`. Section 8 must then be updated from those files.

This is a **methodological reproduction**: the original IRIS v1 code, prompts, batching, CodeQL
queries, post-processing, contextual filtering and evaluator are executed unchanged, with GPT-4
replaced by GPT-OSS 20B. **Exact numerical reproduction of Table 1 is not expected.** The model differs,
and the CodeQL/JDK/dependency resolution environment can differ in detail from the authors' 2024 setup.

## 1. Frozen inputs

| Input | Revision / identity | Verified how |
|---|---|---|
| IRIS | `67140e84e6a01da2b44803a6208be2ea7bd4bd51` = `refs/heads/v1` upstream | `git ls-remote`, `git rev-parse HEAD` |
| CWE-Bench-Java | `698fb7248ae30cb7f7782d59c841f05ad70ea9cc` = v1 submodule pointer (`git ls-tree HEAD data/cwe-bench-java`) | checked out recursively, HEAD compared |
| Dataset files | `project_info.csv` sha256 `f409c8cd…`, `build_info.csv` `9f19f701…`, `fix_info.csv` `86db2c52…` | `runs/_dataset/dataset_manifest.json` |
| CodeQL | release asset `codeql-0.8.3-patched/codeql.zip` (807,846,025 bytes, sha256 `e61633fa…`) | size from GitHub API; CLI reports **2.15.5**, packs `java-queries`/`java-all` **0.8.3** |
| JDKs | Oracle 7u80 (md5 `6152f8a7…`), 8u202 (sha256 `9a5c3241…`), 17.0.12 (sha256 `311f1448…`) | compared against Oracle's published digests (pages in `config/pins.json`) |
| Maven / Gradle | 3.2.1 / 3.5.0 / 3.9.8; 6.8.2 / 7.6.4 / 8.9 | Apache `.sha1` / Gradle `.sha256` files |
| Python | conda env `iris`: Python 3.10.22, torch 2.5.1 (CPU), pandas, openai, transformers | `manifests/environment.json` of each run |

The IRIS README calls the patched distribution "CodeQL 2.15.3". The official release asset that its
setup script downloads reports CLI 2.15.5. We use that asset unchanged; the `0.8.3` in the tag is the
bundled Java pack version.

## 2. Dataset

* 120 unique CVEs / 120 project slugs: CWE-022 = 55, CWE-078 = 13, CWE-079 = 31, CWE-094 = 21 (validated by
  `harness/dataset_manifest.py` on every launch). The expanded 213-CVE dataset is not used.
* Sources are fetched with the upstream `fetch_one.py` (shallow clone, fetch + checkout of `buggy_commit_id`,
  `git apply` of the dataset patch). The harness then verifies that HEAD equals the buggy commit and that
  the patch is applied, and records the tree hash and worktree-diff hash per case (`runs/_dataset/status/<slug>.json`).
* Projects are built by CodeQL autobuild inside `codeql database create`, called through the upstream
  `scripts/build_codeql_dbs.py` functions with the JDK and Maven versions recorded in the frozen `build_info.csv`.
* **CVE-2021-21345 (121 vs 120 rows).** Every original `results/*.csv` has 121 rows:
  `x-stream__xstream_CVE-2021-21345_1.4.15` appears under CWE-078 (its dataset CWE) and again under CWE-094.
  The GHSA advisory shipped with the dataset (`advisory/x-stream__xstream_CVE-2021-21345_1.4.15.json`) lists
  both `CWE-78` and `CWE-94`. `neusym_vul_for_query.py` selects projects with `cwe_id.split(";")`, which
  supports multi-CWE entries. The extra row is therefore most plausibly the same case processed under
  both advisory CWEs, while the frozen `project_info.csv` lists only CWE-078. In the artifact, GPT-4's detection
  of this CVE comes **only** from the CWE-094 row (CWE-078 row: Recall 0). As a result, the paper's "55/120" counts
  121 rows, and on the canonical 120 rows the same CSV gives 54. Our full run evaluates the extra row too
  (eval id `x-stream__xstream_CVE-2021-21345_1.4.15__CWE-094`) and reports both policies.
* **Missing package lists.** At the pinned commit, `package-names/` has no file for the two
  `hapifhir__org.hl7.fhir.core_*` slugs. The files `hapifhir__hapi-fhir_<CVE>_<tag>.txt` that do exist list
  `ca.uhn.fhir.*` packages of a different repository and are byte-identical across both versions. They are
  regenerated after database creation with the upstream tool `scripts/get_packages_codeql.py
  --internal-package org.hl7.fhir`. The explicit prefix is needed because the pom groupId `ca.uhn.hapi.fhir`
  does not prefix the sources. This override is documented in `config/experiment.json`.
* **Structurally undetectable cases.** 13 cases have no `fix_info.csv` row with a non-test file *and* a
  method name, so the original fixed-method evaluator can never mark them detected. Both CodeQL and GPT-4
  have Recall 0 on all 13 in the artifact. They are kept in every denominator and listed in
  `operational_metrics.json`.

## 3. LLM configuration (GPT-OSS 20B via OpenRouter)

| Parameter | Value |
|---|---|
| Endpoint | `https://openrouter.ai/api/v1/chat/completions`, model `openai/gpt-oss-20b` |
| Provider routing | `order = only = ["groq"]`, `allow_fallbacks = false`, `require_parameters = true`, `zdr = true`, `data_collection = "deny"` |
| Decoding | temperature 0.0, top_p 1.0, seed 1234, max_tokens 2048, reasoning effort `low` |
| Concurrency | 1 request at a time (`--num-threads 1`; the adapter is sequential regardless) |
| Retries | 6 attempts on 408/409/425/429/5xx/52x and network errors, exponential backoff (2 s … 60 s), Retry-After honoured; 15 s connect / 180 s read timeout |
| JSON validation | if a response is empty or truncated (`finish_reason = length`) **and** contains no JSON that IRIS's own cleaning can decode, the identical request is re-sent once; no prompt is ever modified |
| Accounting | every request is logged to `runs/<run_id>/llm/ledger.jsonl` with prompt / completion / reasoning tokens, OpenRouter `usage.cost`, returned model and provider, retries |
| Cost limit | checked before every request; smoke $3, full run $40; exceeded → exit 75 with resumable state |
| Verification | every response must report provider `Groq` and model `openai/gpt-oss-20b`; otherwise exit 77 |

Preflight on 2026-10-28: authentication ok, Groq serves the model with all required parameters, Groq is on
OpenRouter's ZDR endpoint list, and a live completion was served by `Groq` / `openai/gpt-oss-20b` with 8
reasoning tokens. `.env` sets `MAXVERA_OPENROUTER_PROVIDER=akashml`. The task specification pins the
groq route, so that value is recorded in `manifests/model_api.json` but not used. `.env` was not modified.

GPT-OSS spends completion tokens on reasoning. In the smoke run, reasoning was 25% of completion tokens,
3 of 75 responses hit the 2048-token cap, and 2 identical re-requests returned valid JSON. For reference,
the artifact's `GPTModel` effectively sent `max_tokens = 4096` to GPT-4: IRIS passes `max_new_tokens = 2048`,
a key that `_OPENAI_DEFAULT_PARAMS` does not override. We use the specified 2048, which equals IRIS's intended value.

## 4. Fidelity to the original methodology

Unchanged: candidate extraction queries and filters, the API and function-parameter labelling prompts
(CWE-specific descriptions and examples, the target CWE is given as in the paper), batch sizes 30 (APIs) / 20
(function parameters; CLI defaults of `neusym_vul.py`), the run-wide API-label cache
(`output/common/<run_id>/`), `--use-exhaustive-qll`, QL/YAML spec generation, the CWE-specific
`cwe-0XXwLLM.ql` queries, rule-based post-processing (`results_pp.sarif`), contextual-analysis prompts,
batching (3), path-grouping caches and ignore rules, and the evaluator (`evaluation_pipeline.py`).

Ground truth isolation: `--posthoc-filtering-skip-fp`, `--filter-by-module` and `--filter-by-module-large`
read `fix_info.csv` and are never passed (asserted in `run_case.py`). The only ground-truth consumer is the
evaluator. The function-parameter prompt includes the first README paragraph, which IRIS fetches from
GitHub at the fix commit. That is original behaviour; it is README text, not a label, and is kept.

Changes, all isolated in `patches/iris-v1-compat.patch` or the harness:

1. OpenRouter adapter (`src/models/openrouter*.py`) and its registration in `get_llm()`.
2. `src/codeql_vul.py` (B0 entrypoint): stale v1 code fixed. Root path, v1 column names, optional `--run-id`, and
   SARIF/CSV outputs that previously overwrote each other (`results.sarif` contained CSV and could not be parsed).
3. Database creation: Gradle added to `PATH` for the 3 cases whose frozen build metadata names a Gradle version
   (upstream only adds Maven); `CODEQL_THREADS=4`, `CODEQL_RAM=12288`, `MAVEN_OPTS=-Xmx4g`.
   Upstream build step as a fallback: the upstream workflow runs `data/cwe-bench-java/scripts/setup.py`
   (`build_one.py`: `mvn clean package …` / `gradle build` under the frozen JDK and Maven/Gradle) *before*
   `build_codeql_dbs.py`, which fills the local Maven/Gradle caches. The harness skips it by default because
   `build_one.build_one_project()` rewrites the frozen `build_info.csv`. This matters because CodeQL autobuild
   does not always use the Maven on `PATH`: for projects whose pom demands it (e.g. camel `prerequisites`
   3.3.3), it downloads its own **Maven 3.8.1**. In the full run, `apache__camel_CVE-2018-8041_2.20.3` then failed
   in `camel-jira` test compilation (`org.codehaus.jettison.json` unresolved). Since that failure, a failed database
   creation triggers the upstream attempt function (`build_one_project_with_{maven,gradle}_attempt` /
   `…_with_gradlew`) with the frozen configuration, then one retry of `codeql database create`. Both attempts are
   recorded in `runs/_dataset/status/<slug>.json` (`prebuild`, `db.first_attempt_failure`). Cases that failed before
   this fallback existed (camel) are re-tried with `scripts/resume_iris_reproduction.sh <run_id> --retry-failed`
   after the main pass.
4. Regeneration of the two hapifhir package lists (section 2).
5. Fatal API errors terminate the IRIS process (exit 75/76/77). Otherwise IRIS's bare `except:` around
   contextual analysis would turn API outages into silently empty answers.
6. `neusym_vul.py` is invoked per case by the harness, as `neusym_vul_for_query.py` does, but with the exit status
   and artifacts checked. `neusym_vul.py` exits 1 after re-evaluating cached complete results; completion is
   therefore judged from artifacts, not from the exit code.

Observed model-behaviour effect on an unchanged rule: IRIS merges LLM labels back to candidates only on
an exact `(package, class, method, signature)` match. GPT-OSS sometimes rewrites parameter names; on spark it
copied `FileInputStream(File file)` from the prompt's example instead of the candidate's
`FileInputStream(File p0)`, so a correct sink label was discarded. The merge is kept, and the loss is measured
post hoc by `harness/label_diagnostics.py`: smoke run, 6 of 422 returned labels (1.4%), but 3 of 22 sinks.

Inherited build effect on an unchanged query: `fetch_func_params.ql` keeps only public methods that are
called from `src/test` and not from main code. Projects whose build does not compile tests yield no
function-parameter candidates, so no internal-API sources are inferred for them. Example: DSpace 4.4's pom
activates a `skiptests` profile (`maven.test.skip=true`) unless overridden, and the upstream database build
(CodeQL autobuild, `-DskipTests`) does not override it. This follows from the original pipeline and is
not altered. Affected rows are listed in `operational_metrics.json → b2_rows_without_func_param_candidates`.

Identical requests within a run (byte-identical prompt and parameters, e.g. two contextual-analysis paths with the
same snippet text) are answered from the run's response cache instead of being re-sent (DSpace: 3 of 331). At
temperature 0 the original would ask the same question again. The cache hit is logged in the ledger.

## 5. Experimental configurations

* **B0 — CodeQL baseline:** `codeql_vul.py --query cwe-0XXwCodeQL` runs every query in
  `java-queries/0.8.3/Security/CWE/CWE-0XX/`, as the original script does, with no LLM. Evaluated with
  `EvaluationPipeline.run_vanilla_only()`.
* **B2 — IRIS + GPT-OSS 20B:** `neusym_vul.py --llm gpt-oss-20b`. *Raw* = `results_pp.sarif` (after rule-based
  post-processing, before LLM filtering; evaluator `vanilla_result`). *Filtered* = contextual-analysis output
  (evaluator `posthoc_filter_result`), which corresponds to the paper's IRIS rows. They are never mixed.

Both use the same CodeQL databases, dataset snapshot and evaluator.

## 6. Metrics

Implemented in `harness/metrics_lib.py`, calibrated on the artifact CSVs:

* Per row: Alerts = `num_results`, TP Alerts = `num_tp_results_method`, Recall = `recall_method` (a path passes
  through a fixed `file:class:method`, test files excluded), Precision = TP Alerts / Alerts, F1 = 2PR/(P+R).
* #Detected = rows with Recall 1. **AvgFDR** = mean of (1 − Precision) over rows with ≥ 1 alert. **AvgF1** = mean
  F1 over all rows (no-alert rows contribute 0). MicroFDR is reported separately and labelled as not the paper metric.
* Rows that did not complete count as not detected, F1 0, and are excluded from AvgFDR. They are always listed, and
  completed-only variants are reported alongside.

Calibration with the same code on the original CSVs:

| Source | Rows | #Detected | AvgFDR | AvgF1 | Paper Table 1 |
|---|---:|---:|---:|---:|---|
| `results/CodeQL.csv` | 121 | 27 | 90.04% | 0.076 | 27 / 90.03% / 0.076 |
| `results/CodeQL.csv` | 120 canonical | 27 | 90.04% | 0.077 | |
| `results/IRIS+GPT-4.csv` | 121 | 55 | 84.94% | 0.177 | 55 / 84.82% / 0.177 |
| `results/IRIS+GPT-4.csv` | 120 canonical | 54 | 84.84% | 0.178 | |

The definitions reproduce Table 1 except for small AvgFDR differences (0.01 pp for CodeQL, 0.12 pp for GPT-4),
which we attribute to rounding or a slightly different row set in the authors' script (not included in v1).
Outputs: `metrics_artifact_compatible.json` (all rows of the run; 121 in a full run) and
`metrics_dataset_canonical.json` (120 cases, dataset CWE only). `verify_metrics.py` independently
re-evaluates every completed row from SARIF + location CSVs + `fix_info.csv` without pandas or IRIS code,
recomputes the aggregates with separately written formulas, and records PASS/FAIL.

## 7. Smoke test (isolated, not counted)

Run `iris-v1_gptoss20b_smoke_20261028T023424Z`: one case per CWE (spark CWE-022, perfecto-plugin CWE-078,
antisamy 1.6.6.1 CWE-079, cron-utils CWE-094). All four cases were acquired and verified, all databases built,
and B0 4/4 and B2 4/4 completed every stage. 75 OpenRouter requests, all served by Groq /
`openai/gpt-oss-20b`; 78k prompt and 43k completion tokens (11k reasoning); **$0.018**. Independent verification:
**PASS**.

| Case | B0 alerts / TP alerts / Recall | Artifact CodeQL | B2 raw | B2 filtered | Artifact GPT-4 |
|---|---|---|---|---|---|
| spark CVE-2018-9159 (022) | 13 / 3 / 1 (36 paths, 12 TP paths) | 12 / 3 / 1 (36, 12) | 0 alerts | 0 | detected |
| perfecto CVE-2020-2261 (078) | 0 | 0 | 2 / 2 / 1 | 2 / 2 / 1 | detected |
| antisamy CVE-2022-29577 (079) | 0 | 0 | 9 / 1 / 1 | 9 alerts, 4 paths, Recall 0 | detected |
| cron-utils CVE-2021-41269 (094) | 0 | 0 | 0 | 0 | detected |

B0 reproduces the artifact's CodeQL rows closely (spark: identical paths and TP counts, one extra alert). For B2,
the smoke cases were chosen because GPT-4 detected them, so 1/4 is not an estimate of the full detection rate.
Two incidents occurred during the smoke run and were fixed before the full run: the B0 SARIF overwrite bug
(spark B0 re-run with the fix via `--retry-failed`), and a harness path bug in stage flags (spark's B2 record
refreshed with `run_case.py --refresh-record`; outputs untouched). The smoke manifest therefore records the
pre-fix patch hash (`af4fd0bf…`); the full run records the final patch (`3cd099b0…`).

## 8. Full run

Run id `iris-v1_gptoss20b_full_20261028T025416Z`, launched 2026-10-28T02:54Z in tmux session `iris_repro_v1`,
with a cost limit of $40. **In progress; no aggregate is reported until the run's artifacts exist.** Each row's
status is in `runs/iris-v1_gptoss20b_full_20261028T025416Z/status/execution_status.csv`.

Snapshot at 2026-10-28T03:31Z (row 4 of 121, ~37 min after launch): DSpace CVE-2016-10726, spark
CVE-2018-9159 and spark CVE-2016-9177 completed DB, B0 and B2; WildFly CVE-2018-1047 completed DB and B0, B2 running.
Cumulative 498 OpenRouter requests, $0.086. Early B0 fidelity check, DSpace CVE-2016-10726: 222 alerts / 539 paths
vs 221 / 539 in `results/CodeQL.csv`. Throughput so far is about 10 min per row, so the run needs roughly 20 h;
large projects dominate.

To finish this section: after `runs/<run_id>/DONE.json` appears, copy the two aggregate tables, the per-CWE
table and the comparison table from `runs/<run_id>/reports/RUN_REPORT.md`, list the rows that did not complete
with their causes (`metrics/operational_metrics.json → failure_causes`), and confirm `metrics/verification.json`
is PASS.

## 9. Reproducibility differences to expect (not tuned)

* Model: GPT-OSS 20B (open-weight reasoning model, served by Groq, quantization undisclosed) vs GPT-4
  (`gpt-4-0125-preview`), and 2048 vs effectively 4096 max tokens.
* Instruction following under IRIS's exact-signature label merge (section 4).
* Database contents: autobuild under today's Maven Central / Gradle plugin availability may differ from 2024.
* The artifact's metric script is not part of v1; aggregates are reproduced from the evaluator fields
  (section 6 calibration).
* 13 structurally undetectable cases bound recall at 107/120 for any method.
