# IRIS (ICLR 2025) reproduction with GPT-OSS 20B

Faithful re-execution of the original IRIS v1 artifact on CWE-Bench-Java (120 CVEs), with
GPT-4 replaced by `openai/gpt-oss-20b` served through OpenRouter. The narrative write-up, including
deviations and results, is in [REPRODUCTION_REPORT.md](REPRODUCTION_REPORT.md).

| Item | Value |
|---|---|
| IRIS | `iris-sast/iris@67140e84e6a01da2b44803a6208be2ea7bd4bd51` (branch `v1`) → `vendor/iris-v1` |
| Dataset | `iris-sast/cwe-bench-java@698fb7248ae30cb7f7782d59c841f05ad70ea9cc` (v1 submodule pointer) |
| CodeQL | release asset `codeql-0.8.3-patched` (reports CLI 2.15.5, java packs 0.8.3) → `vendor/iris-v1/codeql` |
| Python | Miniforge, conda env `iris` (Python 3.10, upstream `environment.yml` + `cpuonly`) → `tools/miniforge3` |
| JDK / build | Oracle JDK 7u80 / 8u202 / 17.0.12, Maven 3.2.1 / 3.5.0 / 3.9.8, Gradle 6.8.2 / 7.6.4 / 8.9 (checksums verified against publisher digests) |
| LLM | OpenRouter `openai/gpt-oss-20b`, provider `groq` only (fallbacks off, ZDR, data collection denied), temperature 0, top_p 1, seed 1234, max_tokens 2048, reasoning effort low, 1 concurrent request |
| Configurations | **B0**: original CodeQL queries (`src/codeql_vul.py`), no LLM. **B2**: full IRIS (`src/neusym_vul.py --llm gpt-oss-20b`, batch sizes 30/20) |

## Layout

```
iris_repro/
  config/pins.json                      frozen revisions, download URLs, publisher checksums
  config/llm_gpt_oss_20b_openrouter.json OpenRouter template (instantiated per run, no secrets)
  config/experiment.json                IRIS arguments, CodeQL/build limits, cost limits, documented overrides
  config/environment.iris.cpu.yml       conda environment
  patches/iris-v1-compat.patch          the only change to IRIS sources (see patches/README.md)
  harness/                              dataset preparation, case runner, orchestrator, metrics, verification, reports
scripts/
  setup_iris_env.sh                     one-time setup (idempotent)
  start_iris_tmux.sh                    validate + create run + launch in tmux session iris_repro_v1
  run_iris_reproduction.sh              wrapper executed inside tmux (keeps the orchestrator exit code through tee)
  check_iris_status.sh                  status / progress / cost / last log lines
  resume_iris_reproduction.sh           resume a run
runs/
  _dataset/                             shared dataset state: per-case source/DB status, dataset manifest, logs
  <run_id>/                             one immutable directory per run (see below)
```

## Setup

```bash
scripts/setup_iris_env.sh          # clones/verifies IRIS + dataset, applies patch, installs toolchains, CodeQL, conda env
```

`.env` must contain `OPENROUTER_API_KEY`. It is read by the OpenRouter client at request time and is
never exported, logged, or written to run artifacts.

## Launch (always through tmux)

```bash
# Smoke test (isolated run directory; never counted in official results)
scripts/start_iris_tmux.sh --smoke --projects perwendel__spark_CVE-2018-9159_2.7.1 \
    jenkinsci__perfecto-plugin_CVE-2020-2261_1.17 nahsra__antisamy_CVE-2022-29577_1.6.6.1 \
    jmrozanec__cron-utils_CVE-2021-41269_9.1.5

# Full reproduction: 120 canonical cases + the artifact's CVE-2021-21345/CWE-094 row, B0 and B2
scripts/start_iris_tmux.sh --full                 # cost limit from config/experiment.json (full_cost_limit_usd)
scripts/start_iris_tmux.sh --full --cost-limit 40 # explicit limit
```

The launcher validates the environment (IRIS commit, patch, CodeQL, conda env, toolchains, key
presence), validates the dataset manifest, creates `runs/<run_id>/`, runs an authenticated API
preflight with the run's own configuration, and starts the detached session `iris_repro_v1`. It
refuses to start while a live `iris_repro_v1` session exists.

## Monitoring

```bash
scripts/check_iris_status.sh [RUN_ID]      # defaults to runs/LATEST
tmux list-sessions
tmux attach -t iris_repro_v1               # detach with Ctrl-b d
tmux capture-pane -pt iris_repro_v1 | tail -n 40
tail -f runs/<run_id>/logs/orchestrator.log
```

## Resume

```bash
scripts/resume_iris_reproduction.sh <run_id>                 # retries interrupted / budget-stopped / API-failed configurations
scripts/resume_iris_reproduction.sh <run_id> --retry-failed  # also retries case-level failures (and failed DB builds)
```

Completed configurations are never re-run. A retried B2 case replays every LLM call already made
from `runs/<run_id>/llm/response_cache.jsonl` (no new cost). The orchestrator stops with resumable state on:
exit 75 (cost limit reached), 76 (persistent API failure after bounded retries), 77 (configuration error,
e.g. the pinned provider no longer serves the model). The cost limit is never raised automatically. To
continue after a budget stop, edit `runs/<run_id>/config/llm_config.json` → `accounting.cost_limit_usd`
deliberately, then resume.

## Evaluation only

```bash
PY=tools/miniforge3/envs/iris/bin/python
$PY iris_repro/harness/evaluate.py          --run-id <run_id>
$PY iris_repro/harness/label_diagnostics.py --run-id <run_id>
$PY iris_repro/harness/verify_metrics.py    --run-id <run_id>   # independent re-evaluation from SARIF
$PY iris_repro/harness/report.py            --run-id <run_id>
```

These run automatically once all rows of a run have been processed.

## Run directory

```
runs/<run_id>/
  run_manifest.json                 cohort, cost limit, IRIS commit, patch/config hashes
  config/                           llm_config.json, experiment.json (frozen copies)
  manifests/                        environment.json, model_api.json, api_preflight.json, dataset manifest snapshot
  status/execution_status.{csv,json} explicit status of every evaluation row; progress.json
  cases/<eval_id>/{b0,b2}.json      command, exit code, stage flags, artifact paths + sha256, evaluator output, LLM usage
  llm/ledger.jsonl                  one line per request: tokens, reasoning tokens, cost, provider, model, retries
  metrics/                          project_metrics.csv, per_cwe_results.csv, raw_vs_filtered.csv,
                                    metrics_artifact_compatible.json, metrics_dataset_canonical.json,
                                    operational_metrics.json, token_cost_report.json, token_cost_by_project.csv,
                                    label_merge_diagnostics.{csv,json}, verification.json
  reports/RUN_REPORT.md, reports/comparison_with_paper.csv
  logs/                             orchestrator and per-case logs (git-ignored)
```

IRIS's own per-project outputs (candidate CSVs, LLM prompts/responses, `llm_labelled_*.json`
specifications, `MySources/MySinks/MySummaries.qll`, `Spec.yml`, raw / post-processed / filtered SARIF)
are written to `vendor/iris-v1/output/<slug>/<run_id>/` (B2) and `vendor/iris-v1/output/<slug>/<run_id>-b0/` (B0);
the case records reference them with sha256 hashes.
