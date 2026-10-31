# IRIS v1 compatibility patch

`iris-v1-compat.patch` is applied by `scripts/setup_iris_env.sh` on top of
`iris-sast/iris@67140e84e6a01da2b44803a6208be2ea7bd4bd51` (branch `v1`). Regenerate it with
`git -C vendor/iris-v1 diff > iris_repro/patches/iris-v1-compat.patch` after `git add -N` of new files.
It does not change prompts, batching, query templates, CodeQL specifications, post-processing,
contextual filtering, or the evaluator.

| File | Change | Why |
|---|---|---|
| `src/models/openrouter_client.py` (new) | OpenRouter client: pinned provider (`groq`, fallbacks off, ZDR, `data_collection=deny`), decoding parameters, bounded retries, timeouts, model/provider verification, token/cost ledger, cost limit, request-level response cache, at most one identical re-request when a response is empty or truncated without parseable JSON | GPT-OSS 20B is served through OpenRouter instead of the OpenAI API used for GPT-4 |
| `src/models/openrouter.py` (new) | `OpenRouterModel(LLM)` with the `GPTModel.predict()` interface; sequential requests (concurrency 1); fatal API/budget/config errors end the process with exit 75/76/77 | IRIS wraps LLM calls in bare `except:` blocks that would otherwise turn API failures into silently empty answers |
| `src/models/llm.py` | `get_llm()` routes the name `gpt-oss-20b` to `OpenRouterModel` (before the generic `gpt*` branch) | register the model; the name starts with `gpt` so `LLM.__init__` skips loading a HuggingFace checkpoint |
| `src/codeql_vul.py` | (a) repository root path `../../` → `../`; (b) v1 column names `cve`→`cve_id`, `commits`→`fix_commit_ids`, `db_name`→`project_slug`; (c) optional `--run-id` (default `common` keeps the original output path); (d) the SARIF and CSV `codeql database analyze` invocations write to separate files | the v1 B0 entrypoint was stale: (a)/(b) made it crash at import / start-up, and (d) the CSV pass overwrote `results.sarif`, so the evaluator could not parse it |

Harness-level compatibility measures (no IRIS source change) are documented in
`iris_repro/REPRODUCTION_REPORT.md` §4: Gradle on `PATH` for Gradle-built cases during database
creation, regeneration of two missing `package-names` files with the upstream tool, CodeQL
resource limits, and `num_threads = 1`.
