# Validation report — 2026-10-21

This report records observed checks, not a successful full reproduction result. The current full run is `repro_fast_20261021T142440Z`; see its [execution record](reproduction_full_2026-10-21.md). Research acceptance gaps are listed in [implementation status](IMPLEMENTATION_STATUS.md).

## Latest code verification

| Check | Observed result | Evidence |
| --- | --- | --- |
| `.venv/bin/pytest -q` | **393 passed, 2 skipped**, 18.71 seconds | `logs/runtime_optimization_20261021T141224Z/verification.json` |
| `.venv/bin/ruff check .` | Passed | `logs/runtime_optimization_20261021T141224Z/verification.json` |
| `.venv/bin/mypy` | No issues in 126 configured source files | `logs/runtime_optimization_20261021T141224Z/verification.json` |
| Response handling regressions | 80 HTTP-boundary/journal cases; independent-review findings reproduced before fixes | [Tests](../tests/pipeline/test_llm_response_recovery.py), [repair report](llm_response_repair_2026-10-21.md) |

The default suite makes no external model calls. Its two skipped tests are explicitly opt-in local CodeQL fixtures, not skipped failures. Documentation cleanup does not change the running implementation hash and does not imply a new code-test run.

## Runtime optimization checks

The 12 new scheduler/fence/error-propagation tests run the real journal/worker dispatch without remote calls. Regressions were observed before fixes: mandatory idle, minute-floor 429 backoff, valid fenced JSON rejected, upstream-swallowed failures, and a later batch sending after a latched failure. Strict duplicate/nonfinite/extra-text rejection remains. A single valid fence is retained unchanged in raw response/hash/cache evidence.

Authorized live profiling made 37 diagnostic attempts with known total cost USD 0.003986665. The final six-prompt journal batch took 7.840 seconds on Groq versus 107.146 seconds on AkashML. Both labeling and context JSON shapes were exercised; this small sample does not establish full benchmark runtime/accuracy. Detailed source settings, probes, costs and review verification are under `logs/runtime_optimization_20261021T141224Z/`; the original paid run remains separate. See the [current execution record](reproduction_full_2026-10-21.md).

## Earlier live model checks

The user separately authorized four small diagnostic API calls. The original failed DSpace prompt returned valid text on raw replay. Through the repaired journal path, a DSpace API prompt and a historical Spark context prompt succeeded, and cached replay sent no additional request. An intentional one-token output limit produced `length`; the client recorded its charge and stopped as `TRUNCATED_RESPONSE`, as expected.

Total reported diagnostic cost: **USD 0.000427**. These checks validate response handling, not benchmark findings. The historical malformed response was not recoverable, so its precise subtype remains unknown. Full evidence is in `logs/llm_response_repair_20261021/live_repaired_summary.json` and the [repair report](llm_response_repair_2026-10-21.md).

## Toolchain and integration evidence

Doctor passed at the new full launch: patched reproduction CodeQL **2.15.5**, research CodeQL **2.26.2**, Landlock available, model/provider/key present. Doctor itself makes zero network requests. The full-selection dry-run passed with **120 cases**, a configured maximum of **120,000 attempts / USD 120** across all cases; these are ceilings, not expected spend. The research dry-run previously selected **96 development cases** and zero model requests.

During migration, the opt-in Java fixture passed with actual CodeQL 2.26.2 / Java 17 in 69.67 seconds. It extracted 43 nodes, 10 edges and 2 cross-file edges, producing a complete candidate with no default alerts or model calls. The separate sandboxed graph-only CLI fixture passed in 192.26 seconds with protected source/sentinel files unchanged. These are historical fixture checks and have not been rerun during documentation cleanup; they do not prove benchmark recall or complete dynamic/library/exception modeling.

## Remaining acceptance limits

The current full reproduction has started but has no completed aggregate/evaluation result yet. Individual project builds, remote dependency resolution, provider failures and full storage requirements remain execution risks. Four obsolete Spring EBR metadata coordinates were quarantined; the full launch records this unresolved dependency risk.

Research W7/W8 remain gated on a measured graph-only development signal. Statistical significance, adjudicated negatives and complete efficiency reporting remain outside the implemented evaluator. Tool fingerprints do not hash every installed toolchain library behind an unchanged version. See [evaluation protocol](evaluation_protocol.md) and [migration decisions](migration_decisions.md).

The historical storage cleanup reclaimed 81.39 GiB; its [record](storage_cleanup.json) describes that event, not current directory sizes. Later smoke/full outputs have since been generated. Old aggregate exports cannot reconstruct deleted raw historical SARIF/prompts or establish new paper-fidelity claims.
