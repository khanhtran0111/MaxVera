# Implementation status — 2026-10-21

This is an implementation report, not a full-run/paper result. Authoritative scope: [v2 plan](../ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md). Work remains gated or unverified as shown below.

| Work package / capability | Status | Code / evidence / remaining gate |
|---|---|---|
| W0 source/artifact inventory, historical index, cleanup | IMPLEMENTED | [inventory](migration_inventory.md), [per-file pre-edit SHA/mapping](migration_source_index.json), [legacy index](legacy_reproduction_index.json), [cleanup](storage_cleanup.json); 81.39 GiB reclaimed |
| W1 typed config, immutable candidate/finding schema, redaction | IMPLEMENTED | [contracts](../maxvera/contracts.py), [schemas](../maxvera/schemas.py), [contract tests](../tests/pipeline/test_contracts_runtime.py) |
| W2 public CLI, DAG, checkpoint, resume, dry-run/status | IMPLEMENTED | [CLI](../maxvera/cli.py), [orchestrator](../maxvera/orchestration.py); corrupt/incomplete/uncertain-paid checkpoints tested; source/DB relations and restored upstream input snapshots validated |
| W3 real IRIS method adapter, independent reference branch | PARTIAL | [reproduction](../maxvera/reproduction.py), [worker](../maxvera/iris_worker.py), [tests](../tests/pipeline/test_reproduction.py); prior smoke attempts stopped after dependency/transport failures; response handling now has unit/journal and isolated live API evidence; fast full run `repro_fast_20261021T142440Z` is active; no completed end-to-end full result yet; patched binary reports 2.15.5; scientific compatibility/fidelity remains unproven |
| W4 OS filesystem firewall and isolated exact upstream evaluator | IMPLEMENTED | [Landlock](../maxvera/sandbox.py), [research worker](../maxvera/research_worker.py), [evaluator worker](../maxvera/evaluator_worker.py); actual denied-read/write/unlink/symlink and method-matching tests; only current run/private caches writable |
| W5 typed graph/custom extraction | PARTIAL | [graph](../maxvera/graph.py), [queries](../src/static_analysis/queries/v2/ProgramCore.qll), [Java integration](../tests/integration/test_pipeline_codeql_fixture.py); missing dynamic/exception/library summaries reported; exact fixture result in validation report |
| W6 three generators, deterministic rank/Top-K | PARTIAL | [generators](../maxvera/candidates.py), [research DAG](../maxvera/research.py); real CodeQL cross-file extraction and sandboxed CLI smoke tested; default-alert overlap is explicit and duplicate evidence merged; frozen real-dev Recall@K gate has not run |
| Reproduction model transport/journal/budget infrastructure | IMPLEMENTED | [journal adapter](../maxvera/llm.py), [journal tests](../tests/pipeline/test_llm_journal.py), [80 response recovery cases](../tests/pipeline/test_llm_response_recovery.py), [repair evidence](llm_response_repair_2026-10-21.md); typed received-response errors, strict JSON/cache revalidation, budgeted retries and unknown-cost stops; dollar ceiling is not provider-side prepaid enforcement |
| W7 research bounded evidence/citation validation/LLM rerank | NOT_IMPLEMENTED | Plan §10 gate: measure graph-only dev discovery first. Selected LLM variants fail explicitly, no dummy inference |
| W8 targeted verification/spec templates | NOT_IMPLEMENTED | Same gate; no claim that NO_FLOW_FOUND proves safety; no fake verification evidence |
| W9 isolated recall/paper evaluation and matched comparator | PARTIAL | [evaluation](../maxvera/evaluation.py), [tests](../tests/pipeline/test_cli_evaluation.py); checksummed matched conditions and versioned evaluator identity enforced; statistics, adjudication and full efficiency reporting remain absent |
| W10 public README/protocols/migration status | IMPLEMENTED | [README](../README.md), [reproduction protocol](reproduction_protocol.md), [research protocol](research_protocol.md), [evaluation protocol](evaluation_protocol.md) |
| Optional USEG/KG/calibration/fixed-version differential | NOT_IMPLEMENTED | Legacy implementations retained internally; not integrated into the new core or presented as new results |

## Validation

See [validation_report.md](validation_report.md) for exact commands, exit codes, fixture scope and remaining gaps. `--dry-run` listed 120 reproduction cases and 96 research development cases. The migration itself made no paid requests. Subsequent authorized diagnostics exercised the pinned model/provider; the latest default suite passed 393 tests with two opt-in CodeQL fixtures skipped. The user then authorized a new full run without repeating smoke solely for the repaired LLM layer. Runtime profiling replaced the fixed 30-second delay with an explicit fast profile and added fail-closed handling for upstream-swallowed model errors. See the [current full execution record](reproduction_full_2026-10-21.md); full evaluation results remain pending.

## Storage / migration decisions

Old large generated outputs/logs/interim checkouts/databases and disposable model caches were removed by explicit user request. Raw datasets, environment/secrets, toolchains, vendor checkouts and compact tracked legacy reproduction exports remain. [Decisions and execution ledger](migration_decisions.md) document this override and its consequence: deleted raw evidence cannot support new fidelity claims.

One deferred minor: tool fingerprints cover launcher/version and repository query/config bytes, not every installed toolchain library/binary behind an unchanged version. Manual bundle patches require a new run ID. See the independent review ledger.
