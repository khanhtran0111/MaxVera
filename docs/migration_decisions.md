# Migration decisions / execution ledger

**Historical migration ledger.** Scope restrictions, test counts and “pending” statements below describe the migration stage before later user-authorized live runs. They are not the current run instructions. Current status: [implementation](IMPLEMENTATION_STATUS.md), [validation](validation_report.md), [full execution](reproduction_full_2026-10-21.md). Legacy runbooks mentioned below were subsequently removed from current docs with backups.

Plan: ../ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md v2.0.

1. Work in place on refactor/pipeline-first-v2, as requested; no second project or worktree.
2. Add the real `maxvera` package alongside `src`; retain working helpers and upstream IRIS. Old phase/baseline commands remain deprecated compatibility entrypoints until parity, not deleted.
3. Ruling: explicit user cleanup supersedes preservation of large raw artifacts. Preserve tracked compact legacy exports and checksum index. Cost: raw historical SARIF/prompts cannot be regenerated from summaries and cannot support new fidelity claims.
4. Ruling: supplied architecture/implementation plan is the approved design; implement inline without repeating approval stages. No paid/full pipeline runs. Unit/integration fixtures and dry-run only.
5. Reproduction precedes research. W7/W8 experiments remain gated by W6 graph-only dev signal, per section 10. Implement only bounded contracts until that gate is measured by the user.
6. Preflight interfaces: W1 config/schemas → W2 immutable DAG; W2 stage records → W3 adapter/finalizer → W4 isolated evaluator; W5 typed graph → W6 generators → W9 evaluator. Oracle metadata never enters research worker.

## Work packages

- W0: inventory complete; baseline 240/240; local pins verified; historical index recorded before cleanup.
- W1/W2: contract and DAG tests passed, including case interruption, independent branches, immutable outputs and journal replay.
- W3: adapter invokes original upstream methods in a process; no analyzer GT evaluation. Paper evaluator fixture passed using actual pinned upstream code. Live model smoke is still pending.
- W4: kernel denied-read and symlink sentinel tests passed; CLI research worker missing-source accounting also passed without GT access.
- W5: actual CodeQL fixture initially failed because key omitted callable/kind, corrected after inspecting identity contract; real extraction test then passed in 69.67 seconds.
- W6: graph discovery emits cross-file candidate without alerts; real dev Recall@K has not been measured, gate remains open.
- W7/W8: intentionally NOT_IMPLEMENTED per plan §10 graph-only signal gate; existing reproduction model transport is not a research LLM implementation.
- W9: evaluator/CLI/comparator fixture tests passed; significance/adjudication/complete efficiency reporting remain NOT_IMPLEMENTED.
- W10: public README and three protocols/status board written; old runbook retained as historical docs.
- Ruling: default research uses D_extended's existing 96-project development split; D_repro_v1 IDs have zero overlap with that split. Cost if wrong: new split/preparation, never silently run an empty selection.
- Ruling: expose explicit --execute while dry_run_default is true. Cost: operational examples include one extra flag; prevents accidental spend during code work.
- Ruling: retain phase/B-number compatibility scripts with deprecation warnings until new parity is proven. Cost: legacy internals remain larger, but users have one canonical public CLI.
- Ruling: legacy tests that depended on deleted experiment outputs now use isolated temporary fixtures with real checksum/manifest validation; no production placeholders were created.
- Ruling: patched IRIS toolchain actually reports 2.15.5; log this discrepancy, do not claim 2.15.3 fidelity. Cost: live compatibility smoke remains required before full reproduction. Status and exact evidence will be updated during implementation.


## Independent whole-change review and fixes

A fresh read-only reviewer audited the complete working tree. Ten Important findings were accepted and reproduced with sixteen failing regression tests in `tests/pipeline/test_review_regressions.py` before correction. This was one consolidated fix pass; no paid or benchmark run was used.

| Finding | Fix / regression evidence |
|---|---|
| IRIS bypassed JSON validation | Separate validation policy and array/object shape from transport response_format; actual upstream-style batch calls tested |
| Over-budget response replay bypassed stop | Durable per-case budget stop precedes every replay/new request |
| Sandbox allowed label mutation | Landlock ABI >=3 handles writes/truncate/remove/create; only current run/private caches writable; real write/unlink denial tested |
| Builds modified shared snapshots | One inventory policy; private build copies and actual analyzed-byte hashes; generated/modified sources recorded |
| Resume consumed unchecked upstream/database files | Restore upstream only from exact hashed stage snapshots, discard partial mutable output, checkpoint database relations/archive and reference inventories; exclude mutable query cache/dynamic pools; build DB from a private source copy |
| File-only GT inflated strong recall | Strong match requires valid method/class span; file-only overlap remains weak |
| Graph/static duplicate inflated novelty | Versioned source/sink program-point overlap; merge attribution, suppress default-alert duplicate; novelty uses explicit overlap |
| Comparator accepted unchecked/mismatched evaluations | Verify every checksum and consistent condition manifest: inputs/snapshots/code/tools/labels/protocol/evaluator/budgets/models |
| Real run IDs prevented paired pool equality | Hash raw discovery content excluding run/ranking/model/verifier metadata |
| Evaluator changes reused stale metrics | Hash policy/evaluator implementation, verify clean pinned upstream evaluator in parent/worker, reject changed identity on reuse |

Evaluator output now uses atomic directory publication. Actual CodeQL inside the read/write sandbox exposed a JVM temporary-directory default under `/tmp`; the fix directs JVM temp and compilation/common caches into the current run's approved cache instead of broadening filesystem permissions.

### Rulings on considered-but-unjudged behavior

1. W7/W8 and statistics/adjudication remain gated/documented absent. Cost: these capabilities are not ready for new research claims.
2. Hosted-model compatibility/provider availability/full benchmark signal remain unverified because the user requested code work first. Cost: live smoke is still required before full spend.
3. Conservative token reservations, unknown-cost stops and one-response dollar overshoot remain explicit transport limits. Cost: budget accounting can halt early and is not a provider-side prepaid cap. The replay bypass itself is fixed.
4. Dynamic dispatch/library/exception/path completeness remains a measured extractor limitation, not verified evidence. Cost: discovery recall may miss real paths; no positive recall claim is made.
5. Historical cleanup and canonical120/artifact121 distinction follow explicit user authorization and preserved compact evidence. Cost: deleted raw artifacts cannot establish new fidelity.
6. Network/process isolation beyond declared filesystem content protections is not claimed. Cost: this is not a general hostile-code sandbox.

### Deferred minor

Tool identity fingerprints launcher/version and source query/config code, but not every binary/QL-library byte behind an unchanged toolchain version. Record any manual toolchain patch and choose a new run ID. Cost: an unrecorded in-place bundle patch is not automatically detected during resume.

Final fix-pass checks: 283 default tests passed, 2 opt-in tests skipped (18.76 s); repository lint passed. Separately, actual CodeQL extraction passed and the complete sandboxed graph-only CLI fixture passed (194.32 s) with zero model calls. The final sandboxed CLI repetition passed in 192.26 s with Java temp/user-home/cache hardening; its exact command is in validation_report.md.

Delivery ruling: preserve the current workspace and local refactor/pipeline-first-v2 branch, as the user explicitly requested; no merge/push/PR is part of this task. Cost: integration into main remains a separate user decision, with all changes locally reviewable.

Final regression evidence also covers explicit library-pack pinning for reference inventories and propagation of a finite case deadline into the actual stage context. These prevent implicit package selection and a configuration limit that only existed in metadata.
