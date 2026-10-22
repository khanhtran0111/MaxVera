# Migration inventory — 2026-10-21

Historical pre-migration inventory. Paths, checksums and limitations in the table describe the audited original implementation; current capabilities and live execution are listed in [implementation status](IMPLEMENTATION_STATUS.md).

Authoritative plan: `../ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md`.
Audited checkout: d968738; baseline: `.venv/bin/python -m pytest -q` → 240 passed (18.93 s).

Every existing source, script, configuration and test has its pre-edit SHA256 and destination in [migration_source_index.json](migration_source_index.json). Retained legacy modules are explicitly identified; no empty replacement folders imply implementation.

| Existing component | Reuse / destination | Verified limitation |
|---|---|---|
| src/reproduction/runner.py, iris_subprocess.py | staged IRIS worker / new reproduction DAG | Old runner requires prebuilt DBs, filters build failures, mixes evaluation; adapter mechanically migrates queries to CodeQL 2.26. |
| src/reproduction/common.py | atomic IO, SARIF normalization | Existing FDR is a patch intersection proxy, not automatically paper AvgFDR. |
| src/data/phase2.py, build_projects.py | pinned dataset prepare, acquisition/build helpers | Research manifest separation alone does not deny filesystem access. |
| src/graphs/program/model.py and src/static_analysis/queries | Old normalizer retained for legacy; new typed graph schema reuses v2 Grounding queries | CALL does not imply taint; external/dynamic targets may be incomplete. |
| src/llm/providers/openrouter.py | canonical model/provider transport | Repro adapter hardcodes Groq config; route must be reconciled, not silently selected. |
| src/pipeline_v2 and phase/baseline modules | retain internal compatibility, isolate new public CLI | Existing staged/B9 orchestration depends on historical artifacts. |

## Previous reproduction evidence

[Read-only index](legacy_reproduction_index.json) records exact export checksums. B2 canonical has 120 statuses: 99 SUCCESS, 5 ANALYSIS_FAILED, 11 BUILD_FAILED, 5 CODEQL_DB_FAILED; detected=36. Artifact view has 121 rows, detected=37. Neither is a new run. Existing code/artifacts do not establish exact patched-2.15.3 parity; do not claim paper fidelity from their counts.

IRIS checkout HEAD verified: 67140e84e6a01da2b44803a6208be2ea7bd4bd51. Dataset HEAD verified: 698fb7248ae30cb7f7782d59c841f05ad70ea9cc.

## Cleanup

The user authorized cleanup of old generated outputs before the new pipeline runs. That completed cleanup retained compact tracked Phase 4 exports, raw datasets, third-party source, environment and toolchains. Its exact historical allowlist and reclaimed space are in [storage_cleanup.json](storage_cleanup.json). It is not an instruction to delete current run outputs or logs.
