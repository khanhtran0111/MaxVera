# Research GO gates implementation plan

**Goal:** Repair the remaining truth-alignment and endpoint-verification blockers,
prepare the fixed pilot cohort, and reassess readiness using fresh evidence.

**Architecture:** Trusted preflight/evaluation validates annotations against the
vulnerable source independently of the analyzer. Static candidate verification
uses exact, provenance-bound SARIF endpoints and requires unique CodeQL binding.
New input views and run IDs preserve existing snapshots and frozen results.

**Spec:** User instructions in this session and
`docs/research_readiness_2026-10-24.md`, especially the final diagnostic addendum.

## Constraints

- Work on `refactor/pipeline-first-v2`, baseline `92416c8`; preserve the dirty tree.
- No project reinitialization, IRIS reproduction, frozen artifact edits, or pinned
  `third_party` checkout changes.
- Keep development and locked 96/24 cohorts and the fixed pilot10 IDs.
- Write and observe failing regressions before production changes.
- Keep uncertain candidates and missing/unaligned truth explicit; no guessed
  endpoint, basename mapping, safety inference from no-flow, or integrity bypass.
- Keep `graph_signal_approved: false` until a genuine reviewed signal exists.

## Work and verification

- [x] Save initial git status, file hashes, HEAD and a complete patch including
  untracked files in `logs/research_go_20261024/initial_state.json` and
  `initial_worktree.patch`.
- [x] Truth: regress commit mismatch, missing/renamed paths, out-of-range spans,
  incomplete mappings and changed source. Implement trusted validation in
  `maxvera/truth_alignment.py`, `preflight.py`, and `evaluation.py`; preserve
  cohort denominators and give new evaluations a distinct immutable identity.
- [x] Verification: regress raw SARIF linkage, complete endpoint coordinates,
  source-boundary integrity and zero/one/multiple bindings. Implement structured
  endpoint provenance in extraction/candidates and exact verifier binding. Run a
  small actual CodeQL fixture.
- [x] Inputs: prepare the same ten development IDs from pinned vulnerable
  commits into a separate verified input view. Record all fetch/preparation
  failures; source/recipe availability alone does not prove successful builds.
- [x] Run default pytest, Ruff, configured mypy and relevant CodeQL regressions;
  independently review new changes and repair confirmed blockers.
- [x] Run fresh preflight/evaluation and the eligible smoke. Execute pilot only
  when prerequisite gates pass; execute full120 only when all full gates pass.
- [x] Publish actual commands, resolved configuration, test results, preserved
  artifact checks and the resulting GO/NO-GO decision.

## Acceptance order

1. Truth is evaluable only after the annotation's vulnerable-source alignment is
   proven. Presence of a fix-commit record or an in-bounds span is insufficient.
2. Existing engineering acceptance requires complete retained-candidate
   accounting, valid assessments where enabled, supported verification where
   enabled, and no incomplete evidence or discovery traversal truncation.
3. Pilot comparison uses the same fixed cohort, source/query identity, Top-K and
   budgets. Diagnose raw-pool coverage separately from ranking and LLM ranking.
4. Scientific thresholds must be registered before the pilot used for approval.
   No threshold was previously fixed in this repository; this change does not
   retrospectively invent one or grant graph-signal approval.
5. Full benchmark claims require all 120 verified inputs and all 120 aligned
   truths; otherwise whole-cohort recall remains unavailable. Locked cases are
   excluded from tuning. Operational completion alone never grants full GO.

## Progress receipts

Parallel tasks have disjoint production-file ownership. Task receipts are
`logs/research_go_20261024/{truth,sarif,input}_report.md`. This ledger records
implementation and observed gates; it does not authorize bypassing a gate.

Outcome: 662 default tests pass, five opt-in skips; actual SARIF fixture passes.
Smoke02 completes 18/18 stages and passes engineering acceptance, with same-code
resume preserving 15,539 files and 0 new paid calls. Two review P1s plus failed-extraction
truth accounting were fixed with RED/GREEN evidence and scoped independent review.
Mapping v2 preserves all 67 pilot rows and 10 cases, aligning 6 cases; source view covers
11/120 for the full prepared profile. Scientific pilot/full remain gated NO-GO.
Minimal expansion criteria are preregistered in
`docs/research_pilot_acceptance_2026-10-24.md`; no graph approval was granted.
