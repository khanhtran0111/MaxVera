# MaxVera smoke recheck implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the independent repair tasks and verification-before-completion for execution claims.

**Goal:** Recheck the supplied research review, repair the scoped runtime defects, execute the complete MaxVera research pipeline on exactly two newly sampled development cases, remove previous run outputs/logs, and report any remaining full-run blockers accurately.

**Architecture:** Continue the existing pipeline in place. Research candidate identity, soft ranking, opaque inputs and filesystem isolation remain intact. Repair IRIS consumption through explicit compatibility behavior without modifying the pinned checkout. Select and freeze two cases before consulting evaluator truth.

**Tech stack:** Python 3.10, pytest, CodeQL Java, Landlock, OpenRouter GPT-OSS-20B/Groq.

**Spec:** User review attachment supplied 23 October 2026; audit `docs/research_audit_2026-10-22.md`; current user request supersedes all previous output-retention choices.

## Constraints and review focus

- Exactly two new random development cases, excluding the two previous smoke cases; failures do not trigger cherry-picked replacement.
- Keep analyzer free of oracle labels; evaluator reads truth only after output freezes.
- Never retry a charge-uncertain remote attempt automatically. Provider route/model remain pinned; raise local finite limits only where needed.
- Delete all old result artifacts, including tracked historical result exports, and old run logs/caches. Keep source, dataset inputs, toolchains, environment and this task's new outputs.
- No full benchmark launch is implied by the requested two-case smoke. Verify usable CLI/profile and state full-run gates accurately.

## Work

- [x] Candidate identity repair: RED→GREEN, real CodeQL identity flow pass; evaluator singleton identity regression added and policy bumped.
- [x] IRIS compatibility repair: semantic schema, strict parser and tail flush pass regressions; explicit worker deviation artifact; positive-only omission semantics retained.
- [x] Random source preparation: two IDs frozen with seed20261023; exact source commits and isolated hash-bound dependency caches; no replacement; Spring Bundlor packaging adaptation declared.
- [x] Root integration and cleanup: old outputs/logs/legacy exports removed; finite API headroom expanded; default498 tests/lint/types pass. Actual first-run graph-size and virtual-library-source blockers reproduced/fixed and independently reviewed before r2.
- [x] Execute actual MaxVera `graph_llm_verify` smoke with the pinned provider; inspect every stage/call/query, freeze then evaluate, verify resume, and publish a current report plus exact runnable command. Final r3 completed 18/18 stages; source-backed endpoint evidence, checksums, DB identities and no-additional-call resume verified. Superseded outputs removed. Report explicitly records 9/10 valid assessments, Recall@5=0/2, missing source preparation and the newly confirmed unresolved metadata/snapshot/tie-break repeatability bug; full gate stays closed.

## Verification

Default checks: `.venv/bin/python -m pytest -q`, `.venv/bin/python -m ruff check .`, `.venv/bin/python -m mypy src`, `git diff --check`.

Use actual two-case CodeQL/LLM smoke for end-to-end behavior. Record terminal failures with concrete causes, not as success or accuracy results. Do not launch more cases to obtain a prettier result. Independent review covers repaired candidate identity, IRIS compatibility and CLI/budget integration before completion.
