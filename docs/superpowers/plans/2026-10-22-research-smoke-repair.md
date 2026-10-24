# Research smoke repair implementation plan

**Goal:** Implement the research flow requested in the supplied review and verify at most two smoke cases; do not launch full experiments.

**Spec:** User attachment “Đánh giá MaxVera trước khi chạy full pipeline”, supplied2026-10-22. Existing research architecture, provider/model and strict analysis/evaluation isolation are retained.

**Design:** Candidate discovery and pre-LLM ranks remain immutable. Bounded, cited LLM evidence only changes final support/rank; targeted CodeQL verification reports evidence without treating no-flow as safety. Offline evaluator protocols explicitly separate public artifact alert counts from literal path metrics. User's request authorizes these fixes and smoke execution; no full-run or model/provider substitution.

**Constraints:** GPT-OSS-20B, pinned Groq route, no full mode; max2 smoke cases; private request journals; uncertain-charge calls are never automatically retried; no oracle input in analyzer; immutable old runs.

## Work checklist

- [x] 1. Evaluator correctness and bounded-memory checksum verification (agent): fail-first tests for empty-path denominators, protocol provenance, duplicate/tampered inventories; preserve iris_paper legacy alias.
- [x] 2. Research evidence/reasoning/verification (agent): real bounded code/graph evidence, citations, durable research-only requests; negative model/no-flow results never drop candidates; tests before implementation.
- [x] 3. CLI/config/runtime integration (root): smoke-only access to research LLM variants; full gated pending development signal; parent-to-worker credential transfer without secret files; stage dependencies and final ranking; dry-run call ceilings; runtime regressions fail before changes.
- [x] 4. Verify and report (root + independent review): 460 default tests passed, 2 expected opt-in skips; Ruff/mypy/diff checks passed. Actual two-case CodeQL smoke and 5 paid completions, frozen candidate identity, DB integrity, unchanged completed resume and isolated evaluator verified. [Report](../../research_smoke_2026-10-22.md) records zero known-CVE recall and unproven full-run gates explicitly.

## Smoke choices

Prefer two small real development projects when label-free snapshots and builds are available. Otherwise use two explicitly labeled Java fixture cases with actual CodeQL and provider calls, and report clearly that real-repository readiness remains unproven. No synthetic output may be presented as live verification.

## Review focus

Credential serialization, oracle-path escape, candidate count preservation after negative/error verdicts, unsupported verification endpoints, and evaluator protocol identity must have regression coverage. No automatic push or full experiment is part of this task.
