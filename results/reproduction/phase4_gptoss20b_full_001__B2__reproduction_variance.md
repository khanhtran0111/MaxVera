# Reproduction variance

Run: `phase4_gptoss20b_full_001`; baseline: `B2`; mode: `full`.

- Effective analyzer: CodeQL 2.26.2 with the 104 Phase 2 databases; the older patched IRIS CLI is incompatible with these databases.
- The IRIS condition is **IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter**, not an exact or numerical reproduction of the paper.
- OpenRouter model `openai/gpt-oss-20b` replaces the paper's 32B model; the provider route is pinned and model fallback is disabled.
- Effective generation limit is 2,048 tokens, matching the paper text; reasoning tokens count against this completion budget.
- README context is read from the pinned local project checkout; runtime network fetching is disabled.
- Canonical metrics contain 120 project rows. Artifact-compatible metrics add CVE-2021-21345 under CWE-094 to reproduce the public CSV's 121st row when run.
- Phase 2 failures remain explicit misses/statuses; they are never silently skipped.
- Independent ground-truth matching prefers method ranges, falls back to class ranges when method lines are blank, and uses file-level matching only when both method and class ranges are unavailable. The aggregate metrics record the count at each granularity.
