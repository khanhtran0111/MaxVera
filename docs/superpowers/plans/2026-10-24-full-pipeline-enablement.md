# Full research pipeline enablement

Continue the user's existing branch and dirty work towards the original v2
research specification. Do not restart IRIS reproduction, modify pinned
checkouts, alter existing snapshots, or overwrite frozen scientific output.

## Decisions

- The original specification permits negative findings (section 11.3) and requires
  full case accounting. The later positive pilot expansion rule remains the
  confirmatory acceptance policy; it must not be reported as a prerequisite that
  all operational execution or all valid negative experiments inherently require.
- Keep `graph_signal_approved: false`. A prospective exploratory experiment may
  be registered separately, after an actual frozen development measurement and
  review, with exact input/code/config identity and its limitations. This is a
  visible protocol amendment, never a scientific approval or a missing-truth fix.
- Upstream source/annotation conflicts stay unknown. No guessed location mapping,
  dropped case, fabricated annotation, or whole-cohort recall from a subset.
- Work in the existing branch, as requested in the preceding handoff. Initial
  changed files and frozen index hashes are saved in
  `logs/research_full_enablement_20261024/initial_state.json` and the accompanying
  tar/patch. No commit or push is required.

## Tasks

1. [x] Add trusted versioned source preparation to the public CLI. Verify the
   frozen release, fetch exact commits without full clones, reuse verified inputs,
   apply pinned build patches, retain all 120 manifest rows, and resume failures
   safely. Preserve canonical metadata and old sources.
2. [x] Repair installed Gradle and wrapper recipes so both build invocations
   compile under CodeQL; observed RED and targeted GREEN evidence.
3. [x] Enforce graph caps while reading and bounded subprocess diagnostics. Add
   disk guards with explicit failures and complete selected-case accounting.
4. [x] Separate execution readiness, truth evaluability and scientific approval.
   Add prospectively frozen exploratory experiment registration/validation with
   real development evidence and immutable condition binding, retaining the
   default reviewed-signal execution policy.
5. [x] Prepare and inspect the complete 120-source view. Investigate and repair
   concrete fetch/archive/build blockers without changing the original cohort.
6. [x] Run appropriate fresh default/static checks, actual CodeQL verification,
   and eligible end-to-end development checks. Review code independently and
   publish exact commands, live progress and remaining practical limits.

## Progress

- Initial audit: 11/120 input-ready; 107 missing sources, 2 legacy missing manifests.
- Full disk: approximately 295 GiB free. No existing pipeline worker was active.
- Source metadata itself contains confirmed version/commit inconsistencies for
  some pilot cases; evidence is being collected in `truth/` task logs. These do
  not authorize rewriting the canonical release or calling aligned spans true
  vulnerabilities.
- All 120 snapshots prepared with normalized-v2; independent exact-Git audit finds
  no missing Java/build inputs across 370676 Java and 14498 build inputs. Old views
  remain untouched. Mapping v3 rebinds exact unchanged 55 targets; 6/10 remain aligned.
- Scoped independent final review is clean; source omission/oracle-receipt and
  development-condition/tool-runtime findings were fixed with RED/GREEN proof.
- Actual v2 sandboxed CLI + same-identity resume and exact SARIF CodeQL fixtures:
  2 passed. Full benchmark and paid120-case execution were not launched.
- Final default suite: 712 passed, 5 skipped. Ruff, configured mypy (126 src files)
  and diff check pass. Actual full120 `--require execution` preflight exits 0.
- Offline preparation retry reuses 120/120 snapshots and preserves all 121
  source seals/manifest hashes. Resource-stop evaluation keeps proven known truth
  in the denominator; two new RED/GREEN regressions cover that terminal status.
