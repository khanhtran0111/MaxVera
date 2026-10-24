# Evaluation protocol v2

Analyzer modules do not import `maxvera.evaluation`. Evaluation is a separate CLI/process that requires labels and checks all raw-run checksums before reading them. Output lives under `results/evaluations/<run_id>/<protocol>` and never modifies analyzer findings.

## Reproduction

`legacy_artifact` uses the pinned upstream evaluator's alert-container counts and matching. `iris_paper` remains its backward-compatible alias. `paper_formula_path` uses the same matching but counts actual code-flow paths (`num_paths` and `num_tp_paths_method`). An alert container with no path contributes zero paths. Every output records its numerator, denominator and counting unit; metrics from these protocols must not be silently combined. Both IRIS and the independent CodeQL reference carry branch-specific SARIF and program-point inventories. Failure in one branch is never replaced with output from the other. Canonical 120-case and legacy 121-row views are labeled separately; missing raw evidence is unknown, never synthesized.

Report detected/selected (120 for a full reproduction), detected/successfully-analyzed, per-CWE counts, failure accounting, AvgFDR and AvgF1 with explicit denominators. AvgFDR excludes cases with zero counted units; AvgF1 includes all selected cases. Missing labels or required truth/method metadata cause an error naming the affected case IDs. These are annotation-dependent reproduction metrics, not an estimate of repository-wide vulnerability precision. Selecting the literal path formula alone does not establish fidelity to the original paper's runtime or data.

## Zero hint

The preregistered strong match requires a complete extracted candidate evidence path or an actual CodeQL flow result that intersects annotated program points. Sink/source/location-only overlap is `weak_location_match`, reported separately. File-only truth annotations contribute only weak/ambiguous overlap, never strong discovery recall. Method/class spans are required for a strong program-point match. Known-CVE Recall@5/@10/@20 is measured before verification. Final ranked recall requires a successful, complete cited assessment set and complete final ranks for every selected case; otherwise aggregate ranked recall is null. Confirmed detection requires `FLOW_FOUND`; graph-only review candidates are not confirmations.

Every declared case is in the denominator. An unmatched candidate is `UNKNOWN_UNREVIEWED`; no precision or FDR is estimated by treating unlabeled locations as negatives. Fixed-version differential and adjudicated negatives are future supplementary evaluation, not analyzer inputs.

## Comparison

The comparator validates evaluation checksums and enforces identical case IDs plus a condition manifest containing input/snapshot identity, analyzer/query implementation, recorded tool versions, evaluator/policy identity, label/truth hashes and budgets/model settings. It separates oracle and zero-hint panels. `--paired-llm` checks raw candidate-pool content without run IDs, ranks or LLM/verifier judgments; it does not compare only truncated Top-K output. Text-only is a pipeline-level comparison, not isolated evidence of graph benefit. It emits machine-readable JSON/CSV and does not automatically claim causality or significance.

Group-aware bootstrap/McNemar, manual ambiguous-match adjudication, full efficiency/peak-RAM summaries and retrieval-paired experiments remain **NOT_IMPLEMENTED** in the new evaluator. These limitations are explicit acceptance gaps, not positive experimental results.

## Integrity

Config/code/schema/source/tool fingerprints reject incompatible resume. Successful stage artifacts are hashed, including database relations, source archives and the upstream snapshots actually restored for later IRIS stages. Mutable partial workspace outputs are discarded before restoring a validated stage snapshot. Frozen runs and evaluations have checksum indexes. Full output with case failures can be evaluated transparently; a running/incomplete/tampered run cannot. Evaluator policy/code and clean pinned upstream IRIS identity are checked before reuse; a changed evaluator cannot silently return stale metrics. Evaluation publication is atomic. Smoke directories are separate from benchmark output; smoke metrics are labeled `SMOKE_NOT_BENCHMARK`.
