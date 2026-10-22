# Evaluation protocol v2

Analyzer modules do not import `maxvera.evaluation`. Evaluation is a separate CLI/process that requires labels and checks all raw-run checksums before reading them. Output lives under `results/evaluations/<run_id>/<protocol>` and never modifies analyzer findings.

## Reproduction

`iris_paper` uses the pinned upstream evaluator's code-flow and enclosing method/class matching. Both IRIS and the independent CodeQL reference carry branch-specific SARIF and program-point inventories. Failure in one branch is never replaced with output from the other. Canonical 120-case and legacy 121-row views are labeled separately; missing raw evidence is unknown, never synthesized.

Report detected/selected (120 for a full reproduction), detected/successfully-analyzed, per-CWE counts, failure accounting, AvgFDR and AvgF1 with explicit denominators. AvgFDR excludes cases with no alerts; AvgF1 includes all cases. These are paper-compatible labeled-path metrics under the dataset's annotations, not an estimate of repository-wide vulnerability precision.

## Zero hint

The preregistered strong match requires a complete extracted candidate evidence path or an actual CodeQL flow result that intersects annotated program points. Sink/source/location-only overlap is `weak_location_match`, reported separately. File-only truth annotations contribute only weak/ambiguous overlap, never strong discovery recall. Method/class spans are required for a strong program-point match. Known-CVE Recall@5/@10/@20 is measured before verification. Post-LLM recall is null until reranking is implemented. Confirmed detection requires `FLOW_FOUND`; graph-only review candidates are not confirmations.

Every declared case is in the denominator. An unmatched candidate is `UNKNOWN_UNREVIEWED`; no precision or FDR is estimated by treating unlabeled locations as negatives. Fixed-version differential and adjudicated negatives are future supplementary evaluation, not analyzer inputs.

## Comparison

The comparator validates evaluation checksums and enforces identical case IDs plus a condition manifest containing input/snapshot identity, analyzer/query implementation, recorded tool versions, evaluator/policy identity, label/truth hashes and budgets/model settings. It separates oracle and zero-hint panels. `--paired-llm` checks raw candidate-pool content without run IDs, ranks or LLM/verifier judgments; it does not compare only truncated Top-K output. Text-only is a pipeline-level comparison, not isolated evidence of graph benefit. It emits machine-readable JSON/CSV and does not automatically claim causality or significance.

Group-aware bootstrap/McNemar, manual ambiguous-match adjudication, full efficiency/peak-RAM summaries and retrieval-paired experiments remain **NOT_IMPLEMENTED** in the new evaluator. These limitations are explicit acceptance gaps, not positive experimental results.

## Integrity

Config/code/schema/source/tool fingerprints reject incompatible resume. Successful stage artifacts are hashed, including database relations, source archives and the upstream snapshots actually restored for later IRIS stages. Mutable partial workspace outputs are discarded before restoring a validated stage snapshot. Frozen runs and evaluations have checksum indexes. Full output with case failures can be evaluated transparently; a running/incomplete/tampered run cannot. Evaluator policy/code and clean pinned upstream IRIS identity are checked before reuse; a changed evaluator cannot silently return stale metrics. Evaluation publication is atomic. Smoke directories are separate from benchmark output; smoke metrics are labeled `SMOKE_NOT_BENCHMARK`.
