# Leakage policy

Runtime analysis may read only its sanitized runtime-view manifest and the
vulnerable repository checkout. It must not receive any of the following:

- CVE or ground-truth CWE identifiers;
- advisory or vulnerability descriptions;
- patches, fix commits, or fixed source;
- ground-truth vulnerable locations;
- manually curated source/sink annotations.

The boundary is enforced in three ways:

1. runtime manifests have a strict allow-list and opaque instance IDs;
2. ground truth is generated under a physically separate directory and loaded
   by `openiris.evaluation.ground_truth` only;
3. leakage tests scan manifest keys/values, source imports, and generated paths.

Phase 0 reproduction is an oracle-CWE protocol. The evaluator may join the
ground-truth CWE to choose the matching built-in CodeQL query, but that join is
recorded as `oracle_cwe: true` and is not reusable by the Phase 1 zero-hint
runtime.
