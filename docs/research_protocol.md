# Research protocol v2

Public entrypoint: `python -m maxvera pipeline research --config configs/pipelines/research.yaml --variant graph_only --mode full --run-id <new-id> --execute`. This full command has **not** been run. Default configuration selects the existing 96-project development split from `D_extended`; it must not use the disjoint IDs from `D_repro_v1`. The benchmark is already seen/development data; do not claim held-out generalization.

## Firewall and snapshots

`dataset prepare` is trusted data preparation and may read labels. `--sources` explicitly fetches pinned vulnerable sources, applies the existing dataset build patches and materializes opaque snapshots with generic build commands. It strips Git/build/patch files, rejects symlinks and hashes source content. Preparation may require network access and substantial storage; it was not run with `--sources` during migration.

The research worker runs under Linux Landlock ABI >=3 with a read and filesystem-mutation allowlist for `analysis_input`, runtime libraries, source modules and pinned toolchains as read-only inputs. Only the current run and its private build/cache directories are writable. It receives a filtered environment and no `.env`. It cannot read or overwrite `evaluator_only`, canonical manifests, raw metadata, reproduction output or other runs; symlink escape is denied. Unavailable Landlock fails closed. This is a filesystem leakage boundary; it is not a general hostile-code or network isolation sandbox.

Snapshots and metadata must already exist before research execution. Source fingerprints enter resume identity. A single inventory policy excludes Git/Gradle/build products. Builds run in a private copy; modified and generated source files are recorded, and graph provenance hashes the actual analyzed copy rather than pretending it is the unchanged input snapshot. Original source/CVE/advisory comments are not accepted as evidence blindly: analyzer output rejects CVE identifiers. Generic catalogue CWE families are allowed and fixed for every project.

## Graph and discovery

Custom CodeQL queries reuse the typed `Grounding.qll` infrastructure, extracting source-backed expression/parameter nodes, local conservative taint steps, argument-to-parameter edges and return-to-call edges. Node keys include span, expression kind and enclosing callable; overloads and shared spans cannot silently merge.

Graphs use deterministic JSONL adjacency data and graph hashes. Schema/provenance distinguish extracted facts from verified vulnerability claims. Static dispatch can miss overrides, lambdas, exceptions or external summaries; unresolved calls/partial build rate are explicitly unknown rather than fabricated zero. Current graph quality reports type counts, cross-file/orphan counts and provenance coverage. Maximum node/edge bounds fail explicitly. Traversal is bounded to five hops by default, 4096 visited nodes per endpoint; shortest paths are retained. Additional path alternatives may be missed.

Generators: generic CodeQL alerts, sink backward slicing and source forward slicing. Independent graph generators can produce a candidate when default alerts are empty. The versioned default-alert coverage rule compares source and sink file/line spans; graph evidence covered at both endpoints shares attribution with the alert and does not add a duplicate Top-K entry. This is a conservative coverage association, not proof that taint models or exploitability are equivalent. Candidate paths remain pre-verification hypotheses; CALLS alone cannot become dataflow. Candidates retain stable evidence IDs, locations, source origins and deterministic rank features. Scores are uncalibrated ranking values. Location-only static alerts are weak evidence; CodeQL code-flow results are recorded distinctly.

`static_only` and `graph_only` execute without a model. Disabled stages record `SKIPPED_BY_VARIANT` and do not emit fake LLM/verification files. `text_only`, `graph_llm` and `graph_llm_verify` are declared in the common variant catalogue but fail explicitly as **NOT_IMPLEMENTED**. Section 10 of the authoritative plan gates W7/W8 implementation at scale on a measured, frozen dev graph-only signal. No benchmark signal has been measured in this migration.

## Next scientific gate

After preparing source snapshots, run static-only and graph-only on a frozen dev set, evaluate raw output independently, inspect candidate coverage and missing evidence, and record the gate decision. Only then extend bounded evidence retrieval, citation validation, model reranking and targeted verification. Never use an LLM to hide discovery/extractor defects. USEG/KG/calibration remain optional legacy components, outside the new core DAG.
