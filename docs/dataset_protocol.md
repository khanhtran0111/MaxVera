# Dataset protocol

Phase 0 uses two strictly separate tracks:

- `legacy`: direct IRIS v1 reproduction. The canonical dataset commit is the
  submodule commit pinned by the IRIS paper artifact, not the current default
  branch of CWE-Bench-Java.
- `v2`: a frozen input for later zero-hint experiments. Its metrics must never
  be combined with legacy metrics.

The commands under `scripts/data/` create a source-controlled snapshot
manifest and generated inventory. Third-party checkouts stay under
`data/external/` and are ignored by Git.

Every runtime case receives an opaque ID. The upstream `project_slug` is not a
runtime identifier because it embeds the CVE. Repository URL, vulnerable
revision, public repository documentation, and build metadata are allowed.
Ground-truth CWE/CVE/advisory/fix data is written only below
`data/ground_truth/` and is read only by `openiris.evaluation`.
