# Phase 0 baseline result classes

These directories have deliberately different evidentiary meanings:

- `published_reference/` contains normalized rows imported from the result
  tables at the pinned IRIS commit. These numbers are useful for comparison,
  but they are not local executions.
- `codeql/` contains records produced by the local Docker CodeQL runner.
- `iris/` contains records produced by the local Docker IRIS runner.

Do not aggregate a `published_reference` record into a local rerun count. The
Phase 0 report generator enforces this by scanning only the dedicated `codeql/`
and `iris/` directories for local gate evidence.
