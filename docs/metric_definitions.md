# Phase 0 metric definitions

- `num_results`: SARIF results that CodeQL emitted.
- `num_paths`: non-filtered CodeQL code flows.
- `detected_file`: at least one retained path intersects a fixed source file.
- `detected_method`: at least one retained path intersects a fixed method.
- `num_tp_paths_file`: retained paths intersecting a fixed source file.
- `num_tp_paths_method`: retained paths intersecting a fixed method.
- `num_tp_results_file` / `num_tp_results_method`: distinct SARIF result IDs
  containing at least one matching path.

These definitions intentionally mirror the IRIS v1 evaluation pipeline. Paths
whose first or last endpoint message contains `toString` or `println` are
excluded to preserve paper compatibility.
