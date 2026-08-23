# Phase results

This directory is the only source-controlled location for aggregate and frozen outputs that belong to a research phase.

Each `phase_<NN>/` may contain:

- `baselines/`: normalized aggregate records;
- `audits/`: environment, provenance and accounting evidence;
- `model_smoke/`: local runtime health records;
- `tables/` and `figures/`: generated summaries;
- `status.json`: machine-readable gate state;
- `report.md`: human-readable phase report.

Large raw artifacts remain in append-only `runs/<run_id>/` and are Git-ignored. Every frozen result must still identify the producing run IDs.
