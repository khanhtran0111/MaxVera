# Phase 4 full reproduction export

Run ID: `phase4_gptoss20b_full_001`.

Đây là các bản sao thuận tiện đặt trực tiếp tại root `results/reproduction/`.
Output gốc và raw SARIF/log vẫn được giữ nguyên trong các thư mục baseline.

## Bảng tổng hợp

- [`phase4_gptoss20b_full_001__table_reproduction.csv`](phase4_gptoss20b_full_001__table_reproduction.csv)

## B0 — CodeQL zero-hint

- [`phase4_gptoss20b_full_001__B0__metrics_dataset_canonical.json`](phase4_gptoss20b_full_001__B0__metrics_dataset_canonical.json)
- [`phase4_gptoss20b_full_001__B0__metrics_artifact_compatible.json`](phase4_gptoss20b_full_001__B0__metrics_artifact_compatible.json)
- [`phase4_gptoss20b_full_001__B0__metrics_project.jsonl`](phase4_gptoss20b_full_001__B0__metrics_project.jsonl)
- [`phase4_gptoss20b_full_001__B0__status_summary.json`](phase4_gptoss20b_full_001__B0__status_summary.json)
- [`phase4_gptoss20b_full_001__B0__project_status.jsonl`](phase4_gptoss20b_full_001__B0__project_status.jsonl)
- [`phase4_gptoss20b_full_001__B0__manifest.json`](phase4_gptoss20b_full_001__B0__manifest.json)
- [`phase4_gptoss20b_full_001__B0__reproduction_variance.md`](phase4_gptoss20b_full_001__B0__reproduction_variance.md)

## B1 — CodeQL CWE-oracle reference

- [`phase4_gptoss20b_full_001__B1__metrics_dataset_canonical.json`](phase4_gptoss20b_full_001__B1__metrics_dataset_canonical.json)
- [`phase4_gptoss20b_full_001__B1__metrics_artifact_compatible.json`](phase4_gptoss20b_full_001__B1__metrics_artifact_compatible.json)
- [`phase4_gptoss20b_full_001__B1__metrics_project.jsonl`](phase4_gptoss20b_full_001__B1__metrics_project.jsonl)
- [`phase4_gptoss20b_full_001__B1__status_summary.json`](phase4_gptoss20b_full_001__B1__status_summary.json)
- [`phase4_gptoss20b_full_001__B1__project_status.jsonl`](phase4_gptoss20b_full_001__B1__project_status.jsonl)
- [`phase4_gptoss20b_full_001__B1__manifest.json`](phase4_gptoss20b_full_001__B1__manifest.json)
- [`phase4_gptoss20b_full_001__B1__reproduction_variance.md`](phase4_gptoss20b_full_001__B1__reproduction_variance.md)

## B2 — IRIS + GPT-OSS 20B/OpenRouter

- [`phase4_gptoss20b_full_001__B2__metrics_dataset_canonical.json`](phase4_gptoss20b_full_001__B2__metrics_dataset_canonical.json)
- [`phase4_gptoss20b_full_001__B2__metrics_artifact_compatible.json`](phase4_gptoss20b_full_001__B2__metrics_artifact_compatible.json)
- [`phase4_gptoss20b_full_001__B2__metrics_project.jsonl`](phase4_gptoss20b_full_001__B2__metrics_project.jsonl)
- [`phase4_gptoss20b_full_001__B2__status_summary.json`](phase4_gptoss20b_full_001__B2__status_summary.json)
- [`phase4_gptoss20b_full_001__B2__project_status.jsonl`](phase4_gptoss20b_full_001__B2__project_status.jsonl)
- [`phase4_gptoss20b_full_001__B2__manifest.json`](phase4_gptoss20b_full_001__B2__manifest.json)
- [`phase4_gptoss20b_full_001__B2__reproduction_variance.md`](phase4_gptoss20b_full_001__B2__reproduction_variance.md)

B2 có 99 `SUCCESS`, 5 `ANALYSIS_FAILED`, 11 `BUILD_FAILED` và 5
`CODEQL_DB_FAILED`. Metrics canonical giữ đủ 120 project và tính failure là miss.

Các file export là snapshot, không tự đồng bộ nếu output gốc được sinh lại.
