"""Evaluator-only Phase 4 process; analysis runners must not import this module."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.reproduction.common import (
    aggregate_metrics,
    atomic_json,
    atomic_jsonl,
    evaluate_sarif,
    read_jsonl,
    write_checksums,
)
from src.reproduction.runner import BASELINE_ROOTS


def _truth_index(root: Path) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    path = root / "data/processed/evaluator_only/D_repro_v1_fix_locations.jsonl"
    for row in read_jsonl(path):
        result[str(row["project_id"])].append(row)
    return result


def evaluate_run(root: Path, baseline_id: str, run_id: str) -> None:
    run_root = root / "results/reproduction" / BASELINE_ROOTS[baseline_id] / run_id
    statuses = read_jsonl(run_root / "project_status.jsonl")
    if len(statuses) != 120:
        raise ValueError(f"{baseline_id}: evaluator requires 120 status rows")
    truth = _truth_index(root)
    metrics: list[dict[str, Any]] = []
    for row in statuses:
        project_id = str(row["project_id"])
        raw_sarif = row.get("sarif")
        sarif = root / str(raw_sarif) if isinstance(raw_sarif, str) else None
        metrics.append(
            evaluate_sarif(project_id, str(row["status"]), sarif, truth.get(project_id, []))
        )
    atomic_jsonl(run_root / "metrics_project.jsonl", metrics)
    atomic_json(run_root / "metrics_dataset_canonical.json", aggregate_metrics(metrics))

    artifact_rows = list(metrics)
    extra_path = run_root / "projects/proj_94f9beab9c96c8392ec8/artifact_row_121.json"
    artifact_complete = False
    if extra_path.is_file():
        extra = json.loads(extra_path.read_text(encoding="utf-8"))
        raw_sarif = extra.get("sarif")
        sarif = root / raw_sarif if isinstance(raw_sarif, str) else None
        variant = evaluate_sarif(
            "proj_94f9beab9c96c8392ec8",
            str(extra.get("status")),
            sarif,
            truth.get("proj_94f9beab9c96c8392ec8", []),
        )
        variant.update(
            {
                "project_id": "proj_94f9beab9c96c8392ec8#CWE-94",
                "canonical_project_id": "proj_94f9beab9c96c8392ec8",
                "artifact_cwe": "CWE-94",
            }
        )
        artifact_rows.append(variant)
        artifact_complete = extra.get("status") == "SUCCESS"
    artifact_metrics = aggregate_metrics(artifact_rows)
    artifact_metrics["artifact_row_121_present"] = artifact_complete
    artifact_metrics["expected_rows"] = 121
    atomic_json(run_root / "metrics_artifact_compatible.json", artifact_metrics)
    write_checksums(run_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("set MAXVERA_DATA_ROLE=evaluator for metric calculation")
    root = args.repo_root.resolve()
    for baseline_id in BASELINE_ROOTS:
        evaluate_run(root, baseline_id, args.run_id)
        print(f"{baseline_id}: independent evaluation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
