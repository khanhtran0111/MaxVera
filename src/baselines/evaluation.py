"""Evaluator-only metrics for Phase 5 hypothesis baselines."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.reproduction.common import (
    atomic_json,
    atomic_jsonl,
    normalize_uri,
    read_csv,
    read_jsonl,
    write_checksums,
)


def _positive(value: Any) -> int | None:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _truth_ranges(rows: Sequence[Mapping[str, Any]]) -> list[tuple[str, int | None, int | None]]:
    result: list[tuple[str, int | None, int | None]] = []
    for row in rows:
        start = _positive(row.get("method_start"))
        end = _positive(row.get("method_end"))
        if start is None or end is None or start > end:
            start = _positive(row.get("class_start"))
            end = _positive(row.get("class_end"))
        if start is None or end is None or start > end:
            start = end = None
        result.append((normalize_uri(str(row.get("file", ""))), start, end))
    return result


def _location_match(
    item: Mapping[str, Any], truth: Sequence[tuple[str, int | None, int | None]]
) -> bool:
    path = normalize_uri(str(item.get("file", "")))
    line = _positive(item.get("line"))
    return line is not None and any(
        path == truth_path and (start is None or end is None or start <= line <= end)
        for truth_path, start, end in truth
    )


def _aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    successful = [row for row in rows if row.get("status") == "SUCCESS"]

    def mean(field: str, values: Sequence[Mapping[str, Any]]) -> float:
        return sum(float(row.get(field, 0.0)) for row in values) / len(values) if values else 0.0

    return {
        "schema_version": 1,
        "projects": total,
        "analysis_successes": len(successful),
        "detected_projects": sum(bool(row.get("detected")) for row in rows),
        "recall_intention_to_analyze": mean("detected", rows),
        "recall_analysis_success_only": mean("detected", successful),
        "macro_precision_successes": mean("precision", successful),
        "macro_f1_successes": mean("f1", successful),
        "macro_fdr_successes": mean("fdr", successful),
        "hypothesis_recall_at_1": mean("hypothesis_recall_at_1", rows),
        "hypothesis_recall_at_3": mean("hypothesis_recall_at_3", rows),
        "hypothesis_recall_at_5": mean("hypothesis_recall_at_5", rows),
        "hypothesis_recall_at_10": mean("hypothesis_recall_at_10", rows),
        "hypothesis_mrr": mean("hypothesis_reciprocal_rank", rows),
        "total_alerts": sum(int(row.get("alerts", 0)) for row in rows),
        "total_true_location_alerts": sum(int(row.get("tp_alerts", 0)) for row in rows),
    }


def evaluate(run_root: Path, repo_root: Path) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("set MAXVERA_DATA_ROLE=evaluator for Phase 5 metric calculation")
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    dataset_id = str(manifest["dataset"]["id"])
    labels = read_csv(repo_root / f"data/processed/evaluator_only/{dataset_id}_labels.csv")
    label_by_id = {row["project_id"]: row for row in labels}
    truth_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(
        repo_root / f"data/processed/evaluator_only/{dataset_id}_fix_locations.jsonl"
    ):
        truth_by_id[str(row["project_id"])].append(row)
    hypotheses_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in read_jsonl(run_root / "hypotheses.jsonl"):
        hypotheses_by_id[str(item["project_id"])].append(item)
    statuses = read_jsonl(run_root / "project_status.jsonl")
    if len(statuses) != len(labels):
        raise ValueError("status coverage does not match evaluator release")
    metrics: list[dict[str, Any]] = []
    for status in statuses:
        project_id = str(status["project_id"])
        label = label_by_id[project_id]
        hypotheses = sorted(
            hypotheses_by_id.get(project_id, []), key=lambda item: int(item.get("rank", 999999))
        )
        truth = _truth_ranges(truth_by_id.get(project_id, []))
        matched = [item for item in hypotheses if _location_match(item, truth)]
        correct_cwe_ranks = [
            index
            for index, item in enumerate(hypotheses, start=1)
            if item.get("candidate_cwe") == label["ground_truth_cwe"]
        ]
        alerts = len(hypotheses)
        true_alerts = len(matched)
        precision = true_alerts / alerts if alerts else 0.0
        recall = 1.0 if true_alerts else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        first_rank = min(correct_cwe_ranks) if correct_cwe_ranks else None
        metrics.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": status["status"],
                "detected": bool(true_alerts),
                "alerts": alerts,
                "tp_alerts": true_alerts,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "fdr": 1.0 - precision if alerts else 0.0,
                "hypothesis_recall_at_1": bool(first_rank and first_rank <= 1),
                "hypothesis_recall_at_3": bool(first_rank and first_rank <= 3),
                "hypothesis_recall_at_5": bool(first_rank and first_rank <= 5),
                "hypothesis_recall_at_10": bool(first_rank and first_rank <= 10),
                "hypothesis_reciprocal_rank": 1.0 / first_rank if first_rank else 0.0,
            }
        )
    atomic_jsonl(run_root / "metrics_project.jsonl", metrics)
    atomic_json(run_root / "metrics_aggregate.json", _aggregate(metrics))
    write_checksums(run_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    evaluate(args.run_root.resolve(), args.repo_root.resolve())
    print(f"Phase 5 evaluation completed: {args.run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
