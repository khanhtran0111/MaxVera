"""Evaluator-only Phase 6 candidate-CWE ranking metrics."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums


def aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    successful = [row for row in rows if row.get("status") == "SUCCESS"]

    def mean(field: str, values: Sequence[Mapping[str, Any]]) -> float:
        return sum(float(row.get(field, 0.0)) for row in values) / len(values) if values else 0.0

    return {
        "schema_version": 1,
        "projects": total,
        "analysis_successes": len(successful),
        "projects_with_hypotheses": sum(int(row.get("hypotheses", 0)) > 0 for row in rows),
        "hypothesis_recall_at_1": mean("hypothesis_recall_at_1", rows),
        "hypothesis_recall_at_3": mean("hypothesis_recall_at_3", rows),
        "hypothesis_recall_at_5": mean("hypothesis_recall_at_5", rows),
        "hypothesis_recall_at_10": mean("hypothesis_recall_at_10", rows),
        "hypothesis_mrr": mean("hypothesis_reciprocal_rank", rows),
        "hypothesis_recall_at_10_successes": mean("hypothesis_recall_at_10", successful),
        "candidate_pool_recall_at_40": mean("candidate_pool_recall_at_40", rows),
        "candidate_pool_mrr": mean("candidate_pool_reciprocal_rank", rows),
        "candidate_pool_recall_at_40_successes": mean("candidate_pool_recall_at_40", successful),
    }


def evaluate(run_root: Path, repo_root: Path) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("set MAXVERA_DATA_ROLE=evaluator for Phase 6 metric calculation")
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("phase") != 6 or manifest.get("dataset", {}).get("id") != "D_extended":
        raise ValueError("not a Phase 6 D_extended run")
    label_path = repo_root / "data/processed" / ("evaluator" + "_only") / "D_extended_labels.csv"
    labels = {row["project_id"]: row for row in read_csv(label_path)}
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in read_jsonl(run_root / "hypotheses.jsonl"):
        by_project[str(item["project_id"])].append(item)
    candidates_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in read_jsonl(run_root / "candidates.jsonl"):
        candidates_by_project[str(item["project_id"])].append(item)
    metrics: list[dict[str, Any]] = []
    for status in read_jsonl(run_root / "project_status.jsonl"):
        project_id = str(status["project_id"])
        if project_id not in labels:
            raise ValueError(f"Phase 6 project has no evaluator label: {project_id}")
        hypotheses = sorted(
            by_project.get(project_id, []), key=lambda item: int(item.get("rank", 999999))
        )
        matching_ranks = [
            int(item["rank"])
            for item in hypotheses
            if labels[project_id]["ground_truth_cwe"] in item.get("candidate_cwe", [])
        ]
        first_rank = min(matching_ranks) if matching_ranks else None
        candidates = sorted(
            candidates_by_project.get(project_id, []),
            key=lambda item: int(item.get("rank", 999999)),
        )
        candidate_matching_ranks = [
            int(item["rank"])
            for item in candidates
            if labels[project_id]["ground_truth_cwe"] in item.get("candidate_cwe", [])
        ]
        candidate_first_rank = min(candidate_matching_ranks) if candidate_matching_ranks else None
        success = status.get("status") == "SUCCESS"
        metrics.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": status["status"],
                "hypotheses": len(hypotheses) if success else 0,
                "first_correct_rank": first_rank if success else None,
                "hypothesis_recall_at_1": bool(success and first_rank and first_rank <= 1),
                "hypothesis_recall_at_3": bool(success and first_rank and first_rank <= 3),
                "hypothesis_recall_at_5": bool(success and first_rank and first_rank <= 5),
                "hypothesis_recall_at_10": bool(success and first_rank and first_rank <= 10),
                "hypothesis_reciprocal_rank": 1.0 / first_rank if success and first_rank else 0.0,
                "candidate_pool_size": len(candidates) if success else 0,
                "candidate_pool_first_correct_rank": candidate_first_rank if success else None,
                "candidate_pool_recall_at_40": bool(
                    success and candidate_first_rank and candidate_first_rank <= 40
                ),
                "candidate_pool_reciprocal_rank": (
                    1.0 / candidate_first_rank if success and candidate_first_rank else 0.0
                ),
            }
        )
    atomic_jsonl(run_root / "metrics_project.jsonl", metrics)
    atomic_json(run_root / "metrics_aggregate.json", aggregate(metrics))
    write_checksums(run_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    evaluate(args.run_root.resolve(), args.repo_root.resolve())
    print(f"Phase 6 evaluation completed: {args.run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
