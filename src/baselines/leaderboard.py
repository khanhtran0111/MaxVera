"""Generate a Phase 5 leaderboard exclusively from fully validated run roots."""

from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.baselines.validate import validate
from src.reproduction.common import read_jsonl


def _resource_totals(path: Path) -> tuple[int, int, int, int, int, float]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return (
        sum(int(row["calls"]) for row in rows),
        sum(int(row["input_tokens"]) for row in rows),
        sum(int(row["output_tokens"]) for row in rows),
        sum(int(row["reasoning_tokens"]) for row in rows),
        sum(int(row["billed_output_tokens"]) for row in rows),
        sum(float(row["api_cost_usd"]) for row in rows),
    )


def row_for_run(run_root: Path) -> dict[str, Any]:
    validate(run_root, require_metrics=True)
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((run_root / "metrics_aggregate.json").read_text(encoding="utf-8"))
    selected = {str(project_id) for project_id in manifest["selected_project_ids"]}
    statuses = read_jsonl(run_root / "project_status.jsonl")
    selected_successes = sum(
        row.get("project_id") in selected and row.get("status") == "SUCCESS" for row in statuses
    )
    (
        calls,
        input_tokens,
        output_tokens,
        reasoning_tokens,
        billed_output_tokens,
        cost,
    ) = _resource_totals(run_root / "resource_usage.csv")
    return {
        "baseline_id": manifest["baseline_id"],
        "baseline_name": manifest["baseline_name"],
        "run_id": manifest["run_id"],
        "run_status": (run_root / "STATUS").read_text(encoding="utf-8").strip(),
        "mode": manifest["mode"],
        "budget_mode": manifest["budget_mode"],
        "failure_policy": "count_as_miss",
        "selected_projects": len(selected),
        "selected_successes": selected_successes,
        "selected_failures": len(selected) - selected_successes,
        "projects": metrics["projects"],
        "analysis_successes": metrics["analysis_successes"],
        "detected_projects": metrics["detected_projects"],
        "recall_intention_to_analyze": metrics["recall_intention_to_analyze"],
        "macro_precision_successes": metrics["macro_precision_successes"],
        "macro_f1_successes": metrics["macro_f1_successes"],
        "hypothesis_recall_at_10": metrics["hypothesis_recall_at_10"],
        "hypothesis_mrr": metrics["hypothesis_mrr"],
        "calls": calls,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "billed_output_tokens": billed_output_tokens,
        "api_cost_usd": round(cost, 8),
    }


def write_leaderboard(run_roots: Sequence[Path], output: Path) -> None:
    rows = sorted(
        (row_for_run(path.resolve()) for path in run_roots),
        key=lambda row: (str(row["budget_mode"]), str(row["baseline_id"])),
    )
    if not rows:
        raise ValueError("at least one validated run root is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, action="append", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/aggregate/phase5_baseline_leaderboard.csv"),
    )
    args = parser.parse_args(argv)
    write_leaderboard(args.run_root, args.output.resolve())
    print(f"Validated-run leaderboard written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
