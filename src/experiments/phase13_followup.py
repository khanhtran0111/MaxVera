"""Run auditable Phase 13 follow-up workloads sequentially, with progress checkpoints."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from src.common.provenance import utc_now
from src.experiments.phase13_audit import run as audit
from src.experiments.phase13_oracles import run as oracle
from src.experiments.phase13_report import run as report
from src.experiments.phase13_robustness import prepare
from src.reproduction.common import atomic_json


def run(root: Path, run_id: str) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("follow-up execution requires evaluator role")
    from src.experiments.phase13 import RUN_ID

    if not RUN_ID.fullmatch(run_id):
        raise ValueError("invalid follow-up run ID")
    parent = root / "results/phase13" / run_id
    status_path = parent / "evaluation/followup_status.json"
    status: dict[str, Any] = {
        "parent_run_id": run_id,
        "started_at": utc_now(),
        "status": "RUNNING",
        "phase13_complete": False,
        "completed_stages": [],
    }

    def checkpoint(stage: str) -> None:
        status["current_stage"] = stage
        status["updated_at"] = utc_now()
        atomic_json(status_path, status)
        print(f"FOLLOWUP_STAGE: {stage}", flush=True)

    try:
        checkpoint("verification_audit")
        audit(root, run_id, "verification_audit_001", check_fixed=True, resume=True)
        status["completed_stages"].append("verification_audit")
        checkpoint("robustness_prerequisites")
        plan_path = prepare(root, run_id, "verification_audit_001", None)
        status["robustness"] = json.loads(plan_path.read_text())["status"]
        checkpoint("initial_progress_report")
        report(root, run_id, "ablation_progress_001", "verification_audit_001")
        status["completed_stages"].append("initial_progress_report")
        for baseline in ("B1", "B2"):
            checkpoint(baseline + "_oracle")
            oracle(root, run_id, baseline, resume=True)
            status["completed_stages"].append(baseline + "_oracle")
            checkpoint("report_after_" + baseline)
            report(root, run_id, "ablation_after_" + baseline.lower(), "verification_audit_001")
        status["status"] = "AVAILABLE_WORKLOADS_COMPLETED_WITH_PENDING_PREREQUISITES"
        status["pending_workloads"] = [
            "Full_verdict_and_verifier_review",
            "development_baseline_selection_lock",
            "five_seed_robustness",
            "final_ablation_report",
        ]
        checkpoint("completed")
    except Exception as error:
        status["status"] = "FAILED"
        status["error"] = f"{type(error).__name__}: {error}"
        atomic_json(status_path, status)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    args = parser.parse_args()
    run(args.repo_root.resolve(), args.run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
