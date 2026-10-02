"""Prepare five-seed execution from sealed inputs and a development selection lock.

Plans preserve all frozen retrieval/prompt/budget settings and change only the
predeclared seed. A confounded verifier or missing development baseline lock
keeps expensive Full runs pending instead of fabricating completed robustness.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from src.baselines.validate import _verify_checksums
from src.common.provenance import sha256_file
from src.experiments.phase13 import RUN_ID
from src.experiments.phase13_snapshot import validate_snapshot
from src.reproduction.common import atomic_json, read_csv, read_jsonl

BASELINES = {
    "B3": "configs/baselines/b3_raw_context.yaml",
    "B4": "configs/baselines/b4_text_rag.yaml",
    "B5": "configs/baselines/b5_static_hypothesis.yaml",
    "B6": "configs/baselines/b6_program_graph_only.yaml",
    "B7": "configs/baselines/b7_security_kg_only.yaml",
    "B8": "configs/baselines/b8_useg_no_pruning.yaml",
    "B9": "configs/baselines/b9_full_useg.yaml",
}


def selection_lock(root: Path, path: Path) -> dict[str, Any]:
    selection: dict[str, Any] = json.loads(path.read_text())
    method = selection.get("selected_method")
    if selection.get("development_only") is not True or method not in {"B0", *BASELINES.keys()} - {
        "B9"
    }:
        raise ValueError("robustness selection must be a development-only fair baseline lock")
    development = {
        row["project_id"] for row in read_csv(root / "data/processed/splits/development.csv")
    }
    selected = selection.get("selected_project_ids", [])
    if len(selected) != len(development) or set(selected) != development:
        raise ValueError("baseline selection must cover exactly the frozen development split")
    candidates = selection.get("candidate_runs", {})
    if set(candidates) != {"B0", "B3", "B4", "B5", "B6", "B7", "B8"}:
        raise ValueError("baseline selection lacks complete fair-baseline candidate coverage")
    for baseline, lock in candidates.items():
        run = root / lock["run_root"]
        _verify_checksums(run)
        if sha256_file(run / "checksums.sha256") != lock["checksums_index_sha256"]:
            raise ValueError(f"development baseline checksum mismatch: {baseline}")
        manifest = json.loads((run / "manifest.json").read_text())
        if manifest.get("analysis_scope") != "development":
            raise ValueError("robustness selection includes an artifact outside development")
        active = [
            r
            for r in read_jsonl(run / "project_status.jsonl")
            if r["status"] != "EXCLUDED_WITH_REASON"
        ]
        if len(active) != len(development) or {r["project_id"] for r in active} != development:
            raise ValueError("development baseline candidate coverage mismatch")
    return selection


def seed_configs(
    root: Path,
    parent: Path,
    seed: int,
    baseline: str,
    destination: Path,
) -> tuple[Path, Path]:
    model = yaml.safe_load((root / "configs/models/gpt_oss_20b_openrouter.yaml").read_text())
    model["seed"] = seed
    destination.mkdir(parents=True, exist_ok=True)
    model_path = destination / "model.yaml"
    experiment_path = destination / "experiment.yaml"
    if baseline in {"B6", "B7", "B8", "B9"}:
        experiment = yaml.safe_load((parent / "configs/phase10.yaml").read_text())
        experiment["llm"]["model_config"] = model_path.relative_to(root).as_posix()
    else:
        experiment = yaml.safe_load((parent / "configs/phase13_baselines.yaml").read_text())
    for path, value in ((model_path, model), (experiment_path, experiment)):
        if path.exists() and yaml.safe_load(path.read_text()) != value:
            raise ValueError("immutable robustness config changed")
        if not path.exists():
            path.write_text(yaml.safe_dump(value, sort_keys=False))
    return model_path, experiment_path


def prepare(root: Path, run_id: str, audit_id: str, selection_path: Path | None) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("robustness planning requires evaluator role")
    if not RUN_ID.fullmatch(run_id) or not RUN_ID.fullmatch(audit_id):
        raise ValueError("invalid robustness run ID")
    parent = root / "results/phase13" / run_id
    snapshot_path = parent / "analyzer_snapshot.json"
    validate_snapshot(root, snapshot_path)
    audit = parent / "evaluation/audits" / audit_id
    _verify_checksums(audit)
    manifest = json.loads((audit / "manifest.json").read_text())
    if manifest["analyzer_snapshot_sha256"] != sha256_file(snapshot_path):
        raise ValueError("robustness audit belongs to a different analyzer snapshot")
    audit_summary = json.loads((audit / "summary.json").read_text())
    reasons = []
    if audit_summary["verified_specifications_audited"] and any(
        status in audit_summary["audit_status_counts"]
        for status in (
            "LINE_SHIFT_CONFOUNDED",
            "PATH_PERSISTS_AFTER_LINE_REMAP",
            "FIXED_ENDPOINT_UNRESOLVED",
        )
    ):
        reasons.append("VERIFIER_EVIDENCE_CONFOUNDED")
    selection = None
    if selection_path is None:
        reasons.append("MISSING_DEVELOPMENT_BASELINE_SELECTION_LOCK")
    else:
        selection = selection_lock(root, selection_path)
    config = yaml.safe_load((root / "configs/experiments/phase13.yaml").read_text())
    methods = ["Full", selection["selected_method"] if selection else "strongest_baseline_pending"]
    plans = []
    for method in methods:
        for seed in config["robustness"]["seeds"]:
            plans.append(
                {
                    "method": method,
                    "seed": seed,
                    "status": "PENDING" if reasons else "READY",
                    "run_id": f"{run_id}_{method.lower()}_s{seed}",
                    "canonical_seed": seed == config["canonical"]["seed"],
                }
            )
    output = parent / "evaluation/robustness_plan.json"
    atomic_json(
        output,
        {
            "schema_version": 1,
            "parent_run_id": run_id,
            "status": "PENDING_PREREQUISITES" if reasons else "READY_FOR_SEQUENTIAL_EXECUTION",
            "reasons": reasons,
            "runs": plans,
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
            "audit_checksums_sha256": sha256_file(audit / "checksums.sha256"),
            "selection_sha256": sha256_file(selection_path) if selection_path else None,
            "provider_route": "akashml",
            "temperature": 0.0,
            "budget_mode": "budget_matched",
            "project_workers": 1,
            "concurrent_codeql_and_llm": False,
            "canonical_artifacts_reused_only_for_seed_1234": True,
            "reusing_one_response_as_multiple_seeds_forbidden": True,
        },
    )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument("--audit-id", default="verification_audit_001")
    parser.add_argument("--selection-lock", type=Path)
    args = parser.parse_args()
    print(prepare(args.repo_root.resolve(), args.run_id, args.audit_id, args.selection_lock))
    return 0


if __name__ == "__main__":
    sys.exit(main())
