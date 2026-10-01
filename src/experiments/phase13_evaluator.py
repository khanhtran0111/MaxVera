"""Run sealed Phase 13 test metrics, differential verification and frozen routing.

Oracle B1/B2 and five-seed robustness remain separate Phase 13 workloads.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from src.baselines.evaluation import _location_match, _truth_ranges
from src.baselines.validate import _verify_checksums
from src.calibration.model import predict, route
from src.calibration.runner import _feature_row
from src.common.provenance import collect_git, sha256_file, utc_now
from src.experiments.phase13_snapshot import validate_snapshot
from src.reproduction.common import (
    aggregate_metrics,
    atomic_json,
    atomic_jsonl,
    evaluate_sarif,
    read_csv,
    read_jsonl,
    write_checksums,
)
from src.specification.evaluation import _endpoint_ids, _matches, _node_location, _truth_range
from src.verification.validate import validate as validate_verification


def _json(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(path.read_text())
    return result


def verification_config(root: Path, snapshot_path: Path) -> Path:
    snapshot = validate_snapshot(root, snapshot_path)
    run_id = str(snapshot["run_id"])
    config = yaml.safe_load(
        (root / "configs/experiments/phase11_static_verification.yaml").read_text()
    )
    config = copy.deepcopy(config)
    config.update(
        {
            "protocol_version": "1.9.0",
            "status": "frozen_phase_13_test_verification",
            "experiment_id": "phase13_test_static_verification",
            "analysis_scope": "test_locked",
            "purpose": "sealed_test_fixed_revision_differential_verification",
            "analyzer_snapshot": snapshot_path.relative_to(root).as_posix(),
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
        }
    )
    dependencies: dict[str, Any] = {}
    for phase, name in (("phase9", "phase9"), ("phase10", "B9")):
        previous = config["development_dependencies"][phase]
        sealed = snapshot["analysis_runs"][name]
        run = root / sealed["run_root"]
        dependencies[phase] = {
            "run_root": sealed["run_root"],
            "run_id": sealed["run_id"],
            "files": previous["files"],
            "sha256": {
                key: sha256_file(run / filename) for key, filename in previous["files"].items()
            },
        }
    config["development_dependencies"] = dependencies
    database_manifest = f"data/interim/phase13_database_manifests/{run_id}.json"
    database_status = f"data/interim/phase13_database_status/{run_id}.jsonl"
    config["databases"] = {
        "vulnerable_root": f"data/interim/phase13_codeql_databases/{run_id}",
        "preparation_manifest": database_manifest,
        "preparation_manifest_sha256": sha256_file(root / database_manifest),
        "build_status": database_status,
        "build_status_sha256": sha256_file(root / database_status),
        "fixed_root": f"data/interim/phase13_fixed_codeql_databases/{run_id}",
        "fixed_database_contract": "opaque_project_id_at_sealed_test_fix_revision",
    }
    path = snapshot_path.parent / "configs/phase13_verification.yaml"
    if path.exists():
        if yaml.safe_load(path.read_text()) != config:
            raise ValueError("immutable test verification config changed")
    else:
        path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


def _finalize(work: Path, final: Path, manifest: Mapping[str, Any]) -> None:
    atomic_json(work / "manifest.json", manifest)
    (work / "STATUS").write_text("SUCCESS\n")
    write_checksums(work)
    os.replace(work, final)


def _new_work(final: Path) -> Path:
    work = final.parent / f".{final.name}.inprogress"
    work.mkdir(parents=True, exist_ok=False)
    return work


def _metric(project_id: str, status: str, alerts: int, true_alerts: int) -> dict[str, Any]:
    if status != "SUCCESS":
        alerts = true_alerts = 0
    precision = true_alerts / alerts if alerts else 0.0
    recall = float(true_alerts > 0)
    return {
        "schema_version": 1,
        "project_id": project_id,
        "status": status,
        "alerts": alerts,
        "tp_alerts": true_alerts,
        "detected": bool(true_alerts),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fdr": 1 - precision if alerts else 0.0,
    }


def proxy_metrics(root: Path, snapshot_path: Path, output: Path) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("test metrics require evaluator role")
    snapshot = validate_snapshot(root, snapshot_path)
    if output.exists():
        _verify_checksums(output)
        return
    # No evaluator input is accessed until the entire analyzer snapshot validates.
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    truth_path = root / "data/processed/evaluator_only/D_extended_fix_locations.jsonl"
    labels = {row["project_id"]: row for row in read_csv(labels_path)}
    truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(truth_path):
        truth[str(row["project_id"])].append(row)
    selected = snapshot["selected_project_ids"]
    if set(selected) - labels.keys():
        raise ValueError("test labels have incomplete coverage")
    nodes = {
        str(row["node_id"]): row
        for row in read_jsonl(
            root / snapshot["analysis_runs"]["phase9"]["run_root"] / "useg/nodes.jsonl"
        )
    }
    work = _new_work(output)
    metrics: list[dict[str, Any]] = []
    aggregates: dict[str, Any] = {}
    for baseline in ("B0", "B3", "B4", "B5", "B6", "B7", "B8", "B9"):
        run = root / snapshot["analysis_runs"][baseline]["run_root"]
        statuses = {str(row["project_id"]): row for row in read_jsonl(run / "project_status.jsonl")}
        is_spec = baseline in {"B6", "B7", "B8", "B9"}
        candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in read_jsonl(run / ("specifications.jsonl" if is_spec else "hypotheses.jsonl")):
            candidates[str(row["project_id"])].append(row)
        rows: list[dict[str, Any]] = []
        for project_id in selected:
            status = str(statuses[project_id]["status"])
            if baseline == "B0":
                raw = statuses[project_id].get("sarif")
                metric = evaluate_sarif(
                    project_id,
                    status,
                    run / raw if isinstance(raw, str) else None,
                    truth[project_id],
                )
            else:
                items = candidates[project_id] if status == "SUCCESS" else []
                if is_spec:
                    ranges = [_truth_range(row) for row in truth[project_id]]
                    matched = sum(
                        item.get("candidate_cwe") == labels[project_id]["ground_truth_cwe"]
                        and any(
                            _matches(_node_location(nodes[node]), ranges)
                            for role in ("sources", "sinks")
                            for node in _endpoint_ids(item, role)
                            if node in nodes
                        )
                        for item in items
                    )
                else:
                    matched = sum(
                        _location_match(item, _truth_ranges(truth[project_id])) for item in items
                    )
                metric = _metric(project_id, status, len(items), matched)
            metric.update(
                {
                    "baseline_id": baseline,
                    "annotation_available": bool(truth[project_id]),
                    "interpretation": "cwe_and_endpoint_fix_location_proxy"
                    if is_spec
                    else "fix_location_proxy",
                }
            )
            rows.append(metric)
            metrics.append(metric)
        aggregates[baseline] = aggregate_metrics(rows)
        aggregates[baseline]["interpretation"] = rows[0]["interpretation"]
        print(f"PROXY_METRICS: {baseline} {len(rows)} test projects", flush=True)
    atomic_jsonl(work / "project_metrics.jsonl", metrics)
    atomic_json(work / "metrics_aggregate.json", aggregates)
    _finalize(
        work,
        output,
        {
            "schema_version": 1,
            "run_id": snapshot["run_id"],
            "created_at": utc_now(),
            "analysis_scope": "test_locked",
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
            "labels_sha256": sha256_file(labels_path),
            "fix_locations_sha256": sha256_file(truth_path),
            "selected_projects": len(selected),
            "annotated_projects": sum(bool(truth[p]) for p in selected),
            "failures_count_as_miss": True,
            "static_verification": False,
            "git": collect_git(root),
        },
    )


def frozen_routing(root: Path, snapshot_path: Path, verification: Path, output: Path) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("test routing requires evaluator role")
    snapshot = validate_snapshot(root, snapshot_path)
    print(validate_verification(verification, repo_root=root), flush=True)
    if output.exists():
        _verify_checksums(output)
        return
    calibration = root / "results/calibration/phase12" / snapshot["phase12_lock"]["run_id"]
    model_record = _json(calibration / "model.json")
    thresholds = _json(calibration / "thresholds.json")
    feature_config = yaml.safe_load(
        (root / "configs/experiments/phase12_calibration.yaml").read_text()
    )["features"]
    b9 = root / snapshot["analysis_runs"]["B9"]["run_root"]
    specs = {row["specification_id"]: row for row in read_jsonl(b9 / "specifications.jsonl")}
    contexts = {row["context_id"]: row for row in read_jsonl(b9 / "contexts.jsonl")}
    nodes = {
        row["node_id"]: row
        for row in read_jsonl(
            root / snapshot["analysis_runs"]["phase9"]["run_root"] / "useg/nodes.jsonl"
        )
    }
    statuses = {
        row["project_id"]: row["status"]
        for row in read_jsonl(verification / "project_status.jsonl")
    }
    records: list[dict[str, Any]] = []
    for result in read_jsonl(verification / "verification_results.jsonl"):
        if (
            result["status"] != "VERIFIED_DIFFERENTIAL"
            or statuses[result["project_id"]] != "SUCCESS"
        ):
            continue
        spec = specs[result["specification_id"]]
        features = _feature_row(result, spec, contexts[spec["context_id"]], nodes, feature_config)
        probability = predict(model_record["model"], features)
        records.append(
            {
                "project_id": result["project_id"],
                "specification_id": result["specification_id"],
                "candidate_cwe": result["candidate_cwe"],
                "features": features,
                "probability": probability,
                "decision": route(probability, thresholds),
            }
        )
    work = _new_work(output)
    atomic_jsonl(work / "routing_decisions.jsonl", records)
    atomic_json(
        work / "summary.json",
        {
            "eligible_findings": len(records),
            "decisions": dict(Counter(row["decision"] for row in records)),
            "model_refitted": False,
            "thresholds_retuned": False,
            "model_sha256": sha256_file(calibration / "model.json"),
            "thresholds_sha256": sha256_file(calibration / "thresholds.json"),
        },
    )
    _finalize(
        work,
        output,
        {
            "schema_version": 1,
            "run_id": snapshot["run_id"],
            "created_at": utc_now(),
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
            "verification_checksums_sha256": sha256_file(verification / "checksums.sha256"),
            "phase12_lock": snapshot["phase12_lock"],
            "git": collect_git(root),
        },
    )


def _command(root: Path, args: list[str]) -> int:
    print("$ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=root, check=False).returncode


def verification_metrics(
    root: Path,
    snapshot_path: Path,
    verification: Path,
    routing: Path,
    output: Path,
) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("verification metrics require evaluator role")
    snapshot = validate_snapshot(root, snapshot_path)
    print(validate_verification(verification, repo_root=root), flush=True)
    _verify_checksums(routing)
    if output.exists():
        _verify_checksums(output)
        return
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    labels = {row["project_id"]: row for row in read_csv(labels_path)}
    statuses = {
        row["project_id"]: row["status"]
        for row in read_jsonl(verification / "project_status.jsonl")
    }
    decisions = {
        row["specification_id"]: row["decision"]
        for row in read_jsonl(routing / "routing_decisions.jsonl")
    }
    results: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in read_jsonl(verification / "verification_results.jsonl"):
        if result["status"] == "VERIFIED_DIFFERENTIAL":
            results[result["project_id"]].append(result)
    rows: list[dict[str, Any]] = []
    aggregates: dict[str, Any] = {}
    for cohort in ("A5", "ACCEPT", "VERIFY", "ABSTAIN"):
        cohort_rows = []
        for project_id in snapshot["selected_project_ids"]:
            items = results[project_id] if statuses[project_id] == "SUCCESS" else []
            if cohort != "A5":
                items = [row for row in items if decisions.get(row["specification_id"]) == cohort]
            true_count = sum(
                row["candidate_cwe"] == labels[project_id]["ground_truth_cwe"] for row in items
            )
            row = _metric(project_id, statuses[project_id], len(items), true_count)
            row["cohort"] = cohort
            rows.append(row)
            cohort_rows.append(row)
        aggregates[cohort] = aggregate_metrics(cohort_rows)
        aggregates[cohort]["interpretation"] = (
            "verified_differential_and_candidate_cwe_correct"
            if cohort == "A5"
            else "frozen_routing_cohort_not_final_Full_verdict"
        )
    work = _new_work(output)
    atomic_jsonl(work / "project_metrics.jsonl", rows)
    atomic_json(work / "metrics_aggregate.json", aggregates)
    _finalize(
        work,
        output,
        {
            "schema_version": 1,
            "created_at": utc_now(),
            "analysis_scope": "test_locked",
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
            "verification_checksums_sha256": sha256_file(verification / "checksums.sha256"),
            "routing_checksums_sha256": sha256_file(routing / "checksums.sha256"),
            "labels_sha256": sha256_file(labels_path),
            "failures_count_as_miss": True,
            "label_policy": "same candidate-CWE positive definition as frozen Phase 12",
            "git": collect_git(root),
        },
    )


def run(root: Path, run_id: str, stage: str) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("Phase 13 evaluator requires MAXVERA_DATA_ROLE=evaluator")
    if collect_git(root).get("dirty") is not False:
        raise RuntimeError("Phase 13 evaluator requires a clean Git worktree")
    run_root = root / "results/phase13" / run_id
    snapshot_path = run_root / "analyzer_snapshot.json"
    validate_snapshot(root, snapshot_path)
    config_path = verification_config(root, snapshot_path)
    output = run_root / "evaluation"
    output.mkdir(exist_ok=True)
    verification = output / "verification" / f"{run_id}_verification"
    status_path = run_root / "evaluator_status.json"
    atomic_json(
        status_path,
        {
            "run_id": run_id,
            "started_at": utc_now(),
            "status": "RUNNING",
            "analyzer_snapshot_sha256": sha256_file(snapshot_path),
            "requested_stage": stage,
        },
    )
    try:
        if stage in {"all", "metrics"}:
            proxy_metrics(root, snapshot_path, output / "proxy_metrics")
        if stage in {"all", "verification"}:
            if not verification.exists():
                config = yaml.safe_load(config_path.read_text())
                fixed = root / config["databases"]["fixed_root"]
                preparation = fixed / "preparation_manifest.json"
                if (
                    not preparation.is_file()
                    or _json(preparation).get("preparation_complete") is not True
                ):
                    code = _command(
                        root,
                        [
                            sys.executable,
                            "-m",
                            "src.verification.prepare_fixed",
                            "--repo-root",
                            str(root),
                            "--config",
                            str(config_path),
                        ],
                    )
                    if (
                        code not in {0, 1}
                        or not preparation.is_file()
                        or not _json(preparation).get("preparation_complete")
                    ):
                        raise RuntimeError("fixed database preparation did not finish")
                args = [
                    sys.executable,
                    "-m",
                    "src.verification.runner",
                    "--repo-root",
                    str(root),
                    "--config",
                    str(config_path),
                    "--run-id",
                    verification.name,
                    "--mode",
                    "full",
                    "--verification-mode",
                    "differential",
                    "--output-root",
                    str(verification.parent),
                ]
                if (verification.parent / f".{verification.name}.inprogress").exists():
                    args.append("--resume")
                if _command(root, args):
                    raise RuntimeError("test verification stopped with an error")
            print(validate_verification(verification, repo_root=root), flush=True)
        if stage in {"all", "routing"}:
            frozen_routing(root, snapshot_path, verification, output / "frozen_routing")
            verification_metrics(
                root,
                snapshot_path,
                verification,
                output / "frozen_routing",
                output / "verification_metrics",
            )
        atomic_json(
            status_path,
            {
                "run_id": run_id,
                "updated_at": utc_now(),
                "status": "REQUESTED_STAGES_COMPLETED",
                "requested_stage": stage,
                "analyzer_snapshot_sha256": sha256_file(snapshot_path),
                "verification_root": verification.relative_to(root).as_posix(),
                "phase13_complete": False,
                "pending_phase13_workloads": [
                    "B1_oracle",
                    "B2_IRIS_oracle",
                    "five_seed_robustness",
                    "paired_project_bootstrap",
                    "final_ablation_report",
                ],
            },
        )
    except Exception as error:
        atomic_json(
            status_path,
            {
                "run_id": run_id,
                "updated_at": utc_now(),
                "status": "FAILED",
                "requested_stage": stage,
                "error": f"{type(error).__name__}: {error}",
            },
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument(
        "--stage", choices=("all", "metrics", "verification", "routing"), default="all"
    )
    args = parser.parse_args()
    run(args.repo_root.resolve(), args.run_id, args.stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
