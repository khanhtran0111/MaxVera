"""Conditional development calibration on v3 verified findings, with explicit fallback."""

from __future__ import annotations

import csv
import math
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.calibration.model import (
    calibration_metrics,
    fit_candidate,
    grouped_oof_predictions,
    predict,
    select_thresholds,
)
from src.common.provenance import sha256_file
from src.pipeline_v2.model import identifier
from src.pipeline_v2.runtime import Run, dependency, development_ids, selection_ids
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def eligibility(
    labels: Sequence[int], groups: Sequence[str], policy: Mapping[str, Any]
) -> dict[str, Any]:
    if len(labels) != len(groups) or any(label not in {0, 1} for label in labels):
        raise ValueError("calibration labels and repository groups must be aligned and binary")
    counts = Counter(labels)
    support = {
        str(label): len(
            {group for value, group in zip(labels, groups, strict=True) if value == label}
        )
        for label in (0, 1)
    }
    reasons = []
    if len(set(groups)) < int(policy["minimum_repository_groups"]):
        reasons.append("INSUFFICIENT_REPOSITORY_GROUPS")
    if any(counts[label] < int(policy["minimum_records_per_class"]) for label in (0, 1)):
        reasons.append("INSUFFICIENT_TWO_CLASS_RECORDS")
    if any(support[str(label)] < int(policy["minimum_groups_per_class"]) for label in (0, 1)):
        reasons.append("INSUFFICIENT_TWO_CLASS_GROUPS")
    if any(
        {label for label, group in zip(labels, groups, strict=True) if group != held_out} != {0, 1}
        for held_out in sorted(set(groups))
    ):
        reasons.append("SINGLE_CLASS_TRAINING_FOLD")
    return {
        "eligible": not reasons,
        "reasons": reasons,
        "verified_findings": len(labels),
        "repository_groups": len(set(groups)),
        "class_counts": {str(k): counts[k] for k in (0, 1)},
        "groups_per_class": support,
        "target": policy["target"],
    }


def wilson_lower(successes: int, count: int) -> float:
    if not count:
        return 0.0
    z = 1.959963984540054
    p = successes / count
    return (
        p + z * z / (2 * count) - z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count))
    ) / (1 + z * z / count)


def accept_policy(
    probabilities: Sequence[float],
    labels: Sequence[int],
    groups: Sequence[str],
    thresholds: Mapping[str, float],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    selected = [i for i, value in enumerate(probabilities) if value >= thresholds["tau_accept"]]
    lower = wilson_lower(sum(labels[i] for i in selected), len(selected))
    enough = len(selected) >= int(policy["minimum_accept_count"])
    enough_groups = len({groups[i] for i in selected}) >= int(policy["minimum_accept_groups"])
    return {
        "enabled": enough and enough_groups and lower >= float(policy["accept_wilson_lower_bound"]),
        "count": len(selected),
        "repository_groups": len({groups[i] for i in selected}),
        "wilson_lower_95": lower,
        "bound_scope": "OOF candidate-CWE correctness; observations may correlate within groups",
    }


def _development_rows(path: Path, allowed: set[str]) -> dict[str, dict[str, str]]:
    # Select the opaque development ID before accessing any evaluator target or group.
    with path.open(encoding="utf-8", newline="") as handle:
        return {
            row["project_id"]: dict(row)
            for row in csv.DictReader(handle)
            if row["project_id"] in allowed
        }


def phase12(
    root: Path,
    config: Mapping[str, Any],
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    phase6_relative: str,
    phase10_relative: str,
    phase11_relative: str,
    *,
    resume: bool = False,
    full: bool = False,
) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("Phase 12 requires a separate evaluator process")
    if not set(selected) <= set(selection_ids(root, config)):
        raise ValueError("calibration selection is outside registered cohort")
    fit_selected = set(selected) & set(development_ids(root))
    p6, lock6 = dependency(root, phase6_relative, selected, 6)
    p10, lock10 = dependency(root, phase10_relative, selected, 10)
    p11, lock11 = dependency(root, phase11_relative, selected, 11)
    dataset, policy = config["dataset"], config["calibration"]
    checked = {}
    for name in ("labels", "split_groups"):
        path = root / dataset[name]
        if sha256_file(path) != dataset[name + "_sha256"]:
            raise ValueError("development evaluator input checksum mismatch")
        checked[name] = path
    run = Run(
        root,
        "results/calibration/v2",
        run_id,
        12,
        config_path,
        selected,
        resume=resume,
        require_clean=full,
        dependencies={
            "phase6": lock6,
            "phase10": lock10,
            "phase11": lock11,
            "evaluator_inputs": {name: dataset[name + "_sha256"] for name in checked},
        },
    )
    all_results = read_jsonl(p11 / "verification_results.jsonl")
    if any(
        row["project_id"] not in selected
        or row.get("verification_version") != "semantic-differential-verifier-v3"
        for row in all_results
    ):
        raise ValueError("calibration requires selected development verifier v3 results")
    labels_by_project = _development_rows(checked["labels"], fit_selected)
    groups_by_project = _development_rows(checked["split_groups"], fit_selected)
    hypotheses = {row["hypothesis_id"]: row for row in read_jsonl(p6 / "hypotheses.jsonl")}
    specifications = {
        row["specification_id"]: row for row in read_jsonl(p10 / "specifications.jsonl")
    }
    rows, labels, groups = [], [], []
    application_features: dict[str, dict[str, float]] = {}
    for result in all_results:
        if result["status"] != "VERIFIED_DIFFERENTIAL":
            continue
        project = result["project_id"]
        if result["specification_id"] not in specifications:
            raise ValueError("verified finding lacks its frozen synthesis specification")
        hypothesis = hypotheses[result["hypothesis_id"]]
        paths = result["vulnerable"]["paths"]
        features = {
            "hypothesis_score": float(hypothesis["score"]),
            "path_count_score": min(1.0, len(paths) / 4),
            "path_compactness": 1 / (1 + min(map(len, paths))),
        }
        features["raw_score"] = sum(features.values()) / len(features)
        if project not in fit_selected:
            application_features[result["specification_id"]] = features
            continue
        if project not in labels_by_project or project not in groups_by_project:
            raise ValueError("verified finding lacks a development-only target/group")
        if groups_by_project[project].get("split") != "development":
            raise ValueError("repository group is outside development")
        if result["specification_id"] not in specifications:
            raise ValueError("verified finding lacks its frozen synthesis specification")
        target = int(result["candidate_cwe"] == labels_by_project[project]["ground_truth_cwe"])
        group = identifier("repo", groups_by_project[project]["repository_group"])
        labels.append(target)
        groups.append(group)
        rows.append(
            {
                "project_id": project,
                "specification_id": result["specification_id"],
                "candidate_cwe": result["candidate_cwe"],
                "target": target,
                "repository_group": group,
                "features": features,
            }
        )
    gate = eligibility(labels, groups, policy)
    atomic_json(run.work / "eligibility.json", gate)
    atomic_jsonl(run.work / "verified_features.jsonl", rows)
    model_name, thresholds, accept = None, {}, {"enabled": False}
    probabilities: dict[str, float] = {}
    frozen_probabilities: dict[str, float] = {}
    if gate["eligible"]:
        numeric = [row["features"] for row in rows]
        candidates = []
        for name in policy["candidates"]:
            values = grouped_oof_predictions(
                name, numeric, labels, groups, policy["feature_names"], policy["optimization"]
            )
            metrics = calibration_metrics(values, labels, int(policy["ece_bins"]))
            candidates.append({"model_name": name, "metrics": metrics, "predictions": values})
        candidates.sort(
            key=lambda item: (
                item["metrics"]["brier"],
                item["metrics"]["ece_equal_width"],
                item["metrics"]["aurc"],
                item["model_name"],
            )
        )
        chosen = candidates[0]
        model_name, values = chosen["model_name"], chosen["predictions"]
        routing = policy["routing"]
        thresholds = select_thresholds(
            values,
            labels,
            target_accept_precision=float(routing["target_accept_precision"]),
            target_verify_recall=float(routing["target_verify_recall"]),
            max_abstain_risk=float(routing["max_abstain_positive_rate"]),
            minimum_accept_count=int(routing["minimum_accept_count"]),
        )
        accept = accept_policy(values, labels, groups, thresholds, routing)
        model = fit_candidate(
            model_name, numeric, labels, policy["feature_names"], policy["optimization"]
        )
        atomic_json(
            run.work / "model.json",
            {
                "model_name": model_name,
                "model": model,
                "thresholds": thresholds,
                "accept_policy": accept,
                "target": policy["target"],
            },
        )
        atomic_json(
            run.work / "grouped_oof.json",
            {"candidates": candidates, "selection": model_name, "group_ids": groups},
        )
        probabilities = {
            row["specification_id"]: value for row, value in zip(rows, values, strict=True)
        }
        frozen_probabilities = {
            spec_id: predict(model, features) for spec_id, features in application_features.items()
        }
    if config["analysis_scope"] == "benchmark_diagnostic":
        atomic_json(
            run.work / "fit_scope.json",
            {
                "selected_project_ids": sorted(fit_selected),
                "test_labels_used": False,
                "development_split_sha256": dataset["development_split_sha256"],
                "application_specifications": sorted(application_features),
                "application_model_sha256": sha256_file(run.work / "model.json")
                if gate["eligible"]
                else None,
            },
        )
    routed = []
    for result in all_results:
        spec_id = result["specification_id"]
        probability = probabilities.get(spec_id, frozen_probabilities.get(spec_id))
        decision = "VERIFY" if result["status"] == "VERIFIED_DIFFERENTIAL" else "ABSTAIN"
        if probability is not None:
            if accept["enabled"] and probability >= thresholds["tau_accept"]:
                decision = "ACCEPT"
            elif probability < thresholds["tau_verify"]:
                decision = "ABSTAIN"
        routed.append(
            {
                "project_id": result["project_id"],
                "specification_id": result["specification_id"],
                "verification_status": result["status"],
                "decision": decision,
                "oof_candidate_cwe_probability": probabilities.get(spec_id),
                **(
                    {"frozen_candidate_cwe_probability": frozen_probabilities.get(spec_id)}
                    if config["analysis_scope"] == "benchmark_diagnostic"
                    else {}
                ),
                "calibrated_full_eligible": gate["eligible"],
            }
        )
    atomic_jsonl(run.work / "routing.jsonl", routed)
    for project in run.pending():
        run.status(project, "SUCCESS", "calibration eligibility and conservative routing recorded")
    return run.finalize(
        {
            "calibration_eligible": gate["eligible"],
            "calibrated_full": gate["eligible"],
            "ineligible_reasons": gate["reasons"],
            "selected_model": model_name,
            "accept_enabled": accept["enabled"],
            "verified_findings": len(rows),
            "routing_counts": dict(Counter(row["decision"] for row in routed)),
            "llm_calls": 0,
            "target_is_vulnerability_fdr": False,
        }
    )
