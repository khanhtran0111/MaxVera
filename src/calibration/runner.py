"""Phase 12 development-only calibration and selective routing runner."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.calibration.model import (
    calibration_metrics,
    fit_candidate,
    grouped_oof_predictions,
    predict,
    risk_coverage_curve,
    route,
    select_thresholds,
)
from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.reproduction.common import (
    atomic_json,
    atomic_jsonl,
    read_csv,
    read_jsonl,
    write_checksums,
)
from src.verification.validate import validate as validate_phase11

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
ROLE_KINDS = {"SOURCE", "SINK", "SANITIZER", "PROPAGATOR"}


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _check_file(repo_root: Path, path_value: object, expected: object) -> Path:
    path = repo_root / str(path_value)
    if not path.is_file():
        raise FileNotFoundError(path)
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"Phase 12 dependency checksum mismatch: {path}")
    return path


def _as_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"expected mapping for {label}")
    return cast(Mapping[str, Any], value)


def _node_cwes(node: Mapping[str, Any]) -> set[str]:
    properties = _as_mapping(node.get("properties", {}), "node properties")
    candidate = properties.get("candidate_cwe", [])
    if isinstance(candidate, str):
        return {candidate}
    if isinstance(candidate, list):
        return {str(value) for value in candidate}
    return set()


def _hypothesis_node(
    nodes: Mapping[str, Mapping[str, Any]], hypothesis_id: str
) -> Mapping[str, Any] | None:
    for node in nodes.values():
        if node.get("kind") != "HYPOTHESIS":
            continue
        properties = _as_mapping(node.get("properties", {}), "hypothesis properties")
        if properties.get("upstream_hypothesis_id") == hypothesis_id:
            return node
    return None


def _confidence(node: Mapping[str, Any] | None) -> float:
    if node is None:
        return 0.0
    components = node.get("confidence_components", [])
    if not isinstance(components, list):
        return 0.0
    values = [
        float(component["value"])
        for component in components
        if isinstance(component, Mapping) and isinstance(component.get("value"), (int, float))
    ]
    return sum(values) / len(values) if values else 0.0


def _provenance_score(nodes: Sequence[Mapping[str, Any]]) -> float:
    if not nodes:
        return 0.0
    values = []
    for node in nodes:
        provenance = node.get("provenance", [])
        count = len(provenance) if isinstance(provenance, list) else 0
        values.append(min(count / 2.0, 1.0))
    return sum(values) / len(values)


def _feature_row(
    result: Mapping[str, Any],
    specification: Mapping[str, Any],
    context: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    feature_config: Mapping[str, Any],
) -> dict[str, float]:
    vulnerable = _as_mapping(result.get("vulnerable", {}), "vulnerable result")
    caps = _as_mapping(feature_config["caps"], "feature caps")
    paths = vulnerable.get("paths", [])
    if not isinstance(paths, list):
        paths = []
    lengths = [len(path) for path in paths if isinstance(path, list) and path]
    path_compactness = (
        sum(2.0 / max(2, length) for length in lengths) / len(lengths) if lengths else 0.0
    )
    endpoint_ids: list[str] = []
    for role in ("sources", "sinks", "sanitizers", "propagators"):
        entries = specification.get(role, [])
        if isinstance(entries, list):
            endpoint_ids.extend(
                str(entry["node_id"])
                for entry in entries
                if isinstance(entry, Mapping) and isinstance(entry.get("node_id"), str)
            )
    endpoint_nodes = [nodes[node_id] for node_id in endpoint_ids if node_id in nodes]
    hypothesis = _hypothesis_node(nodes, str(result["hypothesis_id"]))
    hypothesis_properties = (
        _as_mapping(hypothesis.get("properties", {}), "hypothesis properties")
        if hypothesis is not None
        else {}
    )
    rank = int(hypothesis_properties.get("rank", 10))
    serialized = context.get("serialized_node_ids", [])
    serialized_ids = [str(value) for value in serialized] if isinstance(serialized, list) else []
    context_nodes = [nodes[node_id] for node_id in serialized_ids if node_id in nodes]
    security_roles = {
        str(_as_mapping(node.get("properties", {}), "security properties").get("external_kind"))
        for node in context_nodes
        if node.get("layer") == "security"
    }
    context_hypotheses = [node for node in context_nodes if node.get("kind") == "HYPOTHESIS"]
    agreeing = sum(str(result["candidate_cwe"]) in _node_cwes(node) for node in context_hypotheses)
    program_grounded = sum(node.get("layer") == "program" for node in endpoint_nodes)
    sanitizers = specification.get("sanitizers", [])
    sanitizer_count = len(sanitizers) if isinstance(sanitizers, list) else 0
    features = {
        "path_count_score": min(float(vulnerable.get("path_count", 0)) / int(caps["paths"]), 1.0),
        "path_compactness": path_compactness,
        "source_resolution_score": min(
            float(vulnerable.get("source_endpoints", 0)) / int(caps["endpoints"]), 1.0
        ),
        "sink_resolution_score": min(
            float(vulnerable.get("sink_endpoints", 0)) / int(caps["endpoints"]), 1.0
        ),
        "sanitizer_evidence": min(sanitizer_count / int(caps["sanitizers"]), 1.0),
        "kg_role_coverage": len(security_roles & ROLE_KINDS) / len(ROLE_KINDS),
        "provenance_score": _provenance_score(
            [node for node in [hypothesis, *endpoint_nodes] if node is not None]
        ),
        "hypothesis_score": _confidence(hypothesis),
        "hypothesis_rank_score": max(0.0, min(1.0, 1.0 - (rank - 1) / 9.0)),
        "cwe_agreement": agreeing / len(context_hypotheses) if context_hypotheses else 0.0,
        "program_grounding": program_grounded / len(endpoint_nodes) if endpoint_nodes else 0.0,
    }
    names = [str(name) for name in feature_config["names"]]
    if set(features) != set(names):
        raise ValueError("Phase 12 extracted feature schema does not match frozen config")
    weights = _as_mapping(feature_config["raw_score_weights"], "raw score weights")
    weight_total = sum(float(weights[name]) for name in names)
    if abs(weight_total - 1.0) > 1e-9:
        raise ValueError("Phase 12 raw score weights must sum to one")
    features["raw_score"] = sum(features[name] * float(weights[name]) for name in names)
    return features


def _binary_metrics(
    indexes: Sequence[int], labels: Sequence[int], total: int, total_positives: int
) -> dict[str, float | int]:
    true_positives = sum(labels[index] for index in indexes)
    return {
        "count": len(indexes),
        "coverage": len(indexes) / total if total else 0.0,
        "precision": true_positives / len(indexes) if indexes else 0.0,
        "recall": true_positives / total_positives if total_positives else 0.0,
        "true_positives": true_positives,
        "false_positives": len(indexes) - true_positives,
    }


def run(
    *,
    repo_root: Path,
    config_path: Path,
    output_root: Path,
    run_id: str,
    mode: str,
    limit: int | None,
) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("set MAXVERA_DATA_ROLE=evaluator for Phase 12 calibration")
    config = _mapping(config_path)
    if config.get("status") != "frozen_phase_12_development":
        raise ValueError("Phase 12 config is not frozen for development")
    if mode == "full" and limit is not None:
        raise ValueError("Phase 12 full mode forbids --limit")
    git = collect_git(repo_root)
    if mode == "full" and git["dirty"]:
        raise RuntimeError("Phase 12 full run requires a clean Git worktree")
    if output_root.exists():
        raise FileExistsError(f"Phase 12 output already exists: {output_root}")

    dependencies = _as_mapping(config["development_dependencies"], "dependencies")
    phase9 = _as_mapping(dependencies["phase9_nodes"], "Phase 9 lock")
    phase10 = _as_mapping(dependencies["phase10"], "Phase 10 lock")
    phase11 = _as_mapping(dependencies["phase11"], "Phase 11 lock")
    phase9_nodes_path = _check_file(repo_root, phase9["path"], phase9["sha256"])
    phase10_root = repo_root / str(phase10["run_root"])
    phase11_root = repo_root / str(phase11["run_root"])
    for name, key in (
        ("manifest.json", "manifest_sha256"),
        ("specifications.jsonl", "specifications_sha256"),
        ("contexts.jsonl", "contexts_sha256"),
        ("checksums.sha256", "checksums_index_sha256"),
    ):
        _check_file(phase10_root, name, phase10[key])
    for name, key in (
        ("manifest.json", "manifest_sha256"),
        ("verification_results.jsonl", "verification_results_sha256"),
        ("project_status.jsonl", "project_status_sha256"),
        ("checksums.sha256", "checksums_index_sha256"),
    ):
        _check_file(phase11_root, name, phase11[key])
    validate_phase11(phase11_root, repo_root=repo_root)

    dataset = _as_mapping(config["dataset"], "dataset")
    checked_dataset_paths: dict[str, Path] = {}
    for name in ("development_split", "forbidden_test_split", "labels", "split_groups"):
        checked_dataset_paths[name] = _check_file(
            repo_root, dataset[name], dataset[f"{name}_sha256"]
        )
    development_ids = {
        row["project_id"] for row in read_csv(checked_dataset_paths["development_split"])
    }
    locked_ids = {
        row["project_id"] for row in read_csv(checked_dataset_paths["forbidden_test_split"])
    }
    if development_ids & locked_ids:
        raise ValueError("development and locked-test splits overlap")
    labels_by_project = {
        row["project_id"]: row for row in read_csv(checked_dataset_paths["labels"])
    }
    groups_by_project = {
        row["project_id"]: row["repository_group"]
        for row in read_csv(checked_dataset_paths["split_groups"])
        if row.get("split") == dataset["required_split"]
    }

    nodes = {
        str(row["node_id"]): row for row in read_jsonl(phase9_nodes_path)
    }
    specifications = {
        str(row["specification_id"]): row
        for row in read_jsonl(phase10_root / "specifications.jsonl")
    }
    contexts = {
        str(row["context_id"]): row for row in read_jsonl(phase10_root / "contexts.jsonl")
    }
    label_policy = _as_mapping(config["label_policy"], "label policy")
    eligible_status = str(label_policy["eligible_phase11_status"])
    results = [
        row
        for row in read_jsonl(phase11_root / "verification_results.jsonl")
        if row.get("status") == eligible_status
    ]
    if limit is not None:
        if limit <= 0:
            raise ValueError("--limit must be positive")
        results = results[:limit]
    if not results:
        raise ValueError("no eligible Phase 11 differential findings for calibration")
    if any(str(row["project_id"]) in locked_ids for row in results):
        raise ValueError("Phase 12 attempted to use a locked-test project")
    if any(str(row["project_id"]) not in development_ids for row in results):
        raise ValueError("Phase 12 input is not development-only")

    feature_config = _as_mapping(config["features"], "features")
    feature_names = [str(name) for name in feature_config["names"]]
    records: list[dict[str, Any]] = []
    numeric_rows: list[dict[str, float]] = []
    labels: list[int] = []
    groups: list[str] = []
    for result in results:
        specification_id = str(result["specification_id"])
        specification = specifications.get(specification_id)
        if specification is None:
            raise ValueError(f"missing frozen Phase 10 specification: {specification_id}")
        context = contexts.get(str(specification["context_id"]))
        if context is None:
            raise ValueError(f"missing frozen Phase 10 context for {specification_id}")
        project_id = str(result["project_id"])
        label_row = labels_by_project.get(project_id)
        group = groups_by_project.get(project_id)
        if label_row is None or group is None:
            raise ValueError(f"missing development label/group for {project_id}")
        target = int(str(result["candidate_cwe"]) == label_row["ground_truth_cwe"])
        features = _feature_row(result, specification, context, nodes, feature_config)
        fold_id = hashlib.sha256(group.encode()).hexdigest()[:16]
        records.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "specification_id": specification_id,
                "hypothesis_id": result["hypothesis_id"],
                "candidate_cwe": result["candidate_cwe"],
                "phase11_status": result["status"],
                "fold_id": fold_id,
                "target": target,
                "features": features,
            }
        )
        numeric_rows.append(features)
        labels.append(target)
        groups.append(fold_id)
    if len(set(labels)) < 2:
        raise ValueError("Phase 12 calibration requires positive and negative development labels")

    calibration = _as_mapping(config["calibration"], "calibration")
    optimization = _as_mapping(calibration["optimization"], "optimization")
    bins = int(calibration["ece_bins"])
    candidate_metrics: dict[str, dict[str, float]] = {}
    candidate_predictions: dict[str, list[float]] = {}
    for candidate_value in calibration["candidates"]:
        candidate = str(candidate_value)
        probabilities = grouped_oof_predictions(
            candidate, numeric_rows, labels, groups, feature_names, optimization
        )
        candidate_predictions[candidate] = probabilities
        candidate_metrics[candidate] = calibration_metrics(probabilities, labels, bins)
    selected = min(
        candidate_metrics,
        key=lambda name: (
            candidate_metrics[name]["brier"],
            candidate_metrics[name]["ece_equal_width"],
            candidate_metrics[name]["aurc"],
            name,
        ),
    )
    selected_probabilities = candidate_predictions[selected]
    final_model = fit_candidate(
        selected, numeric_rows, labels, feature_names, optimization
    )
    final_probabilities = [predict(final_model, row) for row in numeric_rows]
    routing = _as_mapping(config["routing"], "routing")
    thresholds = select_thresholds(
        selected_probabilities,
        labels,
        target_accept_precision=float(routing["target_accept_precision"]),
        target_verify_recall=float(routing["target_verify_recall"]),
        max_abstain_risk=float(routing["max_abstain_positive_rate"]),
        minimum_accept_count=int(routing["minimum_accept_count"]),
    )
    decisions = [route(probability, thresholds) for probability in selected_probabilities]
    decision_rows = [
        {
            "schema_version": 1,
            "project_id": record["project_id"],
            "specification_id": record["specification_id"],
            "calibrated_probability_oof": probability,
            "calibrated_probability_refit": refit_probability,
            "decision": decision,
            "abstain_tier": (
                "HIGH_CONFIDENCE"
                if decision == "ABSTAIN" and probability <= thresholds["tau_abstain"]
                else "CONSERVATIVE"
                if decision == "ABSTAIN"
                else None
            ),
            "target": label,
            "evaluated_as_negative": False,
        }
        for record, probability, refit_probability, decision, label in zip(
            records, selected_probabilities, final_probabilities, decisions, labels, strict=True
        )
    ]
    accept_indexes = [index for index, decision in enumerate(decisions) if decision == "ACCEPT"]
    covered_indexes = [index for index, decision in enumerate(decisions) if decision != "ABSTAIN"]
    total_positives = sum(labels)
    summary = {
        "schema_version": 1,
        "phase": 12,
        "run_id": run_id,
        "mode": mode,
        "eligible_findings": len(records),
        "development_projects": len({str(record["project_id"]) for record in records}),
        "repository_groups": len(set(groups)),
        "positive_labels": total_positives,
        "negative_labels": len(labels) - total_positives,
        "selected_model": selected,
        "selected_oof_metrics": candidate_metrics[selected],
        "decision_counts": dict(sorted(Counter(decisions).items())),
        "non_abstained": _binary_metrics(
            covered_indexes, labels, len(labels), total_positives
        ),
        "accepted": _binary_metrics(accept_indexes, labels, len(labels), total_positives),
        "locked_test_used": False,
        "unverified_treated_as_negative": False,
        "llm_calls": 0,
        "network_calls": 0,
    }

    work = output_root.parent / f".{output_root.name}.inprogress"
    if work.exists():
        raise FileExistsError(f"Phase 12 work directory exists: {work}")
    work.mkdir(parents=True)
    try:
        atomic_jsonl(work / "features.jsonl", records)
        atomic_jsonl(
            work / "oof_predictions.jsonl",
            [
                {
                    "schema_version": 1,
                    "project_id": record["project_id"],
                    "specification_id": record["specification_id"],
                    "fold_id": record["fold_id"],
                    "target": label,
                    "probabilities": {
                        candidate: candidate_predictions[candidate][index]
                        for candidate in sorted(candidate_predictions)
                    },
                }
                for index, (record, label) in enumerate(zip(records, labels, strict=True))
            ],
        )
        atomic_json(
            work / "candidate_metrics.json",
            {
                "schema_version": 1,
                "validation": calibration["validation"],
                "selection_order": calibration["selection_order"],
                "candidates": candidate_metrics,
                "selected_model": selected,
            },
        )
        atomic_json(
            work / "model.json",
            {
                "schema_version": 1,
                "model_name": selected,
                "feature_version": feature_config["version"],
                "training_rows": len(records),
                "training_positive_labels": total_positives,
                "model": final_model,
            },
        )
        atomic_json(
            work / "thresholds.json",
            {
                "schema_version": 1,
                "selected_model": selected,
                **thresholds,
                "selection_source": "grouped_out_of_fold_development_predictions",
                "routing_rule": (
                    "ACCEPT if p>=tau_accept; VERIFY if p>=tau_verify; otherwise ABSTAIN; "
                    "p<=tau_abstain marks high-confidence abstention"
                ),
                "tau_abstain_interpretation": (
                    "largest observed low-score cutoff with development positive rate at or below "
                    "the frozen abstain-risk target; all p<tau_verify remain ABSTAIN"
                ),
                "locked_test_used": False,
            },
        )
        atomic_jsonl(work / "routing_decisions.jsonl", decision_rows)
        atomic_jsonl(
            work / "risk_coverage.jsonl",
            [
                {"schema_version": 1, **point}
                for point in risk_coverage_curve(selected_probabilities, labels)
            ],
        )
        atomic_json(work / "calibration_summary.json", summary)
        (work / "config.resolved.yaml").write_text(
            yaml.safe_dump(config, sort_keys=True), encoding="utf-8"
        )
        atomic_json(work / "environment.json", collect_environment(repo_root))
        (work / "command.txt").write_text(
            f"phase12_calibration --mode {mode} --run-id {run_id}\n", encoding="utf-8"
        )
        atomic_json(
            work / "manifest.json",
            {
                "schema_version": 1,
                "phase": 12,
                "protocol_version": config["protocol_version"],
                "experiment_id": config["experiment_id"],
                "run_id": run_id,
                "mode": mode,
                "created_at": utc_now(),
                "data_role": "evaluator",
                "data_access": "development labels only; test_locked forbidden",
                "locked_test_used": False,
                "config": {
                    "path": config_path.relative_to(repo_root).as_posix(),
                    "sha256": sha256_file(config_path),
                },
                "dependencies": {
                    "phase9_run_id": "p9_useg_dev_full_003",
                    "phase10_run_id": phase10["run_id"],
                    "phase11_run_id": phase11["run_id"],
                    "phase11_verification_results_sha256": phase11[
                        "verification_results_sha256"
                    ],
                },
                "evaluator_inputs": {
                    name: sha256_file(path) for name, path in checked_dataset_paths.items()
                },
                "git": git,
            },
        )
        (work / "STATUS").write_text("PASS\n", encoding="utf-8")
        write_checksums(work)
        output_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(work), str(output_root))
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase12_calibration.yaml")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid run ID")
    repo_root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    output_root = repo_root / "results/calibration/phase12" / args.run_id
    run(
        repo_root=repo_root,
        config_path=config_path.resolve(),
        output_root=output_root,
        run_id=args.run_id,
        mode=args.mode,
        limit=args.limit,
    )
    print(f"Phase 12 calibration completed: {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
