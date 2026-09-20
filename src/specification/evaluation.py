"""Evaluator-only annotated proxy metrics for frozen Phase 10 specifications."""

from __future__ import annotations

import argparse
import os
import re
import shutil
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import collect_git, sha256_file, utc_now
from src.reproduction.common import (
    atomic_json,
    atomic_jsonl,
    normalize_uri,
    read_csv,
    read_jsonl,
    write_checksums,
)
from src.specification.validate import validate as validate_phase10

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _positive(value: object) -> int | None:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _truth_range(row: Mapping[str, Any]) -> tuple[str, int | None, int | None]:
    start = _positive(row.get("method_start"))
    end = _positive(row.get("method_end"))
    if start is None or end is None or start > end:
        start = _positive(row.get("class_start"))
        end = _positive(row.get("class_end"))
    if start is None or end is None or start > end:
        start = end = None
    return normalize_uri(str(row.get("file", ""))), start, end


def _node_location(node: Mapping[str, Any]) -> tuple[str, int] | None:
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    if node.get("layer") == "program":
        location = properties.get("location")
        if not isinstance(location, Mapping):
            return None
        file_name = location.get("file")
        line = _positive(location.get("start_line"))
    elif node.get("layer") == "evidence":
        file_name = properties.get("file")
        line = _positive(properties.get("line"))
    else:
        return None
    if not isinstance(file_name, str) or line is None:
        return None
    return normalize_uri(file_name), line


def _matches(
    location: tuple[str, int] | None,
    truth: Sequence[tuple[str, int | None, int | None]],
) -> bool:
    if location is None:
        return False
    file_name, line = location
    return any(
        file_name == truth_file
        and (start is None or end is None or start <= line <= end)
        for truth_file, start, end in truth
    )


def _endpoint_ids(specification: Mapping[str, Any], role: str) -> list[str]:
    entries = specification.get(role)
    if not isinstance(entries, list):
        return []
    return [
        str(entry["node_id"])
        for entry in entries
        if isinstance(entry, Mapping) and isinstance(entry.get("node_id"), str)
    ]


def _aggregate(
    baseline_id: str,
    annotated_ids: Sequence[str],
    statuses: Mapping[str, Mapping[str, Any]],
    spec_rows: Sequence[Mapping[str, Any]],
    project_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    specifications = len(spec_rows)
    proxy_true = sum(bool(row.get("paper_proxy_match")) for row in spec_rows)
    correct_cwe = sum(bool(row.get("candidate_cwe_correct")) for row in spec_rows)
    locatable = sum(bool(row.get("has_locatable_endpoint")) for row in spec_rows)
    detected = sum(bool(row.get("detected")) for row in project_rows)
    successes = sum(statuses[project_id].get("status") == "SUCCESS" for project_id in annotated_ids)
    return {
        "schema_version": 1,
        "baseline_id": baseline_id,
        "annotated_projects": len(annotated_ids),
        "analysis_successes": successes,
        "analysis_failures": len(annotated_ids) - successes,
        "specifications": specifications,
        "candidate_cwe_correct_specifications": correct_cwe,
        "locatable_endpoint_specifications": locatable,
        "paper_proxy_true_specifications": proxy_true,
        "spec_precision_proxy": proxy_true / specifications if specifications else 0.0,
        "project_recall_proxy_intention_to_analyze": (
            detected / len(annotated_ids) if annotated_ids else 0.0
        ),
        "project_recall_proxy_analysis_success_only": detected / successes if successes else 0.0,
        "interpretation": "paper_compatible_fix_location_proxy_not_static_verification",
    }


def evaluate(*, repo_root: Path, config_path: Path, output_root: Path, run_id: str) -> None:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("set MAXVERA_DATA_ROLE=evaluator for Phase 10 spec evaluation")
    config = _mapping(config_path)
    if config.get("status") != "frozen_phase_10_development_evaluation":
        raise ValueError("Phase 10 evaluation config is not frozen")
    if output_root.exists():
        raise FileExistsError(f"Phase 10 evaluation output already exists: {output_root}")

    dataset = cast(Mapping[str, Any], config["dataset"])
    development_ids = [
        row["project_id"] for row in read_csv(repo_root / str(dataset["development_split"]))
    ]
    locked_ids = {
        row["project_id"]
        for row in read_csv(repo_root / str(dataset["forbidden_test_split"]))
    }
    if set(development_ids) & locked_ids:
        raise ValueError("development and locked-test split overlap")
    labels = {
        row["project_id"]: row for row in read_csv(repo_root / str(dataset["labels"]))
    }
    truth_by_project: dict[str, list[tuple[str, int | None, int | None]]] = defaultdict(list)
    for row in read_jsonl(repo_root / str(dataset["fix_locations"])):
        project_id = str(row["project_id"])
        if project_id in development_ids:
            truth_by_project[project_id].append(_truth_range(row))
    annotated_ids = [project_id for project_id in development_ids if truth_by_project[project_id]]
    if set(annotated_ids) & locked_ids or not annotated_ids:
        raise ValueError("invalid annotated development subset")

    nodes = {
        str(node["node_id"]): node
        for node in read_jsonl(repo_root / str(config["phase9_nodes"]))
    }
    work = output_root.parent / f".{output_root.name}.inprogress"
    if work.exists():
        raise FileExistsError(f"Phase 10 evaluation work directory exists: {work}")
    work.mkdir(parents=True)
    try:
        all_spec_rows: list[dict[str, Any]] = []
        all_project_rows: list[dict[str, Any]] = []
        aggregates: dict[str, dict[str, Any]] = {}
        dependencies: dict[str, Any] = {}
        phase10_runs = cast(Mapping[str, Any], config["phase10_runs"])
        for baseline_id in ("B6", "B7", "B8", "B9"):
            lock = cast(Mapping[str, Any], phase10_runs[baseline_id])
            run_root = repo_root / str(lock["run_root"])
            validate_phase10(run_root, repo_root=repo_root)
            manifest_sha = sha256_file(run_root / "manifest.json")
            summary_sha = sha256_file(run_root / "phase10_summary.json")
            if manifest_sha != lock["manifest_sha256"] or summary_sha != lock["summary_sha256"]:
                raise ValueError(f"Phase 10 {baseline_id} lock checksum mismatch")
            dependencies[baseline_id] = {
                "run_id": lock["run_id"],
                "manifest_sha256": manifest_sha,
                "summary_sha256": summary_sha,
            }
            statuses = {
                str(row["project_id"]): row
                for row in read_jsonl(run_root / "project_status.jsonl")
            }
            specifications = read_jsonl(run_root / "specifications.jsonl")
            by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
            baseline_spec_rows: list[dict[str, Any]] = []
            for specification in specifications:
                project_id = str(specification["project_id"])
                if project_id not in annotated_ids:
                    continue
                source_ids = _endpoint_ids(specification, "sources")
                sink_ids = _endpoint_ids(specification, "sinks")
                source_locations = [_node_location(nodes[node_id]) for node_id in source_ids]
                sink_locations = [_node_location(nodes[node_id]) for node_id in sink_ids]
                truth = truth_by_project[project_id]
                source_match = any(_matches(location, truth) for location in source_locations)
                sink_match = any(_matches(location, truth) for location in sink_locations)
                cwe_correct = specification.get("candidate_cwe") == labels[project_id][
                    "ground_truth_cwe"
                ]
                row = {
                    "schema_version": 1,
                    "baseline_id": baseline_id,
                    "project_id": project_id,
                    "specification_id": specification["specification_id"],
                    "hypothesis_id": specification["hypothesis_id"],
                    "candidate_cwe_correct": cwe_correct,
                    "has_locatable_source": any(
                        location is not None for location in source_locations
                    ),
                    "has_locatable_sink": any(location is not None for location in sink_locations),
                    "has_locatable_endpoint": any(
                        location is not None for location in [*source_locations, *sink_locations]
                    ),
                    "source_fix_scope_match": source_match,
                    "sink_fix_scope_match": sink_match,
                    "paper_proxy_match": bool(cwe_correct and (source_match or sink_match)),
                }
                all_spec_rows.append(row)
                baseline_spec_rows.append(row)
                by_project[project_id].append(row)

            project_rows: list[dict[str, Any]] = []
            for project_id in annotated_ids:
                rows = by_project.get(project_id, [])
                status = statuses[project_id]
                project_row = {
                    "schema_version": 1,
                    "baseline_id": baseline_id,
                    "project_id": project_id,
                    "status": status["status"],
                    "specifications": len(rows),
                    "paper_proxy_true_specifications": sum(
                        bool(row["paper_proxy_match"]) for row in rows
                    ),
                    "detected": any(bool(row["paper_proxy_match"]) for row in rows),
                }
                project_rows.append(project_row)
                all_project_rows.append(project_row)
            aggregates[baseline_id] = _aggregate(
                baseline_id, annotated_ids, statuses, baseline_spec_rows, project_rows
            )

        atomic_jsonl(work / "spec_metrics.jsonl", all_spec_rows)
        atomic_jsonl(work / "project_metrics.jsonl", all_project_rows)
        atomic_json(
            work / "metrics_aggregate.json",
            {
                "schema_version": 1,
                "evaluation_id": config["evaluation_id"],
                "annotated_development_projects": len(annotated_ids),
                "development_projects_without_fix_annotation": len(development_ids)
                - len(annotated_ids),
                "baselines": aggregates,
            },
        )
        atomic_json(
            work / "manifest.json",
            {
                "schema_version": 1,
                "phase": 10,
                "protocol_version": config["protocol_version"],
                "run_id": run_id,
                "evaluation_id": config["evaluation_id"],
                "created_at": utc_now(),
                "data_role": "evaluator",
                "data_access": "development labels/fix locations only; test_locked forbidden",
                "config": {
                    "path": config_path.relative_to(repo_root).as_posix(),
                    "sha256": sha256_file(config_path),
                },
                "dependencies": dependencies,
                "evaluator_inputs": {
                    "labels_sha256": sha256_file(repo_root / str(dataset["labels"])),
                    "fix_locations_sha256": sha256_file(
                        repo_root / str(dataset["fix_locations"])
                    ),
                    "development_split_sha256": sha256_file(
                        repo_root / str(dataset["development_split"])
                    ),
                },
                "git": collect_git(repo_root),
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
        "--config", type=Path, default=Path("configs/experiments/phase10_spec_evaluation.yaml")
    )
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid run ID")
    repo_root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    output_root = repo_root / "results/evaluations/phase10" / args.run_id
    evaluate(
        repo_root=repo_root,
        config_path=config_path.resolve(),
        output_root=output_root,
        run_id=args.run_id,
    )
    print(f"Phase 10 annotated specification evaluation completed: {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
