"""Shared status, SARIF, metric, and integrity helpers for Phase 4."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlparse

from src.common.provenance import sha256_file

FINAL_STATUSES = {
    "SUCCESS",
    "BUILD_FAILED",
    "CODEQL_DB_FAILED",
    "ANALYSIS_FAILED",
    "EXCLUDED_WITH_REASON",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            loaded = json.loads(line)
            if not isinstance(loaded, dict):
                raise ValueError(f"non-object JSONL record in {path}")
            records.append(cast(dict[str, Any], loaded))
    return records


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_uri(value: str) -> str:
    parsed = urlparse(value)
    path = parsed.path if parsed.scheme == "file" else value
    decoded = unquote(path).replace("\\", "/")
    for prefix in ("file://", "/%SRCROOT%/", "%SRCROOT%/"):
        if decoded.startswith(prefix):
            decoded = decoded[len(prefix) :]
    # Remove URI/root decoration without rewriting hidden repository paths or
    # concealing traversal that source-bound research validation must reject.
    while decoded.startswith("./"):
        decoded = decoded[2:]
    return decoded.lstrip("/")


def _physical_location(location: Any) -> tuple[str, int] | None:
    if not isinstance(location, dict):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region", {})
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    uri = artifact.get("uri")
    line = region.get("startLine", 0)
    if not isinstance(uri, str) or not isinstance(line, int):
        return None
    return normalize_uri(uri), line


def sarif_paths(path: Path) -> list[list[tuple[str, int]]]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("runs"), list):
        raise ValueError(f"invalid SARIF: {path}")
    paths: list[list[tuple[str, int]]] = []
    for run in loaded["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            result_paths: list[list[tuple[str, int]]] = []
            for flow in result.get("codeFlows", []):
                if not isinstance(flow, dict):
                    continue
                for thread in flow.get("threadFlows", []):
                    if not isinstance(thread, dict):
                        continue
                    locations = [
                        item
                        for entry in thread.get("locations", [])
                        if isinstance(entry, dict)
                        and (item := _physical_location(entry.get("location"))) is not None
                    ]
                    if locations:
                        result_paths.append(locations)
            if not result_paths:
                locations = [
                    item
                    for entry in result.get("locations", [])
                    if isinstance(entry, dict) and (item := _physical_location(entry)) is not None
                ]
                if locations:
                    result_paths.append(locations)
            paths.extend(result_paths)
    return paths


def _result_path_groups(path: Path) -> list[list[list[tuple[str, int]]]]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    groups: list[list[list[tuple[str, int]]]] = []
    if not isinstance(loaded, dict):
        return groups
    runs = loaded.get("runs", [])
    if not isinstance(runs, list):
        return groups
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            one_result: list[list[tuple[str, int]]] = []
            flows = result.get("codeFlows", [])
            if isinstance(flows, list):
                for flow in flows:
                    if not isinstance(flow, dict):
                        continue
                    threads = flow.get("threadFlows", [])
                    if not isinstance(threads, list):
                        continue
                    for thread in threads:
                        if not isinstance(thread, dict):
                            continue
                        thread_locations = thread.get("locations", [])
                        if not isinstance(thread_locations, list):
                            continue
                        path_locations = [
                            item
                            for entry in thread_locations
                            if isinstance(entry, dict)
                            and (item := _physical_location(entry.get("location"))) is not None
                        ]
                        if path_locations:
                            one_result.append(path_locations)
            if not one_result:
                result_locations = result.get("locations", [])
                if isinstance(result_locations, list):
                    path_locations = [
                        item
                        for entry in result_locations
                        if isinstance(entry, dict)
                        and (item := _physical_location(entry)) is not None
                    ]
                    if path_locations:
                        one_result.append(path_locations)
            groups.append(one_result)
    return groups


def _positive_line(value: Any) -> int | None:
    """Parse a source line without treating an upstream blank as line zero."""
    try:
        line = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _ground_truth_locations(
    ground_truth: Sequence[Mapping[str, Any]],
) -> tuple[list[tuple[str, int | None, int | None]], dict[str, int]]:
    """Resolve upstream fix locations from method to class to file granularity."""
    locations: list[tuple[str, int | None, int | None]] = []
    scopes = {"method": 0, "class": 0, "file": 0}
    for item in ground_truth:
        truth_file = normalize_uri(str(item.get("file", "")))
        method_start = _positive_line(item.get("method_start"))
        method_end = _positive_line(item.get("method_end"))
        class_start = _positive_line(item.get("class_start"))
        class_end = _positive_line(item.get("class_end"))
        if method_start is not None and method_end is not None and method_start <= method_end:
            locations.append((truth_file, method_start, method_end))
            scopes["method"] += 1
        elif class_start is not None and class_end is not None and class_start <= class_end:
            locations.append((truth_file, class_start, class_end))
            scopes["class"] += 1
        else:
            # Some upstream fix rows identify only the changed file. Preserve those
            # rows explicitly instead of crashing or silently inventing line zero.
            locations.append((truth_file, None, None))
            scopes["file"] += 1
    return locations, scopes


def evaluate_sarif(
    project_id: str,
    status: str,
    sarif: Path | None,
    ground_truth: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "project_id": project_id,
        "status": status,
        "detected": False,
        "alerts": 0,
        "paths": 0,
        "tp_alerts": 0,
        "tp_paths": 0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "fdr": 0.0,
    }
    truth_ranges, truth_scopes = _ground_truth_locations(ground_truth)
    base["ground_truth_scopes"] = truth_scopes
    if status != "SUCCESS" or sarif is None or not sarif.is_file():
        return base

    def intersects(path_locations: Sequence[tuple[str, int]]) -> bool:
        return any(
            candidate_file == truth_file
            and (truth_start is None or truth_end is None or truth_start <= line <= truth_end)
            for candidate_file, line in path_locations
            for truth_file, truth_start, truth_end in truth_ranges
        )

    groups = _result_path_groups(sarif)
    unique_paths: set[tuple[tuple[str, int], ...]] = set()
    tp_paths: set[tuple[tuple[str, int], ...]] = set()
    tp_alerts = 0
    for group in groups:
        alert_tp = False
        for path_locations in group:
            normalized = tuple(path_locations)
            unique_paths.add(normalized)
            if intersects(path_locations):
                tp_paths.add(normalized)
                alert_tp = True
        if alert_tp:
            tp_alerts += 1
    alerts = len(groups)
    precision = tp_alerts / alerts if alerts else 0.0
    recall = 1.0 if tp_paths else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        **base,
        "detected": bool(tp_paths),
        "alerts": alerts,
        "paths": len(unique_paths),
        "tp_alerts": tp_alerts,
        "tp_paths": len(tp_paths),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fdr": 1.0 - precision if alerts else 0.0,
    }


def aggregate_metrics(projects: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(projects)
    successful = [item for item in projects if item.get("status") == "SUCCESS"]
    detected = sum(bool(item.get("detected")) for item in projects)

    def average(field: str, rows: Sequence[Mapping[str, Any]]) -> float:
        return sum(float(item.get(field, 0.0)) for item in rows) / len(rows) if rows else 0.0

    ground_truth_scopes = {
        scope: sum(
            int(scopes.get(scope, 0))
            for item in projects
            if isinstance((scopes := item.get("ground_truth_scopes")), Mapping)
        )
        for scope in ("method", "class", "file")
    }

    return {
        "schema_version": 1,
        "projects": total,
        "analysis_successes": len(successful),
        "detected_projects": detected,
        "recall_intention_to_analyze": detected / total if total else 0.0,
        "recall_build_success_only": detected / len(successful) if successful else 0.0,
        "macro_precision_successes": average("precision", successful),
        "macro_f1_successes": average("f1", successful),
        "macro_fdr_successes": average("fdr", successful),
        "total_alerts": sum(int(item.get("alerts", 0)) for item in projects),
        "total_paths": sum(int(item.get("paths", 0)) for item in projects),
        "total_tp_alerts": sum(int(item.get("tp_alerts", 0)) for item in projects),
        "total_tp_paths": sum(int(item.get("tp_paths", 0)) for item in projects),
        "ground_truth_scopes": ground_truth_scopes,
    }


def write_checksums(root: Path) -> Path:
    index = root / "checksums.sha256"
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path != index:
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    index.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index
