"""Validate Phase 7 isolation, graph integrity, source mapping, and determinism."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from src.common.provenance import sha256_file
from src.graphs.program.model import EDGE_KINDS, EXTRACTOR_VERSION, edge_id, graph_digest, node_id
from src.reproduction.common import read_csv, read_jsonl

REQUIRED_FILES = {
    "STATUS",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "environment.json",
    "graph_summary.json",
    "manifest.json",
    "project_status.jsonl",
    "resource_usage.csv",
    "status_summary.json",
    "stderr.log",
    "stdout.log",
}


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return loaded


def _verify_checksums(run_root: Path) -> None:
    indexed: set[str] = set()
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 7 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if actual != indexed:
        raise ValueError("Phase 7 checksum index coverage mismatch")


def _node_descriptor(node: Mapping[str, Any]) -> dict[str, Any]:
    location = node.get("location")
    if not isinstance(location, Mapping):
        raise ValueError("Phase 7 node location is missing")
    return {
        "kind": node.get("kind"),
        "subkind": node.get("subkind"),
        "file": location.get("file"),
        "start_line": location.get("start_line"),
        "start_column": location.get("start_column"),
        "end_line": location.get("end_line"),
        "end_column": location.get("end_column"),
        "symbol": node.get("symbol"),
        "type_name": node.get("type_name"),
    }


def _validate_location(location: Mapping[str, Any], source_root: Path) -> None:
    file = location.get("file")
    if not isinstance(file, str) or not file.endswith((".java", ".kt")):
        raise ValueError("Phase 7 node location is not a Java/Kotlin source path")
    pure = PurePosixPath(file.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError("Phase 7 node location escapes the source root")
    target = source_root / pure
    if not target.is_file():
        raise ValueError(f"Phase 7 node source file does not exist: {file}")
    start = location.get("start_line")
    end = location.get("end_line")
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 1
        or end < start
    ):
        raise ValueError("Phase 7 node line range is invalid")
    if end > len(target.read_text(encoding="utf-8", errors="replace").splitlines()):
        raise ValueError("Phase 7 node line range exceeds the source file")


def validate_project_graph(
    project_root: Path, project_id: str, source_root: Path
) -> tuple[int, int, int]:
    nodes = read_jsonl(project_root / "nodes.jsonl")
    edges = read_jsonl(project_root / "edges.jsonl")
    if not nodes:
        raise ValueError(f"Phase 7 graph has no nodes: {project_id}")
    node_ids = [str(node.get("node_id")) for node in nodes]
    if len(set(node_ids)) != len(nodes) or node_ids != sorted(node_ids):
        raise ValueError(f"Phase 7 node IDs/order are invalid: {project_id}")
    for node in nodes:
        if node.get("project_id") != project_id:
            raise ValueError("Phase 7 node project mismatch")
        item = _node_descriptor(node)
        if str(node["node_id"]) != node_id(project_id, item):
            raise ValueError("Phase 7 node ID is not reproducible")
        _validate_location(node["location"], source_root)
        provenance = node.get("provenance")
        if not isinstance(provenance, Mapping) or provenance.get("tool") != "CodeQL":
            raise ValueError("Phase 7 node CodeQL provenance is missing")
    expected_edge_order = sorted(
        edges,
        key=lambda item: (
            str(item.get("kind")),
            str(item.get("source_id")),
            str(item.get("target_id")),
            str(item.get("edge_id")),
        ),
    )
    if edges != expected_edge_order:
        raise ValueError(f"Phase 7 edge ordering is not deterministic: {project_id}")
    edge_ids: set[str] = set()
    resolved = 0
    known_nodes = set(node_ids)
    for edge in edges:
        identifier = str(edge.get("edge_id"))
        kind = str(edge.get("kind"))
        source_id = str(edge.get("source_id"))
        target_id = str(edge.get("target_id"))
        if identifier in edge_ids or identifier != edge_id(project_id, kind, source_id, target_id):
            raise ValueError("Phase 7 edge ID is duplicated or not reproducible")
        edge_ids.add(identifier)
        if kind not in EDGE_KINDS or edge.get("project_id") != project_id:
            raise ValueError("Phase 7 edge kind/project is invalid")
        if source_id in known_nodes and target_id in known_nodes:
            resolved += 1
        provenance = edge.get("provenance")
        if not isinstance(provenance, Mapping) or provenance.get("tool") != "CodeQL":
            raise ValueError("Phase 7 edge CodeQL provenance is missing")
    summary = _json(project_root / "graph_summary.json")
    if int(summary.get("nodes", -1)) != len(nodes) or int(summary.get("edges", -1)) != len(edges):
        raise ValueError("Phase 7 per-project graph summary mismatch")
    if summary.get("graph_sha256") != graph_digest(nodes, edges):
        raise ValueError("Phase 7 graph deterministic digest mismatch")
    if int(summary.get("edge_references_resolved", -1)) != resolved or float(
        summary.get("edge_reference_ratio", -1.0)
    ) != (resolved / len(edges) if edges else 1.0):
        raise ValueError("Phase 7 per-project edge reference summary mismatch")
    expected_kinds = dict(sorted(Counter(str(edge["kind"]) for edge in edges).items()))
    if summary.get("edge_kinds") != expected_kinds:
        raise ValueError("Phase 7 edge-kind summary mismatch")
    return len(nodes), len(edges), resolved


def validate(run_root: Path, *, repo_root: Path) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 7 outputs: {', '.join(missing)}")
    manifest = _json(run_root / "manifest.json")
    if manifest.get("phase") != 7 or manifest.get("dataset", {}).get("id") != "D_extended":
        raise ValueError("not a Phase 7 D_extended run")
    extractor = manifest.get("extractor")
    if not isinstance(extractor, Mapping) or extractor.get("version") != EXTRACTOR_VERSION:
        raise ValueError("Phase 7 extractor provenance mismatch")
    development = {
        row["project_id"] for row in read_csv(repo_root / "data/processed/splits/development.csv")
    }
    locked = {
        row["project_id"] for row in read_csv(repo_root / "data/processed/splits/test_locked.csv")
    }
    selected = {str(value) for value in manifest.get("selected_project_ids", [])}
    if not selected or not selected <= development or selected & locked:
        raise ValueError("Phase 7 selection is not development-only")
    if manifest.get("mode") == "full" and selected != development:
        raise ValueError("full Phase 7 run does not cover all development projects")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    status_by_id = {str(row.get("project_id")): str(row.get("status")) for row in statuses}
    if len(status_by_id) != len(statuses) or set(status_by_id) != selected:
        raise ValueError("Phase 7 project status coverage mismatch")
    if any(status not in {"SUCCESS", "ANALYSIS_FAILED"} for status in status_by_id.values()):
        raise ValueError("Phase 7 project status is not final")
    successes = {project_id for project_id, status in status_by_id.items() if status == "SUCCESS"}
    failures = selected - successes
    run_status = (run_root / "STATUS").read_text(encoding="utf-8").strip()
    if (failures and run_status != "FAILED") or (not failures and run_status != "SUCCESS"):
        raise ValueError("Phase 7 run STATUS does not match project outcomes")
    graphs_root = run_root / "graphs"
    emitted = (
        {path.name for path in graphs_root.iterdir() if path.is_dir()}
        if graphs_root.is_dir()
        else set()
    )
    if emitted != successes:
        raise ValueError("Phase 7 emitted graph coverage does not match successful projects")
    total_nodes = 0
    total_edges = 0
    total_resolved = 0
    source_base = repo_root / "data/interim/phase6_project_sources"
    for project_id in sorted(successes):
        nodes, edges, resolved = validate_project_graph(
            graphs_root / project_id, project_id, source_base / project_id
        )
        total_nodes += nodes
        total_edges += edges
        total_resolved += resolved
    reference_ratio = total_resolved / total_edges if total_edges else 1.0
    if reference_ratio < 0.99:
        raise ValueError(f"Phase 7 edge reference ratio below gate: {reference_ratio:.6f}")
    summary = _json(run_root / "graph_summary.json")
    expected = {
        "projects": len(statuses),
        "analysis_successes": len(successes),
        "analysis_failures": len(failures),
        "nodes": total_nodes,
        "edges": total_edges,
    }
    if any(int(summary.get(key, -1)) != value for key, value in expected.items()):
        raise ValueError("Phase 7 aggregate graph summary mismatch")
    if (
        int(summary.get("edge_references_resolved", -1)) != total_resolved
        or float(summary.get("edge_reference_ratio", -1.0)) != reference_ratio
    ):
        raise ValueError("Phase 7 aggregate edge reference summary mismatch")
    with (run_root / "resource_usage.csv").open(encoding="utf-8", newline="") as handle:
        resources = list(csv.DictReader(handle))
    if {row["project_id"] for row in resources} != selected:
        raise ValueError("Phase 7 resource coverage mismatch")
    _verify_checksums(run_root)
    if failures:
        return (
            "PASS_WITH_ANALYSIS_FAILURES: Phase 7 program graph "
            f"({len(successes)}/{len(selected)} successful; edge references {reference_ratio:.3%})"
        )
    return (
        f"PASS: Phase 7 program graph ({len(successes)} development projects; "
        f"edge references {reference_ratio:.3%})"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(validate(args.run_root.resolve(), repo_root=args.repo_root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
