"""Validate Phase 9 isolation, lineage, acyclicity, and lossless serialization."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import sha256_file
from src.graphs.evidence.model import (
    EDGE_KINDS,
    EVIDENCE_NODE_KINDS,
    LAYERS,
    NODE_KINDS,
    USEG_SCHEMA_VERSION,
    USEG_VERSION,
    cycle_nodes,
    evidence_node_id,
    graph_digest,
    sort_edges,
    sort_nodes,
    useg_edge_id,
)
from src.graphs.useg.builder import _trace_audit, build_useg
from src.reproduction.common import read_jsonl

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PROVENANCE_FIELDS = {
    "source_phase",
    "source_run_id",
    "artifact",
    "artifact_sha256",
    "record_id",
    "producer",
}
REQUIRED_FILES = {
    "STATUS",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "dependency_status.json",
    "environment.json",
    "manifest.json",
    "project_status.jsonl",
    "project_summary.jsonl",
    "resource_usage.json",
    "stderr.log",
    "stdout.log",
    "trace_audit.json",
    "useg/edges.jsonl",
    "useg/nodes.jsonl",
    "useg_summary.json",
}


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _verify_checksums(run_root: Path) -> None:
    indexed: set[str] = set()
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 9 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if actual != indexed:
        raise ValueError("Phase 9 checksum index coverage mismatch")


def _validate_provenance(record: Mapping[str, Any]) -> None:
    provenance = record.get("provenance")
    if not isinstance(provenance, list) or not provenance:
        raise ValueError("Phase 9 node/edge lacks provenance")
    for item in provenance:
        if not isinstance(item, Mapping) or not set(item) >= PROVENANCE_FIELDS:
            raise ValueError("Phase 9 provenance is incomplete")
        if not isinstance(item["source_phase"], int) or item["source_phase"] not in {6, 7, 8, 9}:
            raise ValueError("Phase 9 provenance source phase is invalid")
        for field in PROVENANCE_FIELDS - {"source_phase"}:
            if not isinstance(item[field], str) or not item[field]:
                raise ValueError("Phase 9 provenance contains an empty/non-string field")
        if not SHA256_PATTERN.fullmatch(str(item["artifact_sha256"])):
            raise ValueError("Phase 9 provenance artifact checksum is invalid")


def _validate_confidence(node: Mapping[str, Any]) -> None:
    if "confidence" in node:
        raise ValueError("Phase 9 forbids an aggregate confidence scalar")
    components = node.get("confidence_components")
    if not isinstance(components, list):
        raise ValueError("Phase 9 confidence components are missing")
    identities: set[tuple[str, str]] = set()
    for component in components:
        if not isinstance(component, Mapping):
            raise ValueError("Phase 9 confidence component is not an object")
        name = component.get("name")
        basis = component.get("basis")
        value = component.get("value")
        if not isinstance(name, str) or not name or not isinstance(basis, str) or not basis:
            raise ValueError("Phase 9 confidence component identity is invalid")
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not 0.0 <= float(value) <= 1.0
        ):
            raise ValueError("Phase 9 confidence component is outside [0,1]")
        identity = (name, basis)
        if identity in identities:
            raise ValueError("Phase 9 confidence component is duplicated")
        identities.add(identity)


def _validate_graph(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]], *, iteration: int
) -> None:
    if list(nodes) != sort_nodes(nodes) or list(edges) != sort_edges(edges):
        raise ValueError("Phase 9 graph is not in canonical deterministic order")
    node_ids: set[str] = set()
    for node in nodes:
        if (
            node.get("schema_version") != USEG_SCHEMA_VERSION
            or node.get("useg_version") != USEG_VERSION
            or node.get("analysis_iteration") != iteration
        ):
            raise ValueError("Phase 9 node schema/version/iteration mismatch")
        identifier = str(node.get("node_id"))
        layer = str(node.get("layer"))
        kind = str(node.get("kind"))
        if identifier in node_ids or layer not in LAYERS or kind not in NODE_KINDS:
            raise ValueError("Phase 9 node ID/layer/kind is invalid or duplicated")
        node_ids.add(identifier)
        project_id = node.get("project_id")
        if layer == "evidence":
            if kind not in EVIDENCE_NODE_KINDS or not isinstance(project_id, str):
                raise ValueError("Phase 9 evidence node kind/project is invalid")
            if identifier != evidence_node_id(
                kind,
                project_id,
                str(node.get("identity")),
                analysis_iteration=iteration,
            ):
                raise ValueError("Phase 9 evidence node canonical ID mismatch")
        elif layer == "program":
            if kind != "PROGRAM_NODE" or not identifier.startswith("pgn_"):
                raise ValueError("Phase 9 program reference is invalid")
        elif kind != "SECURITY_NODE" or not identifier.startswith("skgn_"):
            raise ValueError("Phase 9 security reference is invalid")
        if not isinstance(node.get("properties"), Mapping):
            raise ValueError("Phase 9 node properties are not an object")
        _validate_confidence(node)
        _validate_provenance(node)

    edge_ids: set[str] = set()
    for edge in edges:
        if (
            edge.get("schema_version") != USEG_SCHEMA_VERSION
            or edge.get("useg_version") != USEG_VERSION
            or edge.get("analysis_iteration") != iteration
        ):
            raise ValueError("Phase 9 edge schema/version/iteration mismatch")
        identifier = str(edge.get("edge_id"))
        kind = str(edge.get("kind"))
        source_id = str(edge.get("source_id"))
        target_id = str(edge.get("target_id"))
        properties = edge.get("properties")
        if kind not in EDGE_KINDS or not isinstance(properties, Mapping):
            raise ValueError("Phase 9 edge kind/properties are invalid")
        if identifier != useg_edge_id(
            kind,
            source_id,
            target_id,
            properties,
            analysis_iteration=iteration,
        ):
            raise ValueError("Phase 9 edge canonical ID mismatch")
        if identifier in edge_ids or source_id not in node_ids or target_id not in node_ids:
            raise ValueError("Phase 9 edge ID is duplicated or references a missing node")
        edge_ids.add(identifier)
        _validate_provenance(edge)
    if cycle_nodes(nodes, edges):
        raise ValueError("Phase 9 evidence dependency graph contains a cycle")


def validate(run_root: Path, *, repo_root: Path) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 9 outputs: {', '.join(missing)}")
    manifest = _json(run_root / "manifest.json")
    if (
        manifest.get("phase") != 9
        or manifest.get("protocol_version") != "1.6.0"
        or manifest.get("useg_version") != USEG_VERSION
        or manifest.get("analysis_iteration") != 0
    ):
        raise ValueError("not a Phase 9 iteration-0 USEG run")
    if manifest.get("network_calls") != 0 or manifest.get("llm_calls") != 0:
        raise ValueError("Phase 9 iteration 0 violates zero network/LLM policy")
    config_record = cast(Mapping[str, Any], manifest["experiment_config"])
    config_path = repo_root / str(config_record["path"])
    if sha256_file(config_path) != config_record["sha256"]:
        raise ValueError("Phase 9 experiment config checksum mismatch")
    config = _mapping(config_path)

    from src.graphs.useg.runner import _validate_selected_inputs, dependency_status

    dependencies = dependency_status(repo_root, config)
    if _json(run_root / "dependency_status.json") != dependencies:
        raise ValueError("Phase 9 persisted dependency status mismatch")
    if manifest.get("development_dependencies") != dependencies:
        raise ValueError("Phase 9 manifest dependency status mismatch")
    selected = [str(value) for value in cast(Sequence[Any], manifest["selected_project_ids"])]
    if len(selected) != int(manifest["selected_project_count"]) or len(set(selected)) != len(
        selected
    ):
        raise ValueError("Phase 9 selected project manifest is invalid")
    _validate_selected_inputs(repo_root, config, selected)

    statuses = read_jsonl(run_root / "project_status.jsonl")
    summaries = read_jsonl(run_root / "project_summary.jsonl")
    if [str(row.get("project_id")) for row in statuses] != selected:
        raise ValueError("Phase 9 project status coverage/order mismatch")
    if [str(row.get("project_id")) for row in summaries] != selected:
        raise ValueError("Phase 9 project summary coverage/order mismatch")
    if any(row.get("status") not in {"SUCCESS", "ANALYSIS_FAILED"} for row in statuses):
        raise ValueError("Phase 9 project status is not final")
    successes = {str(row["project_id"]) for row in statuses if row["status"] == "SUCCESS"}
    failures = set(selected) - successes
    run_status = (run_root / "STATUS").read_text(encoding="utf-8").strip()
    if (failures and run_status != "FAILED") or (not failures and run_status != "SUCCESS"):
        raise ValueError("Phase 9 run STATUS does not match project outcomes")
    if manifest.get("mode") == "full":
        coverage = cast(Mapping[str, Any], config["coverage"])
        if (
            len(selected) != int(coverage["expected_full_projects"])
            or len(successes) != int(coverage["expected_phase7_successes"])
            or len(failures) != int(coverage["expected_phase7_failures"])
        ):
            raise ValueError("Phase 9 full-run intention-to-analyze coverage mismatch")

    nodes = read_jsonl(run_root / "useg/nodes.jsonl")
    edges = read_jsonl(run_root / "useg/edges.jsonl")
    _validate_graph(nodes, edges, iteration=0)
    emitted_projects = {
        str(node["project_id"])
        for node in nodes
        if node.get("layer") == "evidence" and isinstance(node.get("project_id"), str)
    }
    if emitted_projects != successes:
        raise ValueError("Phase 9 graph coverage does not match successful projects")

    forbidden = [
        str(value).lower()
        for value in cast(Mapping[str, Any], config["validation"])[
            "forbidden_output_substrings"
        ]
    ]
    serialized = "\n".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) for record in [*nodes, *edges]
    ).lower()
    leaked = [value for value in forbidden if value in serialized]
    if leaked:
        raise ValueError(f"Phase 9 output contains forbidden evaluator material: {leaked}")

    summary = _json(run_root / "useg_summary.json")
    expected_counts = {
        "projects": len(selected),
        "analysis_successes": len(successes),
        "analysis_failures": len(failures),
        "nodes": len(nodes),
        "edges": len(edges),
        "llm_calls": 0,
        "network_calls": 0,
    }
    if any(int(summary.get(key, -1)) != value for key, value in expected_counts.items()):
        raise ValueError("Phase 9 aggregate summary count mismatch")
    node_layers = dict(sorted(Counter(str(node["layer"]) for node in nodes).items()))
    evidence_kinds = dict(
        sorted(
            Counter(
                str(node["kind"]) for node in nodes if node.get("layer") == "evidence"
            ).items()
        )
    )
    edge_kinds = dict(sorted(Counter(str(edge["kind"]) for edge in edges).items()))
    if (
        summary.get("node_layers") != node_layers
        or summary.get("evidence_node_kinds") != evidence_kinds
        or summary.get("edge_kinds") != edge_kinds
        or summary.get("graph_sha256") != graph_digest(nodes, edges)
    ):
        raise ValueError("Phase 9 aggregate graph summary/digest mismatch")
    audit = _trace_audit(nodes, edges)
    if _json(run_root / "trace_audit.json") != audit or audit["status"] != "PASS":
        raise ValueError("Phase 9 trace/cycle/round-trip audit mismatch")

    locks = cast(Mapping[str, Any], config["development_dependencies"])
    rebuilt = build_useg(
        phase6_root=repo_root
        / str(cast(Mapping[str, Any], locks["phase6"])["run_root"]),
        phase7_root=repo_root
        / str(cast(Mapping[str, Any], locks["phase7"])["run_root"]),
        phase8_root=repo_root
        / str(cast(Mapping[str, Any], locks["phase8"])["run_root"]),
        experiment=config,
        config_sha256=str(config_record["sha256"]),
        selected_project_ids=selected,
    )
    if (
        rebuilt["nodes"] != nodes
        or rebuilt["edges"] != edges
        or rebuilt["statuses"] != statuses
        or rebuilt["project_summaries"] != summaries
        or rebuilt["summary"] != summary
        or rebuilt["trace_audit"] != audit
    ):
        raise ValueError("Phase 9 graph does not reproduce from locked dependencies")

    implementation = cast(Mapping[str, Any], manifest["implementation_sha256"])
    for relative, digest in implementation.items():
        if sha256_file(repo_root / str(relative)) != digest:
            raise ValueError(f"Phase 9 implementation checksum mismatch: {relative}")
    _verify_checksums(run_root)
    if failures:
        return (
            "PASS_WITH_ANALYSIS_FAILURES: Phase 9 USEG "
            f"({len(successes)}/{len(selected)} successful; "
            f"{len(nodes)} nodes, {len(edges)} edges; acyclic and lossless)"
        )
    return (
        f"PASS: Phase 9 USEG ({len(successes)} projects; {len(nodes)} nodes, "
        f"{len(edges)} edges; acyclic and lossless)"
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
