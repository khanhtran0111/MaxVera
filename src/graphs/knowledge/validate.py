"""Validate Phase 8 source locks, fact provenance, layers, schema, and audit coverage."""

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
from src.graphs.knowledge.builder import build_audit
from src.graphs.knowledge.model import (
    BUILDER_VERSION,
    EDGE_KINDS,
    KG_SCHEMA_VERSION,
    LAYERS,
    NODE_KINDS,
    edge_id,
    graph_digest,
    node_id,
    sort_edges,
    sort_nodes,
)
from src.graphs.knowledge.prepare import validate_source_bundle
from src.reproduction.common import read_jsonl

REQUIRED_FILES = {
    "STATUS",
    "audit_sample.json",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "dependency_status.json",
    "deterministic/edges.jsonl",
    "deterministic/nodes.jsonl",
    "environment.json",
    "kg_summary.json",
    "llm_inferred/edges.jsonl",
    "llm_inferred/nodes.jsonl",
    "manifest.json",
    "resource_usage.json",
    "source_manifest.json",
    "stderr.log",
    "stdout.log",
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PROVENANCE_FIELDS = {
    "source_id",
    "publisher",
    "url",
    "version",
    "license",
    "license_url",
    "artifact_sha256",
    "locator",
    "extraction",
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
    index = run_root / "checksums.sha256"
    indexed: set[str] = set()
    for line in index.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 8 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path != index
    }
    if actual != indexed:
        raise ValueError("Phase 8 checksum index does not cover the exact artifact")


def _validate_provenance(record: Mapping[str, Any]) -> None:
    provenance = record.get("provenance")
    if not isinstance(provenance, list) or not provenance:
        raise ValueError("Phase 8 fact lacks provenance")
    for item in provenance:
        if not isinstance(item, Mapping) or not set(item) >= PROVENANCE_FIELDS:
            raise ValueError("Phase 8 provenance is incomplete")
        if any(not isinstance(item[field], str) or not item[field] for field in PROVENANCE_FIELDS):
            raise ValueError("Phase 8 provenance contains an empty/non-string field")
        if not str(item["url"]).startswith("https://") or not str(
            item["license_url"]
        ).startswith("https://"):
            raise ValueError("Phase 8 provenance URL is not HTTPS")
        if not SHA256_PATTERN.fullmatch(str(item["artifact_sha256"])):
            raise ValueError("Phase 8 provenance artifact checksum is invalid")


def _validate_common_fact(record: Mapping[str, Any]) -> None:
    if record.get("schema_version") != KG_SCHEMA_VERSION:
        raise ValueError("Phase 8 fact schema version mismatch")
    if record.get("layer") not in LAYERS:
        raise ValueError("Phase 8 fact has an invalid layer")
    confidence = record.get("confidence")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0.0 <= float(confidence) <= 1.0
    ):
        raise ValueError("Phase 8 confidence is outside [0,1]")
    if not isinstance(record.get("properties"), Mapping):
        raise ValueError("Phase 8 fact properties are not an object")
    _validate_provenance(record)


def _validate_facts(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]
) -> None:
    node_ids: set[str] = set()
    for node in nodes:
        _validate_common_fact(node)
        kind = str(node.get("kind"))
        identity = str(node.get("identity"))
        identifier = str(node.get("node_id"))
        if kind not in NODE_KINDS or identifier != node_id(kind, identity):
            raise ValueError("Phase 8 node kind or canonical ID is invalid")
        if node.get("fact_id") != identifier or identifier in node_ids:
            raise ValueError("Phase 8 node fact ID is invalid or duplicated")
        if node.get("layer") != "deterministic":
            raise ValueError("canonical Phase 8 deterministic output contains inferred node")
        node_ids.add(identifier)
    edge_ids: set[str] = set()
    for edge in edges:
        _validate_common_fact(edge)
        kind = str(edge.get("kind"))
        source_id = str(edge.get("source_id"))
        target_id = str(edge.get("target_id"))
        properties = cast(Mapping[str, Any], edge.get("properties"))
        identifier = str(edge.get("edge_id"))
        if kind not in EDGE_KINDS or identifier != edge_id(
            kind, source_id, target_id, properties
        ):
            raise ValueError("Phase 8 edge kind or canonical ID is invalid")
        if edge.get("fact_id") != identifier or identifier in edge_ids:
            raise ValueError("Phase 8 edge fact ID is invalid or duplicated")
        if source_id not in node_ids or target_id not in node_ids:
            raise ValueError("Phase 8 edge references a missing node")
        if edge.get("layer") != "deterministic":
            raise ValueError("canonical Phase 8 deterministic output contains inferred edge")
        edge_ids.add(identifier)
    if list(nodes) != sort_nodes(nodes) or list(edges) != sort_edges(edges):
        raise ValueError("Phase 8 facts are not in canonical deterministic order")


def validate(run_root: Path, *, repo_root: Path) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 8 outputs: {', '.join(missing)}")
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != "SUCCESS":
        raise ValueError("Phase 8 run status is not SUCCESS")
    manifest = _json(run_root / "manifest.json")
    if (
        manifest.get("phase") != 8
        or manifest.get("protocol_version") != "1.5.0"
        or manifest.get("builder_version") != BUILDER_VERSION
        or manifest.get("graph_scope") != "global"
    ):
        raise ValueError("not a canonical Phase 8 global Security KG run")
    if manifest.get("network_called") is not False or manifest.get("llm_calls") != 0:
        raise ValueError("Phase 8 manifest violates offline/deterministic policy")

    config_record = cast(Mapping[str, Any], manifest["experiment_config"])
    config_path = repo_root / str(config_record["path"])
    if sha256_file(config_path) != config_record["sha256"]:
        raise ValueError("Phase 8 experiment config checksum mismatch")
    config = _mapping(config_path)
    source_record = cast(Mapping[str, Any], manifest["source_bundle"])
    source_config_path = repo_root / str(source_record["source_config"])
    if sha256_file(source_config_path) != source_record["source_config_sha256"]:
        raise ValueError("Phase 8 source config checksum mismatch")
    source_config = _mapping(source_config_path)
    source_manifest = validate_source_bundle(repo_root, source_config_path, source_config)
    raw_manifest_path = repo_root / str(source_config["raw_root"]) / "source_manifest.json"
    if sha256_file(raw_manifest_path) != source_record["source_manifest_sha256"]:
        raise ValueError("Phase 8 source manifest checksum mismatch")
    if _json(run_root / "source_manifest.json") != source_manifest:
        raise ValueError("Phase 8 persisted source manifest mismatch")

    from src.graphs.knowledge.runner import dependency_status

    dependencies = dependency_status(repo_root, config)
    if _json(run_root / "dependency_status.json") != dependencies:
        raise ValueError("Phase 8 dependency status mismatch")
    if manifest.get("development_dependencies") != dependencies:
        raise ValueError("Phase 8 manifest dependency lock mismatch")

    nodes = read_jsonl(run_root / "deterministic/nodes.jsonl")
    edges = read_jsonl(run_root / "deterministic/edges.jsonl")
    inferred_nodes = read_jsonl(run_root / "llm_inferred/nodes.jsonl")
    inferred_edges = read_jsonl(run_root / "llm_inferred/edges.jsonl")
    if inferred_nodes or inferred_edges:
        raise ValueError("Phase 8 canonical inferred layer must be empty")
    _validate_facts(nodes, edges)

    forbidden = [
        str(value).lower()
        for value in cast(Mapping[str, Any], config["validation"])[
            "forbidden_fact_substrings"
        ]
    ]
    serialized = "\n".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True) for item in [*nodes, *edges]
    ).lower()
    leaked = [value for value in forbidden if value in serialized]
    if leaked:
        raise ValueError(f"Phase 8 facts contain forbidden evaluator/project material: {leaked}")

    summary = _json(run_root / "kg_summary.json")
    expected_counts = {
        "nodes": len(nodes),
        "edges": len(edges),
        "deterministic_facts": len(nodes) + len(edges),
        "llm_inferred_facts": 0,
        "llm_calls": 0,
    }
    if any(int(summary.get(key, -1)) != value for key, value in expected_counts.items()):
        raise ValueError("Phase 8 summary count mismatch")
    node_kinds = dict(sorted(Counter(str(item["kind"]) for item in nodes).items()))
    edge_kinds = dict(sorted(Counter(str(item["kind"]) for item in edges).items()))
    if summary.get("node_kinds") != node_kinds or summary.get("edge_kinds") != edge_kinds:
        raise ValueError("Phase 8 kind summary mismatch")
    required_node_kinds = set(
        cast(Mapping[str, Any], config["validation"])["required_global_node_kinds"]
    )
    if not required_node_kinds <= set(node_kinds):
        raise ValueError("Phase 8 graph does not cover every required knowledge node kind")
    if summary.get("graph_sha256") != graph_digest(nodes, edges):
        raise ValueError("Phase 8 graph digest mismatch")

    expected_audit = build_audit(nodes, edges, config)
    if _json(run_root / "audit_sample.json") != expected_audit:
        raise ValueError("Phase 8 per-CWE audit sample mismatch")
    if expected_audit["status"] != "PASS" or summary.get("audit_status") != "PASS":
        raise ValueError("Phase 8 per-CWE audit gate did not pass")
    _verify_checksums(run_root)
    return (
        "PASS: Phase 8 global Security KG "
        f"({len(nodes)} nodes, {len(edges)} edges, provenance-complete, zero LLM facts)"
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
