"""Canonical Phase 9 Evidence Graph and USEG records."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from typing import Any

USEG_SCHEMA_VERSION = 1
USEG_VERSION = "phase9-useg-v1"

EVIDENCE_NODE_KINDS = {
    "HYPOTHESIS",
    "ASSERTION",
    "CODEQL_FINDING",
    "TAINT_PATH",
    "SANITIZER_EVIDENCE",
    "CONTRADICTION",
    "VERIFICATION_RESULT",
}
REFERENCE_NODE_KINDS = {"PROGRAM_NODE", "SECURITY_NODE"}
NODE_KINDS = EVIDENCE_NODE_KINDS | REFERENCE_NODE_KINDS
EDGE_KINDS = {"SUPPORTS", "CONTRADICTS", "VERIFIED_BY", "DERIVED_FROM", "MATCHES"}
LAYERS = {"evidence", "program", "security"}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _stable_id(prefix: str, parts: Sequence[object]) -> str:
    payload = "\0".join(
        canonical_json(part) if isinstance(part, (dict, list, tuple)) else str(part)
        for part in parts
    ).encode()
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:24]}"


def evidence_node_id(
    kind: str, project_id: str, identity: str, *, analysis_iteration: int
) -> str:
    if kind not in EVIDENCE_NODE_KINDS:
        raise ValueError(f"unsupported Phase 9 evidence node kind: {kind}")
    return _stable_id("evn", (USEG_VERSION, analysis_iteration, project_id, kind, identity))


def useg_edge_id(
    kind: str,
    source_id: str,
    target_id: str,
    properties: Mapping[str, Any],
    *,
    analysis_iteration: int,
) -> str:
    if kind not in EDGE_KINDS:
        raise ValueError(f"unsupported Phase 9 edge kind: {kind}")
    return _stable_id(
        "uve",
        (USEG_VERSION, analysis_iteration, kind, source_id, target_id, dict(properties)),
    )


def evidence_node(
    *,
    kind: str,
    project_id: str,
    identity: str,
    properties: Mapping[str, Any],
    confidence_components: Sequence[Mapping[str, Any]],
    provenance: Sequence[Mapping[str, Any]],
    analysis_iteration: int,
) -> dict[str, Any]:
    identifier = evidence_node_id(
        kind, project_id, identity, analysis_iteration=analysis_iteration
    )
    return {
        "schema_version": USEG_SCHEMA_VERSION,
        "useg_version": USEG_VERSION,
        "analysis_iteration": analysis_iteration,
        "node_id": identifier,
        "layer": "evidence",
        "kind": kind,
        "project_id": project_id,
        "identity": identity,
        "properties": dict(properties),
        "confidence_components": [dict(item) for item in confidence_components],
        "provenance": [dict(item) for item in provenance],
    }


def reference_node(
    *,
    node_id: str,
    layer: str,
    project_id: str | None,
    properties: Mapping[str, Any],
    confidence_components: Sequence[Mapping[str, Any]],
    provenance: Sequence[Mapping[str, Any]],
    analysis_iteration: int,
) -> dict[str, Any]:
    if layer not in {"program", "security"}:
        raise ValueError(f"unsupported Phase 9 reference layer: {layer}")
    return {
        "schema_version": USEG_SCHEMA_VERSION,
        "useg_version": USEG_VERSION,
        "analysis_iteration": analysis_iteration,
        "node_id": node_id,
        "layer": layer,
        "kind": "PROGRAM_NODE" if layer == "program" else "SECURITY_NODE",
        "project_id": project_id,
        "identity": node_id,
        "properties": dict(properties),
        "confidence_components": [dict(item) for item in confidence_components],
        "provenance": [dict(item) for item in provenance],
    }


def useg_edge(
    *,
    kind: str,
    source_id: str,
    target_id: str,
    project_id: str,
    properties: Mapping[str, Any],
    provenance: Sequence[Mapping[str, Any]],
    analysis_iteration: int,
) -> dict[str, Any]:
    identifier = useg_edge_id(
        kind,
        source_id,
        target_id,
        properties,
        analysis_iteration=analysis_iteration,
    )
    return {
        "schema_version": USEG_SCHEMA_VERSION,
        "useg_version": USEG_VERSION,
        "analysis_iteration": analysis_iteration,
        "edge_id": identifier,
        "kind": kind,
        "source_id": source_id,
        "target_id": target_id,
        "project_id": project_id,
        "properties": dict(properties),
        "provenance": [dict(item) for item in provenance],
    }


def sort_nodes(nodes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted((dict(node) for node in nodes), key=lambda item: str(item["node_id"]))


def sort_edges(edges: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (dict(edge) for edge in edges),
        key=lambda item: (
            str(item["kind"]),
            str(item["source_id"]),
            str(item["target_id"]),
            str(item["edge_id"]),
        ),
    )


def graph_digest(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]
) -> str:
    digest = hashlib.sha256()
    for record_type, records in (("node", nodes), ("edge", edges)):
        for record in records:
            digest.update(record_type.encode())
            digest.update(b"\0")
            digest.update(canonical_json(record).encode())
            digest.update(b"\n")
    return digest.hexdigest()


def cycle_nodes(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Return nodes left after Kahn elimination; an empty list means a DAG."""
    node_ids = {str(node["node_id"]) for node in nodes}
    outgoing: dict[str, list[str]] = defaultdict(list)
    indegree = dict.fromkeys(node_ids, 0)
    for edge in edges:
        source = str(edge["source_id"])
        target = str(edge["target_id"])
        if source not in node_ids or target not in node_ids:
            continue
        outgoing[source].append(target)
        indegree[target] += 1
    queue = deque(sorted(node_id for node_id, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        source = queue.popleft()
        visited += 1
        for target in outgoing.get(source, []):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    if visited == len(node_ids):
        return []
    return sorted(node_id for node_id, degree in indegree.items() if degree > 0)


def reachable_ids(
    start_id: str, edges: Sequence[Mapping[str, Any]], *, max_depth: int | None = None
) -> set[str]:
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        outgoing[str(edge["source_id"])].append(str(edge["target_id"]))
    seen = {start_id}
    queue: deque[tuple[str, int]] = deque([(start_id, 0)])
    while queue:
        source, depth = queue.popleft()
        if max_depth is not None and depth >= max_depth:
            continue
        for target in outgoing.get(source, []):
            if target not in seen:
                seen.add(target)
                queue.append((target, depth + 1))
    return seen
