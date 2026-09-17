"""Canonical Phase 8 fact schema, identifiers, and graph digest."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

KG_SCHEMA_VERSION = 1
BUILDER_VERSION = "phase8-security-kg-v1"

NODE_KINDS = {
    "CWE",
    "OWASP_CATEGORY",
    "SOURCE",
    "SINK",
    "SANITIZER",
    "PROPAGATOR",
    "PRECONDITION",
    "MITIGATION",
}
EDGE_KINDS = {
    "RELATED_CWE",
    "MAPS_TO_OWASP",
    "HAS_SOURCE",
    "HAS_SINK",
    "HAS_SANITIZER",
    "HAS_PROPAGATOR",
    "HAS_PRECONDITION",
    "MITIGATED_BY",
}
LAYERS = {"deterministic", "llm_inferred"}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _stable_id(prefix: str, parts: Sequence[object]) -> str:
    payload = "\0".join(
        canonical_json(part) if isinstance(part, (dict, list, tuple)) else str(part)
        for part in parts
    ).encode()
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:24]}"


def node_id(kind: str, identity: str) -> str:
    if kind not in NODE_KINDS:
        raise ValueError(f"unsupported Phase 8 node kind: {kind}")
    return _stable_id("skgn", (kind, identity))


def edge_id(
    kind: str,
    source_id: str,
    target_id: str,
    properties: Mapping[str, Any] | None = None,
) -> str:
    if kind not in EDGE_KINDS:
        raise ValueError(f"unsupported Phase 8 edge kind: {kind}")
    return _stable_id("skge", (kind, source_id, target_id, dict(properties or {})))


def node_record(
    *,
    kind: str,
    identity: str,
    label: str,
    properties: Mapping[str, Any],
    confidence: float,
    provenance: Sequence[Mapping[str, Any]],
    layer: str = "deterministic",
) -> dict[str, Any]:
    identifier = node_id(kind, identity)
    return {
        "schema_version": KG_SCHEMA_VERSION,
        "fact_id": identifier,
        "node_id": identifier,
        "kind": kind,
        "identity": identity,
        "label": label,
        "properties": dict(properties),
        "layer": layer,
        "confidence": confidence,
        "provenance": [dict(item) for item in provenance],
    }


def edge_record(
    *,
    kind: str,
    source_id: str,
    target_id: str,
    properties: Mapping[str, Any],
    confidence: float,
    provenance: Sequence[Mapping[str, Any]],
    layer: str = "deterministic",
) -> dict[str, Any]:
    identifier = edge_id(kind, source_id, target_id, properties)
    return {
        "schema_version": KG_SCHEMA_VERSION,
        "fact_id": identifier,
        "edge_id": identifier,
        "kind": kind,
        "source_id": source_id,
        "target_id": target_id,
        "properties": dict(properties),
        "layer": layer,
        "confidence": confidence,
        "provenance": [dict(item) for item in provenance],
    }


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
