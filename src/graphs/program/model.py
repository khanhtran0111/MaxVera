"""Canonical Phase 7 program-graph schema and deterministic normalization."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

GRAPH_SCHEMA_VERSION = 1
EXTRACTOR_VERSION = "phase7-java-program-graph-v1"
EDGE_KINDS = {
    "AST_PARENT",
    "CALL",
    "CONTROL_DEP",
    "DATA_FLOW",
    "DEF_USE",
    "TAINT_CANDIDATE",
    "TYPE",
}


def _stable_id(prefix: str, parts: Sequence[object]) -> str:
    payload = "\0".join(str(part) for part in parts).encode()
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:24]}"


def descriptor(row: Mapping[str, str], prefix: str = "") -> dict[str, Any]:
    """Read one node descriptor from a decoded CodeQL CSV row."""

    def field(name: str) -> str:
        key = f"{prefix}{name}"
        if key not in row or row[key] is None:
            raise ValueError(f"decoded CodeQL row is missing {key}")
        return str(row[key])

    return {
        "kind": field("kind"),
        "subkind": field("subkind"),
        "file": field("file").replace("\\", "/").lstrip("./"),
        "start_line": int(field("start_line")),
        "start_column": int(field("start_column")),
        "end_line": int(field("end_line")),
        "end_column": int(field("end_column")),
        "symbol": field("symbol"),
        "type_name": field("type_name"),
    }


def node_id(project_id: str, item: Mapping[str, Any]) -> str:
    return _stable_id(
        "pgn",
        (
            project_id,
            item["kind"],
            item["subkind"],
            item["file"],
            item["start_line"],
            item["start_column"],
            item["end_line"],
            item["end_column"],
            item["symbol"],
            item["type_name"],
        ),
    )


def edge_id(project_id: str, kind: str, source_id: str, target_id: str) -> str:
    return _stable_id("pge", (project_id, kind, source_id, target_id))


def node_record(
    project_id: str, item: Mapping[str, Any], provenance: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "project_id": project_id,
        "node_id": node_id(project_id, item),
        "kind": item["kind"],
        "subkind": item["subkind"],
        "symbol": item["symbol"],
        "type_name": item["type_name"],
        "location": {
            "file": item["file"],
            "start_line": item["start_line"],
            "start_column": item["start_column"],
            "end_line": item["end_line"],
            "end_column": item["end_column"],
        },
        "provenance": dict(provenance),
    }


def normalize_graph(
    project_id: str,
    node_rows: Sequence[Mapping[str, str]],
    edge_rows: Sequence[Mapping[str, str]],
    *,
    node_provenance: Mapping[str, Any],
    edge_provenance: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize CodeQL table rows and close the graph over every edge endpoint."""
    nodes: dict[str, dict[str, Any]] = {}

    def retain(item: Mapping[str, Any], provenance: Mapping[str, Any]) -> str:
        record = node_record(project_id, item, provenance)
        identifier = str(record["node_id"])
        nodes.setdefault(identifier, record)
        return identifier

    for row in node_rows:
        retain(descriptor(row, "node_"), node_provenance)
    edges: dict[str, dict[str, Any]] = {}
    for row in edge_rows:
        kind = str(row["edge_kind"])
        if kind not in EDGE_KINDS:
            raise ValueError(f"unsupported Phase 7 edge kind: {kind}")
        source_id = retain(descriptor(row, "source_"), edge_provenance)
        target_id = retain(descriptor(row, "target_"), edge_provenance)
        identifier = edge_id(project_id, kind, source_id, target_id)
        edges.setdefault(
            identifier,
            {
                "schema_version": GRAPH_SCHEMA_VERSION,
                "project_id": project_id,
                "edge_id": identifier,
                "kind": kind,
                "source_id": source_id,
                "target_id": target_id,
                "provenance": dict(edge_provenance),
            },
        )
    return (
        sorted(nodes.values(), key=lambda item: str(item["node_id"])),
        sorted(
            edges.values(),
            key=lambda item: (
                str(item["kind"]),
                str(item["source_id"]),
                str(item["target_id"]),
                str(item["edge_id"]),
            ),
        ),
    )


def graph_digest(nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for kind, records in (("node", nodes), ("edge", edges)):
        for record in records:
            digest.update(kind.encode())
            digest.update(b"\0")
            digest.update(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
            digest.update(b"\n")
    return digest.hexdigest()
