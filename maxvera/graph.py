"""Typed, source-backed graph normalization and extraction-quality accounting."""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath

from maxvera.contracts import ORACLE_PATTERN, digest, safe_id

FLOW_KINDS = {"MAY_FLOW", "ARG_TO_PARAM", "RET_TO_CALL", "DEF_USE"}
EDGE_KINDS = FLOW_KINDS | {"CALLS", "CONTROL_DEP", "GUARDS", "AST_PARENT"}


def relative_file(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValueError("graph location must have safe relative path")
    if ORACLE_PATTERN.search(value):
        raise ValueError("oracle identifier in analyzer path")
    return path.as_posix()


def normalize_graph(
    case_id: str, snapshot_id: str, node_rows: list[dict], edge_rows: list[dict], query_hash: str
) -> dict:
    safe_id(case_id)
    nodes, mapping = {}, {}
    for row in node_rows:
        location = {
            "file": relative_file(row["file"]),
            **{
                key: int(row[key])
                for key in ("start_line", "start_column", "end_line", "end_column")
            },
        }
        if min(location[k] for k in ("start_line", "start_column", "end_line", "end_column")) < 1:
            raise ValueError("graph location must be positive")
        if (location["end_line"], location["end_column"]) < (
            location["start_line"],
            location["start_column"],
        ):
            raise ValueError("reversed graph span")
        identifier = "n-" + digest([snapshot_id, location, row["kind"], row["symbol"]])[:24]
        if row["key"] in mapping and mapping[row["key"]] != identifier:
            raise ValueError("ambiguous graph node key")
        mapping[row["key"]] = identifier
        node = nodes.setdefault(
            identifier,
            {
                "node_id": identifier,
                "repo_snapshot_id": snapshot_id,
                "kind": row["kind"],
                "symbol": row["symbol"],
                **location,
                "language": "java",
                "expression": row.get("expression", ""),
                "roles": [],
                "extractor": "codeql-program-v2",
                "provenance_ref": "query:sha256:" + query_hash,
            },
        )
        if row.get("role"):
            if row["role"] not in {"source", "sink", "guard"}:
                raise ValueError("unknown generic node role")
            node["roles"] = sorted(set(node["roles"] + [row["role"]]))
    edges = {}
    for row in edge_rows:
        if row["source"] not in mapping or row["target"] not in mapping:
            raise ValueError("dangling edge: missing graph endpoint")
        kind = row["kind"]
        if kind not in EDGE_KINDS:
            raise ValueError("unsupported graph edge kind")
        src, dst = mapping[row["source"]], mapping[row["target"]]
        identifier = "e-" + digest([snapshot_id, src, dst, kind])[:24]
        edges[identifier] = {
            "edge_id": identifier,
            "src": src,
            "dst": dst,
            "kind": kind,
            "evidence_class": "EXTRACTED_FACT",
            "confidence": None,
            "source_location": f"{nodes[src]['file']}:{nodes[src]['start_line']}",
            "provenance_ref": "query:sha256:" + query_hash,
        }
    n = sorted(nodes.values(), key=lambda x: x["node_id"])
    e = sorted(edges.values(), key=lambda x: x["edge_id"])
    connected = {x[k] for x in e for k in ("src", "dst")}
    quality = {
        "nodes_by_kind": dict(Counter(x["kind"] for x in n)),
        "edges_by_kind": dict(Counter(x["kind"] for x in e)),
        "orphan_nodes": sum(x["node_id"] not in connected for x in n),
        "cross_file_edges": sum(nodes[x["src"]]["file"] != nodes[x["dst"]]["file"] for x in e),
        "unresolved_calls": "UNKNOWN_NOT_EXTRACTED",
        "partial_build_rate": None,
        "provenance_coverage": 1.0 if n else 0.0,
        "limitations": [
            "Static call targets may miss dynamic dispatch and external summaries",
            "Extracted local taint steps are candidate evidence, not verified exploit paths",
            "Exception flow and implicit library effects may be missing",
        ],
    }
    return {
        "schema_version": "2.0",
        "case_id": case_id,
        "snapshot_id": snapshot_id,
        "nodes": n,
        "edges": e,
        "graph_hash": digest([n, e]),
        "quality": quality,
    }
