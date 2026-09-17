"""Trace a Phase 9 USEG node to its downstream program/security provenance."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.reproduction.common import read_jsonl


def trace_subgraph(run_root: Path, node_id: str, *, max_depth: int = 6) -> dict[str, Any]:
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")
    nodes = read_jsonl(run_root / "useg/nodes.jsonl")
    edges = read_jsonl(run_root / "useg/edges.jsonl")
    by_id = {str(node["node_id"]): node for node in nodes}
    if node_id not in by_id:
        raise ValueError(f"unknown Phase 9 node ID: {node_id}")
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        outgoing[str(edge["source_id"])].append(edge)
    seen = {node_id}
    selected_edges: dict[str, dict[str, Any]] = {}
    queue: deque[tuple[str, int]] = deque([(node_id, 0)])
    while queue:
        source, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for edge in outgoing.get(source, []):
            selected_edges[str(edge["edge_id"])] = edge
            target = str(edge["target_id"])
            if target not in seen:
                seen.add(target)
                queue.append((target, depth + 1))
    selected_nodes = sorted(
        (by_id[identifier] for identifier in seen),
        key=lambda item: str(item["node_id"]),
    )
    ordered_edges = sorted(
        selected_edges.values(),
        key=lambda item: (
            str(item["kind"]),
            str(item["source_id"]),
            str(item["target_id"]),
            str(item["edge_id"]),
        ),
    )
    return {
        "schema_version": 1,
        "root_node_id": node_id,
        "max_depth": max_depth,
        "nodes": selected_nodes,
        "edges": ordered_edges,
        "layers_reached": sorted({str(node["layer"]) for node in selected_nodes}),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--max-depth", type=int, default=6)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            trace_subgraph(args.run_root.resolve(), args.node_id, max_depth=args.max_depth),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
