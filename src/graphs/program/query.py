"""Deterministic neighborhood and directional slice queries over a Phase 7 graph."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.graphs.program.model import EDGE_KINDS
from src.reproduction.common import atomic_json, read_jsonl


def select_seed(
    nodes: Sequence[Mapping[str, Any]],
    *,
    node_id: str | None,
    file: str | None,
    line: int | None,
) -> str:
    if node_id:
        if node_id not in {str(node["node_id"]) for node in nodes}:
            raise ValueError("seed node ID is absent from the project graph")
        return node_id
    if not file or line is None or line < 1:
        raise ValueError("provide --node-id or both --file and --line")
    normalized = file.replace("\\", "/").lstrip("./")
    matching = [node for node in nodes if node.get("location", {}).get("file") == normalized]
    if not matching:
        raise ValueError("seed file is absent from the project graph")

    def distance(node: Mapping[str, Any]) -> tuple[int, int, str]:
        location = node["location"]
        start = int(location["start_line"])
        end = int(location["end_line"])
        span_distance = 0 if start <= line <= end else min(abs(line - start), abs(line - end))
        return span_distance, end - start, str(node["node_id"])

    return str(min(matching, key=distance)["node_id"])


def query_graph(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    *,
    seed_id: str,
    hops: int,
    direction: str,
    edge_kinds: set[str] | None = None,
) -> dict[str, Any]:
    if hops < 0:
        raise ValueError("hops must be non-negative")
    if direction not in {"in", "out", "both"}:
        raise ValueError("direction must be in, out, or both")
    allowed = edge_kinds or EDGE_KINDS
    unknown = allowed - EDGE_KINDS
    if unknown:
        raise ValueError(f"unknown edge kinds: {sorted(unknown)}")
    outgoing: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    incoming: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("kind") not in allowed:
            continue
        outgoing[str(edge["source_id"])].append(edge)
        incoming[str(edge["target_id"])].append(edge)
    visited = {seed_id}
    distances = {seed_id: 0}
    queue: deque[str] = deque([seed_id])
    selected_edge_ids: set[str] = set()
    while queue:
        current = queue.popleft()
        depth = distances[current]
        if depth >= hops:
            continue
        candidates: list[Mapping[str, Any]] = []
        if direction in {"out", "both"}:
            candidates.extend(outgoing[current])
        if direction in {"in", "both"}:
            candidates.extend(incoming[current])
        for edge in sorted(candidates, key=lambda item: str(item["edge_id"])):
            selected_edge_ids.add(str(edge["edge_id"]))
            neighbor = (
                str(edge["target_id"])
                if str(edge["source_id"]) == current
                else str(edge["source_id"])
            )
            if neighbor not in visited:
                visited.add(neighbor)
                distances[neighbor] = depth + 1
                queue.append(neighbor)
    selected_nodes = sorted(
        (dict(node) for node in nodes if str(node["node_id"]) in visited),
        key=lambda item: str(item["node_id"]),
    )
    selected_edges = sorted(
        (
            dict(edge)
            for edge in edges
            if str(edge["edge_id"]) in selected_edge_ids
            and str(edge["source_id"]) in visited
            and str(edge["target_id"]) in visited
        ),
        key=lambda item: (
            str(item["kind"]),
            str(item["source_id"]),
            str(item["target_id"]),
            str(item["edge_id"]),
        ),
    )
    return {
        "schema_version": 1,
        "seed_node_id": seed_id,
        "hops": hops,
        "direction": direction,
        "edge_kinds": sorted(allowed),
        "node_count": len(selected_nodes),
        "edge_count": len(selected_edges),
        "distances": dict(sorted(distances.items())),
        "nodes": selected_nodes,
        "edges": selected_edges,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--node-id")
    parser.add_argument("--file")
    parser.add_argument("--line", type=int)
    parser.add_argument("--hops", type=int, default=2)
    parser.add_argument("--direction", choices=("in", "out", "both"), default="both")
    parser.add_argument("--edge-kind", action="append", dest="edge_kinds")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    project_root = args.run_root.resolve() / "graphs" / args.project_id
    nodes = read_jsonl(project_root / "nodes.jsonl")
    edges = read_jsonl(project_root / "edges.jsonl")
    if not nodes:
        raise SystemExit("ERROR: project graph is missing or empty")
    seed = select_seed(nodes, node_id=args.node_id, file=args.file, line=args.line)
    result = query_graph(
        nodes,
        edges,
        seed_id=seed,
        hops=args.hops,
        direction=args.direction,
        edge_kinds=set(args.edge_kinds) if args.edge_kinds else None,
    )
    if args.output:
        atomic_json(args.output.resolve(), result)
        print(f"Phase 7 graph query written to {args.output}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
