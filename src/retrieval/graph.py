"""Deterministic Phase 10 retrieval over the locked Phase 9 USEG."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

STRATEGIES = {
    "program_graph_only",
    "security_knowledge_graph_only",
    "unified_graph_unpruned",
    "unified_graph_pruned",
}


def estimate_tokens(text: str) -> int:
    """Conservatively estimate hosted-model tokens without a tokenizer dependency."""
    return max(1, math.ceil(len(text.encode("utf-8")) / 3.5))


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class GraphContext:
    context_id: str
    strategy: str
    hypothesis_node_id: str
    hypothesis_id: str
    project_id: str
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[dict[str, Any], ...]
    retrieved_node_count: int
    retrieved_edge_count: int
    structurally_pruned: bool


def _node_sort_key(node: Mapping[str, Any], root_id: str) -> tuple[int, str, str]:
    layer_order = {"evidence": 0, "program": 1, "security": 2}
    return (
        -1 if node.get("node_id") == root_id else layer_order.get(str(node.get("layer")), 9),
        str(node.get("kind")),
        str(node.get("node_id")),
    )


def _edge_sort_key(edge: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(edge.get("kind")),
        str(edge.get("source_id")),
        str(edge.get("target_id")),
        str(edge.get("edge_id")),
    )


def _allowed_layers(strategy: str) -> set[str]:
    if strategy == "program_graph_only":
        return {"evidence", "program"}
    if strategy == "security_knowledge_graph_only":
        return {"evidence", "security"}
    return {"evidence", "program", "security"}


def retrieve_context(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    *,
    hypothesis_id: str,
    strategy: str,
    max_hops: int,
    max_nodes: int,
) -> GraphContext:
    """Retrieve a project-isolated, deterministic context for one hypothesis.

    Traversal is intentionally undirected because Phase 9 dependency edges point from
    assertions/findings toward their derivation while security matches point outward.
    Project filtering prevents a shared global Security node from joining evidence from
    different repositories.
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"unsupported Phase 10 retrieval strategy: {strategy}")
    if max_hops < 1 or max_nodes < 1:
        raise ValueError("max_hops and max_nodes must be positive")
    roots = [
        dict(node)
        for node in nodes
        if node.get("kind") == "HYPOTHESIS"
        and isinstance(node.get("properties"), Mapping)
        and node["properties"].get("upstream_hypothesis_id") == hypothesis_id
    ]
    if len(roots) != 1:
        raise ValueError(f"expected one USEG hypothesis node for {hypothesis_id}, got {len(roots)}")
    root = roots[0]
    root_id = str(root["node_id"])
    project_id = str(root["project_id"])
    allowed_layers = _allowed_layers(strategy)
    by_id = {str(node["node_id"]): dict(node) for node in nodes}
    eligible_edges = [
        dict(edge)
        for edge in edges
        if edge.get("project_id") == project_id
        and str(edge.get("source_id")) in by_id
        and str(edge.get("target_id")) in by_id
        and str(by_id[str(edge["source_id"])].get("layer")) in allowed_layers
        and str(by_id[str(edge["target_id"])].get("layer")) in allowed_layers
    ]
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for edge in eligible_edges:
        source = str(edge["source_id"])
        target = str(edge["target_id"])
        adjacency[source].append((target, edge))
        adjacency[target].append((source, edge))
    for values in adjacency.values():
        values.sort(key=lambda item: (_edge_sort_key(item[1]), item[0]))

    unpruned = strategy == "unified_graph_unpruned"
    depth_limit: int | None = None if unpruned else max_hops
    node_limit: int | None = None if unpruned else max_nodes
    selected_ids = {root_id}
    queue: deque[tuple[str, int]] = deque([(root_id, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth_limit is not None and depth >= depth_limit:
            continue
        for neighbor, _edge in adjacency.get(current, []):
            if neighbor in selected_ids:
                continue
            if node_limit is not None and len(selected_ids) >= node_limit:
                break
            selected_ids.add(neighbor)
            queue.append((neighbor, depth + 1))

    selected_nodes = tuple(
        sorted(
            (by_id[node_id] for node_id in selected_ids),
            key=lambda node: _node_sort_key(node, root_id),
        )
    )
    selected_edges = tuple(
        sorted(
            (
                edge
                for edge in eligible_edges
                if str(edge["source_id"]) in selected_ids
                and str(edge["target_id"]) in selected_ids
            ),
            key=_edge_sort_key,
        )
    )
    identity = hashlib.sha256(
        _canonical(
            {
                "strategy": strategy,
                "hypothesis_id": hypothesis_id,
                "nodes": [node["node_id"] for node in selected_nodes],
                "edges": [edge["edge_id"] for edge in selected_edges],
            }
        ).encode()
    ).hexdigest()[:24]
    return GraphContext(
        context_id=f"ctx_{identity}",
        strategy=strategy,
        hypothesis_node_id=root_id,
        hypothesis_id=hypothesis_id,
        project_id=project_id,
        nodes=selected_nodes,
        edges=selected_edges,
        retrieved_node_count=len(selected_nodes),
        retrieved_edge_count=len(selected_edges),
        structurally_pruned=not unpruned,
    )


def _compact_node(node: Mapping[str, Any]) -> dict[str, Any]:
    properties = node.get("properties")
    compact: dict[str, Any] = {
        "id": node["node_id"],
        "layer": node["layer"],
        "kind": node["kind"],
    }
    if isinstance(properties, Mapping):
        allowed = {
            "assertion_type",
            "candidate_cwe",
            "external_kind",
            "file",
            "identity",
            "line",
            "location",
            "role",
            "status",
            "symbol",
            "type_name",
            "upstream_hypothesis_id",
        }
        compact["properties"] = {
            str(key): value for key, value in properties.items() if key in allowed
        }
        fact = properties.get("fact_properties")
        if isinstance(fact, Mapping):
            fact_allowed = {
                "access",
                "callable",
                "package",
                "semantic_kind",
                "signature",
                "type",
            }
            compact["properties"]["fact"] = {
                str(key): value for key, value in fact.items() if key in fact_allowed
            }
    return compact


def _compact_edge(edge: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": edge["edge_id"],
        "kind": edge["kind"],
        "source": edge["source_id"],
        "target": edge["target_id"],
    }


def serialize_context(
    context: GraphContext, *, token_budget: int
) -> tuple[str, dict[str, Any]]:
    """Serialize a compact context and deterministically truncate to the token cap."""
    if token_budget < 1:
        raise ValueError("token_budget must be positive")
    header = {
        "schema_version": 1,
        "context_id": context.context_id,
        "strategy": context.strategy,
        "project_id": context.project_id,
        "hypothesis_id": context.hypothesis_id,
        "hypothesis_node_id": context.hypothesis_node_id,
    }
    lines = [_canonical({"record": "context", **header})]
    included_ids: set[str] = set()
    for node in context.nodes:
        candidate = _canonical({"record": "node", **_compact_node(node)})
        if estimate_tokens("\n".join([*lines, candidate])) > token_budget:
            continue
        lines.append(candidate)
        included_ids.add(str(node["node_id"]))
    for edge in context.edges:
        if str(edge["source_id"]) not in included_ids or str(edge["target_id"]) not in included_ids:
            continue
        candidate = _canonical({"record": "edge", **_compact_edge(edge)})
        if estimate_tokens("\n".join([*lines, candidate])) > token_budget:
            continue
        lines.append(candidate)
    serialized = "\n".join(lines)
    metadata = {
        "schema_version": 1,
        **header,
        "retrieved_nodes": context.retrieved_node_count,
        "retrieved_edges": context.retrieved_edge_count,
        "serialized_nodes": len(included_ids),
        "serialized_edges": len(lines) - 1 - len(included_ids),
        "estimated_tokens": estimate_tokens(serialized),
        "token_budget": token_budget,
        "structurally_pruned": context.structurally_pruned,
        "serialization_truncated": len(included_ids) < context.retrieved_node_count,
        "serialized_node_ids": sorted(included_ids),
    }
    return serialized, metadata
