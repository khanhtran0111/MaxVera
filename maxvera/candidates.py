"""Three independently attributed generators and deterministic pre-LLM ranking."""

from __future__ import annotations

import json
from collections import defaultdict, deque

from maxvera.contracts import digest
from maxvera.graph import FLOW_KINDS
from maxvera.sarif_endpoints import BINDING_POLICY


def generate(
    graph: dict,
    alerts: list[dict],
    *,
    max_hops: int = 5,
    max_traversal_nodes: int = 4096,
    diagnostics: dict | None = None,
    check_budget=None,
) -> list[dict]:
    if (
        isinstance(max_traversal_nodes, bool)
        or not isinstance(max_traversal_nodes, int)
        or max_traversal_nodes < 1
    ):
        raise ValueError("max_traversal_nodes must be a positive integer")
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    adjacency, backward, edges = defaultdict(list), defaultdict(list), {}
    for e in graph["edges"]:
        edges[e["edge_id"]] = e
        if e["kind"] in FLOW_KINDS:
            adjacency[e["src"]].append((e["dst"], e["edge_id"]))
            backward[e["dst"]].append((e["src"], e["edge_id"]))
    for adj in (adjacency, backward):
        for neighbors in adj.values():
            neighbors.sort(key=lambda item: (_node_key(nodes[item[0]]), edges[item[1]]["kind"]))
    pool = {}
    report = {
        "schema_version": "1.0",
        "max_traversal_nodes": max_traversal_nodes,
        "max_hops": max_hops,
        "traversals": 0,
        "truncated_traversals": 0,
        "cap_reached": False,
        "truncated_slices": [],
    }

    def retain(
        source, sink, edge_ids, generator, status, locations=None, scope=None, endpoint_spec=None
    ):
        # Full SARIF hashes and result ordering are provenance, not program semantics.
        endpoint_identity = (
            [endpoint_spec.get(key) for key in ("source", "sink", "binding_policy")]
            if endpoint_spec and endpoint_spec.get("status") == "EXACT_SPAN"
            else None
        )
        identity = [graph["snapshot_id"], source, sink, edge_ids, locations]
        if endpoint_identity:
            identity.append(endpoint_identity)
        ident = "cand-" + digest(identity)[:24]
        path_nodes = set()
        for edge_id in edge_ids:
            e = edges[edge_id]
            path_nodes.update([e["src"], e["dst"]])
        path_nodes.update(x for x in (source, sink) if x)
        locs = locations or [
            {k: nodes[i][k] for k in ("file", "start_line", "end_line")}
            for i in sorted(path_nodes, key=lambda i: _node_key(nodes[i]))
        ]
        semantic_key = json.dumps(
            [
                _node_key(nodes[source]) if source else None,
                _node_key(nodes[sink]) if sink else None,
                [
                    [
                        _node_key(nodes[edges[e]["src"]]),
                        _node_key(nodes[edges[e]["dst"]]),
                        edges[e]["kind"],
                    ]
                    for e in edge_ids
                ],
                locs,
                endpoint_identity,
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        item = pool.setdefault(
            ident,
            {
                "schema_version": "2.0",
                "case_id": graph["case_id"],
                "snapshot_id": graph["snapshot_id"],
                "candidate_id": ident,
                "rank_pre_llm": None,
                "rank_post_llm": None,
                "semantic_rank_key": semantic_key,
                "origin_generators": [],
                "hypothesized_cwes": [],
                "locations": locs,
                "source_node_id": source,
                "sink_node_id": sink,
                "graph_path_edge_ids": edge_ids,
                "graph_path_node_ids": sorted(path_nodes),
                "evidence_bundle_id": None,
                "discovery_status": status,
                "verification_status": "NOT_ATTEMPTED",
                "decision": "REVIEW",
                "scope": "repository",
                "coverage": "EXTRACTOR_MODEL_ONLY",
                "discovery_truncated": False,
                "default_alert_overlap": generator == "static_alerts",
                "alert_overlap_policy": "exact-source-sink-full-spans-v2",
                "score_type": "UN-CALIBRATED-RANKING",
                "rank_features": {
                    "cross_file": len({location["file"] for location in locs}) > 1,
                    "path_complete": status in {"COMPLETE_CANDIDATE_PATH", "STATIC_CONFIRMED"},
                    "guard_status": "UNKNOWN",
                },
                "provenance": {
                    "candidate_generator_version": "graph-discovery-2.1",
                    "graph_hash": graph["graph_hash"],
                    "analyzed_snapshot_id": graph.get("analyzed_snapshot_id", graph["snapshot_id"]),
                },
            },
        )
        item["origin_generators"] = sorted(set(item["origin_generators"] + [generator]))
        if scope:
            item["static_signal_scope"] = scope
        if endpoint_spec:
            item["static_endpoint_spec"] = endpoint_spec
        return ident

    def traverse(start, reverse):
        adj = backward if reverse else adjacency
        wanted = "source" if reverse else "sink"
        queue = deque([(start, [])])
        found = False
        seen = {start}
        expansions = 0
        truncated = False
        retained = set()
        report["traversals"] += 1
        while queue:
            if check_budget:
                check_budget()
            current, path = queue.popleft()
            expansions += 1
            if wanted in nodes[current]["roles"]:
                source, sink = (current, start) if reverse else (start, current)
                retained.add(
                    retain(
                        source,
                        sink,
                        list(reversed(path)) if reverse else path,
                        "sink_backward_slice" if reverse else "source_forward_slice",
                        "COMPLETE_CANDIDATE_PATH",
                    )
                )
                found = True
                # A directly consumed source is also a sink: retain its zero-edge
                # identity flow, then keep searching for other reachable endpoints.
                if current != start:
                    continue
            if len(path) >= max_hops:
                continue
            for target, edge_id in adj[current]:
                if target in seen:
                    continue
                if len(seen) >= max_traversal_nodes:
                    truncated = True
                    continue
                seen.add(target)
                queue.append((target, [*path, edge_id]))
        if not found:
            retained.add(
                retain(
                    None if reverse else start,
                    start if reverse else None,
                    [],
                    "sink_backward_slice" if reverse else "source_forward_slice",
                    "SINK_ONLY" if reverse else "SOURCE_ONLY",
                )
            )
        if truncated:
            report["truncated_traversals"] += 1
            report["cap_reached"] = True
            report["truncated_slices"].append(
                {
                    "start_node_id": start,
                    "direction": "backward" if reverse else "forward",
                    "visited_nodes": len(seen),
                    "expanded_nodes": expansions,
                    "reason": "MAX_TRAVERSAL_NODES",
                }
            )
            for identifier in retained:
                pool[identifier]["discovery_truncated"] = True
                pool[identifier]["coverage"] = "TRAVERSAL_LIMITED"

    for node in graph["nodes"]:
        if "sink" in node["roles"]:
            traverse(node["node_id"], True)
        if "source" in node["roles"]:
            traverse(node["node_id"], False)

    def exact_endpoint(node, endpoint):
        if not isinstance(endpoint, dict):
            return False
        coordinates = [
            endpoint.get(key)
            for key in ("start_line", "start_column", "end_line", "end_column_exclusive")
        ]
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in coordinates
        ):
            return False
        start_line, start_column, end_line, exclusive = coordinates
        # A column-one exclusive end requires source text to recover the previous
        # line width. Discovery has no source bytes, so keep a separate candidate.
        if exclusive <= 1 or (end_line, exclusive) <= (start_line, start_column):
            return False
        span = {
            "file": endpoint.get("file"),
            "start_line": start_line,
            "start_column": start_column,
            "end_line": end_line,
            "end_column": exclusive - 1,
        }
        return all(node.get(key) == value for key, value in span.items())

    for alert in alerts:
        # Conservative coverage rule: the same source AND sink program points.
        # It measures default-query coverage, not equality of taint models/exploitability.
        spec = alert.get("static_endpoint_spec", {})
        exact_spec = (
            spec.get("status") == "EXACT_SPAN"
            and spec.get("binding_policy") == BINDING_POLICY
            and alert.get("scope_status", "REPOSITORY_ENDPOINTS") == "REPOSITORY_ENDPOINTS"
            and alert.get("excluded_location_count", 0) == 0
        )
        matches = [
            c
            for c in pool.values()
            if c["source_node_id"]
            and c["sink_node_id"]
            and alert.get("path_evidence") == "CODEQL_FLOW"
            and exact_spec
            and exact_endpoint(nodes[c["source_node_id"]], spec.get("source"))
            and exact_endpoint(nodes[c["sink_node_id"]], spec.get("sink"))
        ]
        if matches:
            for c in matches:
                c["default_alert_overlap"] = True
                c["origin_generators"] = sorted(set(c["origin_generators"]) | {"static_alerts"})
                c.setdefault("static_endpoint_spec", spec)
                provenance = c.setdefault("static_endpoint_specs", [])
                if spec not in provenance:
                    provenance.append(spec)
                if alert.get("scope_status"):
                    c["static_signal_scope"] = {
                        "status": alert["scope_status"],
                        "excluded_location_count": alert.get("excluded_location_count", 0),
                        "policy": alert.get("scope_policy"),
                    }
            continue  # Do not spend a second Top-K position on the default-alert copy.
        retain(
            None,
            None,
            [],
            "static_alerts",
            "STATIC_CONFIRMED" if alert.get("path_evidence") == "CODEQL_FLOW" else "SINK_ONLY",
            alert["locations"],
            {
                "status": alert["scope_status"],
                "excluded_location_count": alert.get("excluded_location_count", 0),
                "policy": alert.get("scope_policy"),
            }
            if alert.get("scope_status")
            else None,
            alert.get("static_endpoint_spec"),
        )
    if diagnostics is not None:
        diagnostics.update(report)
    return sorted(pool.values(), key=lambda c: c["candidate_id"])


def _node_key(node: dict) -> tuple:
    """Canonical program point order, independent of snapshot and analyzer row IDs."""
    return tuple(
        node.get(k, "")
        for k in ("file", "start_line", "start_column", "end_line", "end_column", "kind", "symbol")
    )


def rank(candidates: list[dict], *, top_k: int = 20) -> list[dict]:
    if top_k < 1:
        raise ValueError("top_k must be positive")
    ranked = []
    for c in candidates:
        features = c["rank_features"]
        score = (
            4 * features["path_complete"]
            + 2 * features["cross_file"]
            + len(c["origin_generators"])
            - 0.1 * len(c["graph_path_edge_ids"])
        )
        ranked.append({**c, "score": round(score, 6)})
    ranked.sort(
        key=lambda c: (
            -c["score"],
            c.get("semantic_rank_key", json.dumps(c.get("locations", []), sort_keys=True)),
            c["candidate_id"],
        )
    )
    return [{**c, "rank_pre_llm": i + 1} for i, c in enumerate(ranked[:top_k])]
