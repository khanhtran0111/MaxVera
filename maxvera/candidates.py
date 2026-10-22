"""Three independently attributed generators and deterministic pre-LLM ranking."""

from __future__ import annotations

from collections import defaultdict, deque

from maxvera.contracts import digest
from maxvera.graph import FLOW_KINDS


def generate(
    graph: dict, alerts: list[dict], *, max_hops: int = 5, check_budget=None
) -> list[dict]:
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    adjacency, backward = defaultdict(list), defaultdict(list)
    for e in graph["edges"]:
        if e["kind"] in FLOW_KINDS:
            adjacency[e["src"]].append((e["dst"], e["edge_id"]))
            backward[e["dst"]].append((e["src"], e["edge_id"]))
    pool = {}

    def retain(source, sink, edge_ids, generator, status, locations=None):
        ident = "cand-" + digest([graph["snapshot_id"], source, sink, edge_ids, locations])[:24]
        path_nodes = set()
        path_edges = set(edge_ids)
        for e in graph["edges"]:
            if e["edge_id"] in path_edges:
                path_nodes.update([e["src"], e["dst"]])
        path_nodes.update(x for x in (source, sink) if x)
        locs = locations or [
            {k: nodes[i][k] for k in ("file", "start_line", "end_line")} for i in sorted(path_nodes)
        ]
        item = pool.setdefault(
            ident,
            {
                "schema_version": "2.0",
                "case_id": graph["case_id"],
                "snapshot_id": graph["snapshot_id"],
                "candidate_id": ident,
                "rank_pre_llm": None,
                "rank_post_llm": None,
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
                "default_alert_overlap": generator == "static_alerts",
                "alert_overlap_policy": "source-sink-program-points-v1",
                "score_type": "UN-CALIBRATED-RANKING",
                "rank_features": {
                    "cross_file": len({location["file"] for location in locs}) > 1,
                    "path_complete": status in {"COMPLETE_CANDIDATE_PATH", "STATIC_CONFIRMED"},
                    "guard_status": "UNKNOWN",
                },
                "provenance": {
                    "candidate_generator_version": "graph-discovery-2.0",
                    "graph_hash": graph["graph_hash"],
                },
            },
        )
        item["origin_generators"] = sorted(set(item["origin_generators"] + [generator]))

    def traverse(start, reverse):
        adj = backward if reverse else adjacency
        wanted = "source" if reverse else "sink"
        queue = deque([(start, [], frozenset([start]))])
        found = False
        seen = {start}
        expansions = 0
        while queue and expansions < 4096:
            if check_budget:
                check_budget()
            current, path, visited = queue.popleft()
            expansions += 1
            if current != start and wanted in nodes[current]["roles"]:
                source, sink = (current, start) if reverse else (start, current)
                retain(
                    source,
                    sink,
                    list(reversed(path)) if reverse else path,
                    "sink_backward_slice" if reverse else "source_forward_slice",
                    "COMPLETE_CANDIDATE_PATH",
                )
                found = True
                # Do not continue beyond an already matched sensitive endpoint.
                continue
            if len(path) >= max_hops:
                continue
            for target, edge_id in sorted(adj[current]):
                if target not in seen and len(seen) < 4096:
                    seen.add(target)
                    queue.append((target, [*path, edge_id], visited | {target}))
        if not found:
            retain(
                None if reverse else start,
                start if reverse else None,
                [],
                "sink_backward_slice" if reverse else "source_forward_slice",
                "SINK_ONLY" if reverse else "SOURCE_ONLY",
            )

    for node in graph["nodes"]:
        if "sink" in node["roles"]:
            traverse(node["node_id"], True)
        if "source" in node["roles"]:
            traverse(node["node_id"], False)

    def overlaps(a, b):
        return (
            a["file"] == b["file"]
            and a["start_line"] <= b["end_line"]
            and b["start_line"] <= a["end_line"]
        )

    for alert in alerts:
        # Conservative coverage rule: the same source AND sink program points.
        # It measures default-query coverage, not equality of taint models/exploitability.
        matches = [
            c
            for c in pool.values()
            if c["source_node_id"]
            and c["sink_node_id"]
            and alert.get("path_evidence") == "CODEQL_FLOW"
            and overlaps(nodes[c["source_node_id"]], alert["locations"][0])
            and overlaps(nodes[c["sink_node_id"]], alert["locations"][-1])
        ]
        if matches:
            for c in matches:
                c["default_alert_overlap"] = True
                c["origin_generators"] = sorted(set(c["origin_generators"]) | {"static_alerts"})
            continue  # Do not spend a second Top-K position on the default-alert copy.
        retain(
            None,
            None,
            [],
            "static_alerts",
            "STATIC_CONFIRMED" if alert.get("path_evidence") == "CODEQL_FLOW" else "SINK_ONLY",
            alert["locations"],
        )
    return sorted(pool.values(), key=lambda c: c["candidate_id"])


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
    ranked.sort(key=lambda c: (-c["score"], c["candidate_id"]))
    return [{**c, "rank_pre_llm": i + 1} for i, c in enumerate(ranked[:top_k])]
