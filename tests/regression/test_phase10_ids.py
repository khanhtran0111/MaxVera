from __future__ import annotations

import json

from src.retrieval.graph import retrieve_context
from src.specification.schema import parse_specification


def test_phase10_context_and_specification_ids_are_stable() -> None:
    nodes = [
        {
            "node_id": "evn_hyp",
            "layer": "evidence",
            "kind": "HYPOTHESIS",
            "project_id": "proj_fixture",
            "properties": {
                "upstream_hypothesis_id": "hyp_fixture",
                "candidate_cwe": ["CWE-79"],
            },
        },
        {
            "node_id": "evn_source",
            "layer": "evidence",
            "kind": "ASSERTION",
            "project_id": "proj_fixture",
            "properties": {
                "assertion_type": "source_location",
                "role": "source",
                "file": "src/Test.java",
                "line": 10,
            },
        },
        {
            "node_id": "evn_sink",
            "layer": "evidence",
            "kind": "ASSERTION",
            "project_id": "proj_fixture",
            "properties": {
                "assertion_type": "source_location",
                "role": "sink",
                "file": "src/Test.java",
                "line": 20,
            },
        },
    ]
    edges = [
        {
            "edge_id": "edge_source",
            "kind": "DERIVED_FROM",
            "source_id": "evn_source",
            "target_id": "evn_hyp",
            "project_id": "proj_fixture",
        },
        {
            "edge_id": "edge_sink",
            "kind": "DERIVED_FROM",
            "source_id": "evn_sink",
            "target_id": "evn_hyp",
            "project_id": "proj_fixture",
        },
    ]
    context = retrieve_context(
        nodes,
        edges,
        hypothesis_id="hyp_fixture",
        strategy="unified_graph_pruned",
        max_hops=4,
        max_nodes=80,
    )
    response = json.dumps(
        {
            "specification": {
                "hypothesis_id": "hyp_fixture",
                "candidate_cwe": "CWE-79",
                "sources": [{"node_id": "evn_source", "rationale": "source"}],
                "sinks": [{"node_id": "evn_sink", "rationale": "sink"}],
                "sanitizers": [],
                "propagators": [],
                "preconditions": [],
                "summary": "fixture",
            }
        }
    )
    by_id = {str(node["node_id"]): node for node in nodes}
    spec = parse_specification(
        response,
        project_id="proj_fixture",
        hypothesis_id="hyp_fixture",
        candidate_cwes=["CWE-79"],
        context_id=context.context_id,
        context_nodes=by_id,
        allowed_node_ids=set(by_id),
        baseline_id="B9",
        attempt=1,
        max_role_items=8,
        max_preconditions=8,
    )
    assert context.context_id == "ctx_a2537420fd2302e42048f243"
    assert spec["specification_id"] == "spec_a07cf5e438d425ec325ab44e"
