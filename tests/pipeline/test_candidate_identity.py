"""A source expression consumed directly by a sink retains its identity flow."""

from __future__ import annotations

import pytest

from maxvera.candidates import generate
from maxvera.graph import normalize_graph


def identity_graph():
    node = {
        "key": "input",
        "file": "App.java",
        "start_line": "3",
        "start_column": "31",
        "end_line": "3",
        "end_column": "54",
        "kind": "MethodCall",
        "symbol": "App#run()",
        "expression": 'System.getenv("COMMAND")',
    }
    return normalize_graph(
        "opaque-identity",
        "snapshot",
        [{**node, "role": "source"}, {**node, "role": "sink"}],
        [],
        "query-hash",
    )


@pytest.mark.parametrize("max_hops", [0, 5])
def test_direct_source_sink_expression_is_one_complete_zero_edge_candidate(max_hops):
    graph = identity_graph()
    candidates = generate(graph, [], max_hops=max_hops)

    assert len(candidates) == 1
    candidate = candidates[0]
    endpoint = graph["nodes"][0]["node_id"]
    assert candidate["source_node_id"] == candidate["sink_node_id"] == endpoint
    assert candidate["graph_path_edge_ids"] == []
    assert candidate["graph_path_node_ids"] == [endpoint]
    assert candidate["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
    assert candidate["rank_features"]["path_complete"] is True
    assert candidate["origin_generators"] == ["sink_backward_slice", "source_forward_slice"]
    assert candidate["verification_status"] == "NOT_ATTEMPTED"
    assert candidate["decision"] == "REVIEW"


def test_identity_match_preserves_paths_to_other_endpoints():
    graph = identity_graph()
    middle = graph["nodes"][0]
    graph["nodes"] += [
        {**middle, "node_id": "upstream", "roles": ["source"], "start_line": 2, "end_line": 2},
        {**middle, "node_id": "downstream", "roles": ["sink"], "start_line": 4, "end_line": 4},
    ]
    graph["edges"] = [
        {"edge_id": "incoming", "src": "upstream", "dst": middle["node_id"], "kind": "MAY_FLOW"},
        {"edge_id": "outgoing", "src": middle["node_id"], "dst": "downstream", "kind": "MAY_FLOW"},
    ]

    candidates = generate(graph, [])
    paths = {(c["source_node_id"], c["sink_node_id"]): c for c in candidates}
    assert set(paths) == {
        ("upstream", middle["node_id"]),
        (middle["node_id"], middle["node_id"]),
        (middle["node_id"], "downstream"),
    }
    assert paths[("upstream", middle["node_id"])]["graph_path_edge_ids"] == ["incoming"]
    assert paths[(middle["node_id"], "downstream")]["graph_path_edge_ids"] == ["outgoing"]


def test_static_alert_shares_the_identity_candidate_instead_of_duplicating_it():
    graph = identity_graph()
    node = graph["nodes"][0]
    span = {key: node[key] for key in ("file", "start_line", "start_column", "end_line")}
    span["end_column_exclusive"] = node["end_column"] + 1
    specification = {
        "status": "EXACT_SPAN",
        "binding_policy": "EXPR_OR_PARAMETER_EXACT_SPAN_V1",
        "source": span,
        "sink": span,
        "sarif_sha256": "original",
    }
    candidates = generate(
        graph,
        [
            {
                "path_evidence": "CODEQL_FLOW",
                "locations": [{"file": "App.java", "start_line": 3, "end_line": 3}],
                "static_endpoint_spec": specification,
            }
        ],
    )

    assert len(candidates) == 1
    assert candidates[0]["default_alert_overlap"] is True
    assert candidates[0]["static_endpoint_spec"] == specification
    assert candidates[0]["static_endpoint_specs"] == [specification]
    assert candidates[0]["origin_generators"] == [
        "sink_backward_slice",
        "source_forward_slice",
        "static_alerts",
    ]


def test_identity_candidate_binds_both_exact_span_verifier_endpoints(tmp_path):
    from maxvera.orchestration import Context
    from maxvera.research_verification import _endpoints, render_queries
    from src.common.provenance import sha256_file

    workspace = tmp_path / "run/stages/opaque-identity/static_extract/workspace"
    workspace.mkdir(parents=True)
    source_file = workspace / "App.java"
    source_file.write_text(
        "class App {\n  void run() throws Exception {\n"
        '    Runtime.getRuntime().exec(System.getenv("COMMAND"));\n  }\n}\n'
    )
    graph = identity_graph()
    graph["nodes"][0]["content_hash"] = content_hash = sha256_file(source_file)
    candidates = generate(graph, [])
    assert len(candidates) == 1
    ctx = Context(
        tmp_path,
        tmp_path / "run",
        tmp_path / "run/stages/opaque-identity/targeted_verify",
        {"case_id": "opaque-identity"},
        {},
        {
            "static_extract": {
                "result": {
                    "analyzed_snapshot_id": "snapshot",
                    "analyzed_files": {"App.java": content_hash},
                }
            }
        },
    )

    source, sink = _endpoints(ctx, candidates[0], graph)
    assert source["node_id"] == sink["node_id"] == graph["nodes"][0]["node_id"]
    for query in render_queries(candidates[0]["candidate_id"], source, sink):
        assert query.count('getRelativePath() = "App.java"') == 2
        assert query.count("getStartLine() = 3") == 2
        assert query.count("getStartColumn() = 31") == 2
        assert query.count("getEndColumn() = 54") == 2


@pytest.mark.parametrize(
    "changed", ["source", "sink", "missing", "ambiguous", "binding", "multiline"]
)
def test_line_overlap_never_discards_a_distinct_or_unresolved_static_endpoint_pair(changed):
    graph = identity_graph()
    node = graph["nodes"][0]
    endpoint = {
        "file": node["file"],
        "start_line": node["start_line"],
        "start_column": node["start_column"],
        "end_line": node["end_line"],
        "end_column_exclusive": node["end_column"] + 1,
    }
    spec = {
        "status": "EXACT_SPAN",
        "binding_policy": "EXPR_OR_PARAMETER_EXACT_SPAN_V1",
        "source": endpoint.copy(),
        "sink": endpoint.copy(),
        "sarif_sha256": "raw",
    }
    if changed in ("source", "sink"):
        spec[changed]["start_column"] += 1
    elif changed == "ambiguous":
        spec["status"] = "AMBIGUOUS_SARIF_LINKAGE"
    elif changed == "binding":
        spec["binding_policy"] = "UNKNOWN_BINDING"
    elif changed == "multiline":
        spec["source"]["end_line"] += 1
    alert = {
        "locations": [
            {"file": node["file"], "start_line": node["start_line"], "end_line": node["end_line"]}
        ],
        "path_evidence": "CODEQL_FLOW",
    }
    if changed != "missing":
        alert["static_endpoint_spec"] = spec
    output = generate(graph, [alert])
    assert len(output) == 2
    static = [c for c in output if c["source_node_id"] is None]
    assert len(static) == 1 and static[0]["origin_generators"] == ["static_alerts"]
    graph_candidate = next(c for c in output if c["source_node_id"] is not None)
    assert "static_alerts" not in graph_candidate["origin_generators"]
    assert graph_candidate["default_alert_overlap"] is False
