from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.retrieval.graph import retrieve_context, serialize_context
from src.specification.compiler import render_query
from src.specification.runner import _endpoint_ids_by_role, _estimated_request_tokens
from src.specification.schema import parse_specification, specification_json_schema

REPO_ROOT = Path(__file__).resolve().parents[2]


def _fixture_graph() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    nodes: list[dict[str, object]] = [
        {
            "node_id": "evn_hyp",
            "layer": "evidence",
            "kind": "HYPOTHESIS",
            "project_id": "proj_fixture",
            "properties": {
                "upstream_hypothesis_id": "hyp_fixture",
                "candidate_cwe": ["CWE-79"],
                "rank": 1,
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
                "symbol": "input",
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
                "symbol": "println",
            },
        },
        {
            "node_id": "pgn_call",
            "layer": "program",
            "kind": "PROGRAM_NODE",
            "project_id": "proj_fixture",
            "properties": {
                "external_kind": "EXPR",
                "symbol": "println",
                "type_name": "void",
                "location": {
                    "file": "src/Test.java",
                    "start_line": 20,
                    "end_line": 20,
                },
            },
        },
        {
            "node_id": "skgn_cwe",
            "layer": "security",
            "kind": "SECURITY_NODE",
            "project_id": None,
            "properties": {"external_kind": "CWE", "identity": "CWE-79"},
        },
        {
            "node_id": "skgn_source",
            "layer": "security",
            "kind": "SECURITY_NODE",
            "project_id": None,
            "properties": {
                "external_kind": "SOURCE",
                "fact_properties": {"callable": "getParameter", "type": "Request"},
            },
        },
    ]
    edges: list[dict[str, object]] = [
        {
            "edge_id": "e1",
            "kind": "DERIVED_FROM",
            "source_id": "evn_source",
            "target_id": "evn_hyp",
            "project_id": "proj_fixture",
        },
        {
            "edge_id": "e2",
            "kind": "DERIVED_FROM",
            "source_id": "evn_sink",
            "target_id": "evn_hyp",
            "project_id": "proj_fixture",
        },
        {
            "edge_id": "e3",
            "kind": "MATCHES",
            "source_id": "evn_sink",
            "target_id": "pgn_call",
            "project_id": "proj_fixture",
        },
        {
            "edge_id": "e4",
            "kind": "MATCHES",
            "source_id": "evn_hyp",
            "target_id": "skgn_cwe",
            "project_id": "proj_fixture",
        },
        {
            "edge_id": "e5",
            "kind": "MATCHES",
            "source_id": "evn_source",
            "target_id": "skgn_source",
            "project_id": "proj_fixture",
        },
    ]
    return nodes, edges


def test_phase10_config_pins_clean_phase9_and_protocol_budget() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase10_retrieval_specification.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert config["protocol_version"] == "1.7.0"
    assert config["development_dependency"]["phase9"]["run_id"] == (
        "p9_useg_dev_full_003"
    )
    assert config["development_dependency"]["phase9"]["manifest_sha256"] == (
        "83dce921c979db710762bd205588c667033bc10fb6c64c4581fce9a8c84810c7"
    )
    assert config["budget"]["budget_matched"] == {
        "max_context_tokens_per_call": 8192,
        "max_output_tokens_per_call": 2048,
        "max_calls_per_project": 30,
        "max_total_input_tokens_per_project": 160000,
    }
    assert config["retrieval"]["prompt_reserve_tokens"] == 3072


@pytest.mark.parametrize(
    ("strategy", "present", "absent"),
    [
        ("program_graph_only", "pgn_call", "skgn_cwe"),
        ("security_knowledge_graph_only", "skgn_cwe", "pgn_call"),
        ("unified_graph_unpruned", "pgn_call", "missing"),
        ("unified_graph_pruned", "skgn_source", "missing"),
    ],
)
def test_phase10_retrieval_is_layer_isolated_and_deterministic(
    strategy: str, present: str, absent: str
) -> None:
    nodes, edges = _fixture_graph()
    first = retrieve_context(
        nodes,
        edges,
        hypothesis_id="hyp_fixture",
        strategy=strategy,
        max_hops=4,
        max_nodes=80,
    )
    second = retrieve_context(
        list(reversed(nodes)),
        list(reversed(edges)),
        hypothesis_id="hyp_fixture",
        strategy=strategy,
        max_hops=4,
        max_nodes=80,
    )
    identifiers = {str(node["node_id"]) for node in first.nodes}
    assert present in identifiers
    assert absent not in identifiers
    assert first == second
    text, metadata = serialize_context(first, token_budget=4096)
    assert metadata["estimated_tokens"] <= 4096
    assert json.loads(text.splitlines()[0])["context_id"] == first.context_id


def test_phase10_spec_is_context_grounded_and_renders_unverified_query() -> None:
    nodes, edges = _fixture_graph()
    context = retrieve_context(
        nodes,
        edges,
        hypothesis_id="hyp_fixture",
        strategy="unified_graph_pruned",
        max_hops=4,
        max_nodes=80,
    )
    _text, metadata = serialize_context(context, token_budget=4096)
    by_id = {str(node["node_id"]): node for node in context.nodes}
    response = json.dumps(
        {
            "specification": {
                "hypothesis_id": "hyp_fixture",
                "candidate_cwe": "CWE-79",
                "sources": [{"node_id": "evn_source", "rationale": "request input"}],
                "sinks": [{"node_id": "pgn_call", "rationale": "output call"}],
                "sanitizers": [],
                "propagators": [],
                "preconditions": [
                    {"text": "untrusted input reaches output", "evidence_node_ids": ["evn_source"]}
                ],
                "summary": "Candidate cross-site scripting flow.",
            }
        }
    )
    spec = parse_specification(
        response,
        project_id="proj_fixture",
        hypothesis_id="hyp_fixture",
        candidate_cwes=["CWE-79"],
        context_id=context.context_id,
        context_nodes=by_id,
        allowed_node_ids=set(metadata["serialized_node_ids"]),
        baseline_id="B9",
        attempt=1,
        max_role_items=8,
        max_preconditions=8,
    )
    query = render_query(spec, by_id)
    assert spec["status"] == "SYNTHESIZED_UNVERIFIED"
    assert "phase10AtLocation" in query
    assert "verification is Phase 11" in query
    assert "verified vulnerability" not in query.casefold()


def test_phase10_schema_and_parser_reject_out_of_context_or_wrong_role() -> None:
    schema = specification_json_schema(
        hypothesis_id="hyp_fixture",
        candidate_cwes=["CWE-79"],
        allowed_endpoint_ids_by_role={
            "sources": ["evn_source"],
            "sinks": ["evn_sink"],
            "sanitizers": [],
            "propagators": [],
        },
        allowed_evidence_ids=["evn_source", "evn_sink"],
        max_role_items=8,
        max_preconditions=8,
    )
    assert schema["additionalProperties"] is False
    specification_properties = schema["properties"]["specification"]["properties"]
    assert specification_properties["sanitizers"]["maxItems"] == 0
    assert specification_properties["sanitizers"]["items"]["properties"]["node_id"][
        "enum"
    ]
    assert specification_properties["propagators"]["maxItems"] == 0
    nodes, _edges = _fixture_graph()
    by_id = {str(node["node_id"]): node for node in nodes}
    invalid = json.dumps(
        {
            "specification": {
                "hypothesis_id": "hyp_fixture",
                "candidate_cwe": "CWE-79",
                "sources": [{"node_id": "evn_sink", "rationale": "wrong role"}],
                "sinks": [{"node_id": "evn_sink", "rationale": "sink"}],
                "sanitizers": [],
                "propagators": [],
                "preconditions": [],
                "summary": "Invalid source assignment.",
            }
        }
    )
    with pytest.raises(ValueError, match="requested semantic role"):
        parse_specification(
            invalid,
            project_id="proj_fixture",
            hypothesis_id="hyp_fixture",
            candidate_cwes=["CWE-79"],
            context_id="ctx_fixture",
            context_nodes=by_id,
            allowed_node_ids={"evn_source", "evn_sink"},
            baseline_id="B9",
            attempt=1,
            max_role_items=8,
            max_preconditions=8,
        )


def test_phase10_endpoint_preflight_matches_schema_roles() -> None:
    nodes, edges = _fixture_graph()
    context = retrieve_context(
        nodes,
        edges,
        hypothesis_id="hyp_fixture",
        strategy="unified_graph_pruned",
        max_hops=4,
        max_nodes=80,
    )
    _text, metadata = serialize_context(context, token_budget=4096)
    by_id = {str(node["node_id"]): node for node in context.nodes}
    roles = _endpoint_ids_by_role(by_id, set(metadata["serialized_node_ids"]))
    assert "evn_source" in roles["sources"]
    assert "evn_source" not in roles["sinks"]
    assert "evn_sink" in roles["sinks"]
    schema = specification_json_schema(
        hypothesis_id="hyp_fixture",
        candidate_cwes=["CWE-79"],
        allowed_endpoint_ids_by_role=roles,
        allowed_evidence_ids=["evn_hyp", "evn_source", "evn_sink"],
        max_role_items=8,
        max_preconditions=8,
    )
    assert _estimated_request_tokens("fixture", schema, repair_error="x" * 500) < 8192
