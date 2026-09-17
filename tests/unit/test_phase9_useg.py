from __future__ import annotations

from pathlib import Path

import yaml

from src.graphs.evidence.model import EDGE_KINDS, EVIDENCE_NODE_KINDS, cycle_nodes
from src.graphs.useg.builder import _build_project, _trace_audit

REPO_ROOT = Path(__file__).resolve().parents[2]


def _experiment() -> dict[str, object]:
    return {
        "analysis_iteration": 0,
        "development_dependencies": {
            "phase6": {"run_id": "p6"},
            "phase7": {"run_id": "p7"},
            "phase8": {"run_id": "p8"},
        },
        "mapping": {
            "version": "phase9-cross-layer-mapping-v1",
            "prefer_exact_symbol": True,
            "max_program_matches_per_assertion": 3,
            "max_security_api_matches_per_assertion": 8,
            "max_precondition_matches_per_assertion": 8,
            "max_taint_candidates_per_hypothesis": 16,
        },
    }


def _security_node(
    node_id: str, kind: str, identity: str, properties: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "node_id": node_id,
        "kind": kind,
        "identity": identity,
        "label": identity,
        "properties": properties,
        "confidence": 1.0,
        "provenance": [{"source_id": "fixture"}],
    }


def test_phase9_config_pins_schema_and_all_three_upstreams() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase9_useg.yaml").read_text(encoding="utf-8")
    )
    assert config["protocol_version"] == "1.6.0"
    assert config["analysis_iteration"] == 0
    assert set(config["schema"]["evidence_node_kinds"]) == EVIDENCE_NODE_KINDS
    assert set(config["schema"]["edge_kinds"]) == EDGE_KINDS
    assert config["development_dependencies"]["phase6"]["run_id"] == (
        "p6_static_v2_dev_full_001"
    )
    assert config["development_dependencies"]["phase7"]["run_id"] == (
        "p7_pg_dev_full_004"
    )
    assert config["development_dependencies"]["phase8"]["run_id"] == (
        "p8_skg_global_full_002"
    )
    assert config["execution"]["llm_calls"] == 0
    assert config["execution"]["network_calls"] == 0


def test_phase9_canonical_selection_is_locked_to_clean_full_003() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/main.yaml").read_text(encoding="utf-8")
    )
    lock = config["development_locks"]["phase9_evidence_graph_useg"]
    assert lock["status"] == "locked_for_downstream_development"
    assert lock["canonical_run_id"] == "p9_useg_dev_full_003"
    assert lock["run_commit"] == "2395d219789ad5401e1fecdb26cee9030208c19b"
    assert lock["run_git_dirty"] is False
    assert lock["graph_sha256"] == (
        "918707ee3bbb59858b2b2d8dd9aafb762467f983bf579c97e35ba4191a1a41fa"
    )
    assert lock["manifest_sha256"] == (
        "83dce921c979db710762bd205588c667033bc10fb6c64c4581fce9a8c84810c7"
    )


def test_phase9_cross_layer_candidate_path_is_acyclic_and_fully_traceable() -> None:
    project_id = "proj_fixture"
    program_nodes = [
        {
            "node_id": "pgn_source",
            "project_id": project_id,
            "kind": "EXPR",
            "subkind": "MethodCall",
            "symbol": "println",
            "type_name": "void",
            "location": {
                "file": "src/Test.java",
                "start_line": 10,
                "start_column": 1,
                "end_line": 10,
                "end_column": 20,
            },
            "provenance": {"tool_version": "2.26.2", "query_sha256": "1" * 64},
        },
        {
            "node_id": "pgn_target",
            "project_id": project_id,
            "kind": "EXPR",
            "subkind": "VarAccess",
            "symbol": "value",
            "type_name": "String",
            "location": {
                "file": "src/Test.java",
                "start_line": 10,
                "start_column": 21,
                "end_line": 10,
                "end_column": 26,
            },
            "provenance": {"tool_version": "2.26.2", "query_sha256": "1" * 64},
        },
    ]
    program_edges = [
        {
            "edge_id": "pge_candidate",
            "kind": "TAINT_CANDIDATE",
            "source_id": "pgn_source",
            "target_id": "pgn_target",
            "provenance": {"tool_version": "2.26.2", "query_sha256": "2" * 64},
        }
    ]
    cwe = _security_node("skgn_cwe79", "CWE", "CWE-79", {})
    sink = _security_node(
        "skgn_sink", "SINK", "sink:println", {"callable": "println", "type": "Writer"}
    )
    precondition = _security_node("skgn_pre", "PRECONDITION", "precondition", {})
    security_nodes = {
        str(node["node_id"]): node for node in (cwe, sink, precondition)
    }
    hypotheses = [
        {
            "hypothesis_id": "hyp_fixture",
            "candidate_cwe": ["CWE-79"],
            "generator": "static_rules",
            "rank": 1,
            "ranking_version": "phase6-family-balanced-v2",
            "score": 0.8,
            "locations": [
                {"file": "src/Test.java", "line": 10, "role": "sink", "symbol": "println"}
            ],
            "preconditions": ["Untrusted content reaches output."],
        }
    ]
    store, summary = _build_project(
        project_id=project_id,
        hypotheses=hypotheses,
        program_nodes=program_nodes,
        program_edges=program_edges,
        security_nodes=security_nodes,
        cwe_nodes={"CWE-79": cwe},
        security_adjacency={
            ("skgn_cwe79", "HAS_SINK"): ["skgn_sink"],
            ("skgn_cwe79", "HAS_PRECONDITION"): ["skgn_pre"],
        },
        experiment=_experiment(),
        config_sha256="a" * 64,
        phase6_hypotheses_sha="b" * 64,
        phase7_nodes_artifact="graphs/proj_fixture/nodes.jsonl",
        phase7_nodes_sha="c" * 64,
        phase7_edges_artifact="graphs/proj_fixture/edges.jsonl",
        phase7_edges_sha="d" * 64,
        phase8_nodes_sha="e" * 64,
    )
    nodes = list(store.nodes.values())
    edges = list(store.edges.values())
    assert summary["program_mapped_assertions"] == 1
    assert summary["security_mapped_assertions"] == 2
    assert summary["candidate_taint_paths"] == 1
    assert {node["kind"] for node in nodes if node["layer"] == "evidence"} == {
        "HYPOTHESIS",
        "ASSERTION",
        "CODEQL_FINDING",
        "TAINT_PATH",
    }
    assert not cycle_nodes(nodes, edges)
    audit = _trace_audit(nodes, edges)
    assert audit["status"] == "PASS"
    assert audit["candidate_paths_with_program_and_security_trace"] == 1
    assert audit["final_finding_gate"] == "PASS_NO_FINAL_FINDINGS_PHASE9"


def test_phase9_cycle_detection_reports_double_counting_risk() -> None:
    nodes = [{"node_id": "a"}, {"node_id": "b"}]
    edges = [
        {"source_id": "a", "target_id": "b"},
        {"source_id": "b", "target_id": "a"},
    ]
    assert cycle_nodes(nodes, edges) == ["a", "b"]
