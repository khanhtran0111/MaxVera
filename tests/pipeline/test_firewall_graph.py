"""Security and discovery regressions: actual denied filesystem access and graph provenance."""

import subprocess
import sys

import pytest


def test_os_firewall_denies_labels_even_when_path_is_known(tmp_path):
    from maxvera.sandbox import landlock_available

    if not landlock_available():
        pytest.skip("kernel lacks Landlock; production research must fail closed")
    allowed = tmp_path / "analysis_input"
    allowed.mkdir()
    (allowed / "case.txt").write_text("source")
    labels = tmp_path / "evaluator_only"
    labels.mkdir()
    secret = labels / "truth.txt"
    secret.write_text("POISON_GROUND_TRUTH_197")
    (allowed / "escape").symlink_to(secret)
    script = """import json,sys
from pathlib import Path
from maxvera.sandbox import restrict_reads
restrict_reads([Path(sys.argv[1])])
assert (Path(sys.argv[1])/'case.txt').read_text() == 'source'
for p in [sys.argv[2],str(Path(sys.argv[1])/'escape')]:
 try: Path(p).read_text()
 except PermissionError: continue
 raise AssertionError('ground truth readable')
print('denied')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(allowed), str(secret)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "denied"


def graph_fixture():
    nodes = [
        {
            "key": "source",
            "file": "Controller.java",
            "start_line": "4",
            "start_column": "2",
            "end_line": "4",
            "end_column": "30",
            "kind": "MethodCall",
            "symbol": "Request#getParameter(String)",
            "role": "source",
            "expression": 'req.getParameter("q")',
        },
        {
            "key": "middle",
            "file": "Service.java",
            "start_line": "7",
            "start_column": "2",
            "end_line": "7",
            "end_column": "20",
            "kind": "Parameter",
            "symbol": "Service#search(String)",
            "role": "",
            "expression": "q",
        },
        {
            "key": "sink",
            "file": "Repository.java",
            "start_line": "9",
            "start_column": "2",
            "end_line": "9",
            "end_column": "30",
            "kind": "MethodCall",
            "symbol": "Statement#execute(String)",
            "role": "sink",
            "expression": "stmt.execute(q)",
        },
    ]
    edges = [
        {"source": "source", "target": "middle", "kind": "ARG_TO_PARAM"},
        {"source": "middle", "target": "sink", "kind": "MAY_FLOW"},
    ]
    return nodes, edges


def test_graph_generators_discover_cross_file_candidate_without_static_alert(tmp_path):
    from maxvera.candidates import generate, rank
    from maxvera.graph import normalize_graph

    nodes, edges = graph_fixture()
    graph = normalize_graph("opaque-1", "snapshot-hash", nodes, edges, "query-hash")
    candidates = rank(generate(graph, [], max_hops=5), top_k=20)
    assert len(candidates) == 1
    c = candidates[0]
    assert set(c["origin_generators"]) == {"sink_backward_slice", "source_forward_slice"}
    assert len(c["graph_path_edge_ids"]) == 2
    assert c["verification_status"] == "NOT_ATTEMPTED"
    assert c["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
    assert c["rank_features"]["cross_file"] is True
    assert graph["quality"]["cross_file_edges"] == 2
    assert (
        graph["graph_hash"]
        == normalize_graph(
            "opaque-1", "snapshot-hash", list(reversed(nodes)), list(reversed(edges)), "query-hash"
        )["graph_hash"]
    )
    assert candidates == rank(generate(graph, [], max_hops=5), top_k=20)


def test_call_edges_never_become_dataflow_and_missing_edges_remain_partial():
    from maxvera.candidates import generate, rank
    from maxvera.graph import normalize_graph

    nodes, edges = graph_fixture()
    edges[1]["kind"] = "CALLS"
    graph = normalize_graph("opaque-1", "hash", nodes, edges, "query")
    candidates = rank(generate(graph, [], max_hops=5), top_k=20)
    assert candidates
    assert all(c["discovery_status"] != "COMPLETE_CANDIDATE_PATH" for c in candidates)
    assert all(c["verification_status"] == "NOT_ATTEMPTED" for c in candidates)
    assert not any(e["evidence_class"] == "VERIFIED" for e in graph["edges"])


def test_graph_rejects_dangling_edges_and_unsafe_locations():
    from maxvera.graph import normalize_graph

    nodes, edges = graph_fixture()
    edges.append({"source": "missing", "target": "sink", "kind": "MAY_FLOW"})
    with pytest.raises(ValueError, match=r"missing|dangling"):
        normalize_graph("opaque-1", "hash", nodes, edges, "query")
    nodes[0]["file"] = "../evaluator_only/labels.csv"
    with pytest.raises(ValueError, match=r"path|relative"):
        normalize_graph("opaque-1", "hash", nodes, [], "query")


def test_static_candidates_preserve_real_path_evidence_and_location_only_is_weak():
    from maxvera.candidates import generate
    from maxvera.graph import normalize_graph

    graph = normalize_graph("opaque-1", "snapshot", [], [], "query")
    alerts = [
        {
            "locations": [{"file": "X.java", "start_line": 7, "end_line": 7}],
            "path_evidence": "CODEQL_FLOW",
        },
        {
            "locations": [{"file": "Y.java", "start_line": 9, "end_line": 9}],
            "path_evidence": "LOCATION_ONLY",
        },
    ]
    candidates = generate(graph, alerts)
    by_file = {c["locations"][0]["file"]: c for c in candidates}
    assert by_file["X.java"]["discovery_status"] == "STATIC_CONFIRMED"
    assert by_file["Y.java"]["discovery_status"] == "SINK_ONLY"


def test_snapshot_change_invalidates_resume_fingerprint(tmp_path):
    from maxvera.cli import input_fingerprints

    view = tmp_path / "data/processed/analysis_input/projects/opaque-1"
    view.mkdir(parents=True)
    source = view / "X.java"
    source.write_text("class X {}")
    cases = [{"case_id": "opaque-1", "source_dir": "projects/opaque-1"}]
    first = input_fingerprints(tmp_path, cases, research=True)
    source.write_text("class X { int changed; }")
    second = input_fingerprints(tmp_path, cases, research=True)
    assert first[0]["snapshot_content_hash"] != second[0]["snapshot_content_hash"]
