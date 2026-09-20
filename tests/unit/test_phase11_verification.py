from __future__ import annotations

from src.verification.query import query_id, render_endpoint_query, render_path_query
from src.verification.runner import _status


def _spec() -> dict[str, object]:
    return {
        "specification_id": "spec_example_001",
        "candidate_cwe": "CWE-78",
        "sources": [{"node_id": "source"}],
        "sinks": [{"node_id": "sink"}],
        "sanitizers": [],
        "propagators": [],
    }


def _nodes() -> dict[str, dict[str, object]]:
    return {
        "source": {
            "layer": "program",
            "properties": {"location": {"file": "src/Main.java", "start_line": 10}},
        },
        "sink": {
            "layer": "security",
            "properties": {"fact_properties": {"callable": "exec", "type": "Runtime"}},
        },
    }


def test_rendered_queries_use_global_taint_tracking_and_valid_ids() -> None:
    endpoint = render_endpoint_query(_spec(), _nodes())
    path = render_path_query(_spec(), _nodes())
    assert "@kind table" in endpoint
    assert "phase11Source(endpoint)" in endpoint
    assert "TaintTracking::Global<Phase11Config>" in path
    assert "Phase11Flow::flowPath(source, sink)" in path
    assert query_id("spec_example_001") == "java/maxvera/phase11/spec-example-001"
    assert "SYNTHESIZED_UNVERIFIED" not in path


def test_only_vulnerable_fixed_disappearance_is_verified() -> None:
    path = {"source_endpoints": 1, "sink_endpoints": 1, "path_count": 1}
    no_path = {"source_endpoints": 1, "sink_endpoints": 1, "path_count": 0}
    assert _status(path, no_path)[0] == "VERIFIED_DIFFERENTIAL"
    assert _status(path, None)[0] == "UNVERIFIED_FIXED_NOT_RUN"
    assert _status(path, path)[0] == "UNVERIFIED_PERSISTS_FIXED"
    assert _status(no_path, None)[0] == "UNVERIFIED_NO_VULNERABLE_PATH"
    assert (
        _status({"source_endpoints": 0, "sink_endpoints": 1, "path_count": 0}, None)[0]
        == "UNVERIFIED_UNRESOLVED_SOURCE"
    )
