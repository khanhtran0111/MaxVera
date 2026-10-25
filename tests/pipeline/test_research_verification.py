"""Targeted verification is a modeled flow check, never a safety verdict."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maxvera.orchestration import Context, StageFailure
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def context(tmp_path: Path, *, endpoint=True) -> Context:
    run = tmp_path / "run"
    base = run / "stages/opaque-case"
    stage = base / "targeted_verify"
    stage.mkdir(parents=True)
    workspace = base / "static_extract/workspace"
    workspace.mkdir(parents=True)
    (workspace / "App.java").write_text("class App {}\n")
    from src.common.provenance import sha256_file

    content = sha256_file(workspace / "App.java")
    graph = {
        "snapshot_id": "snapshot",
        "nodes": [
            {
                "node_id": "source",
                "file": "App.java",
                "start_line": 2,
                "end_line": 2,
                "start_column": 3,
                "end_column": 9,
                "kind": "MethodCall",
                "roles": ["source"],
                "content_hash": content,
            },
            {
                "node_id": "sink",
                "file": "App.java",
                "start_line": 5,
                "end_line": 5,
                "start_column": 4,
                "end_column": 12,
                "kind": "MethodCall",
                "roles": ["sink"],
                "content_hash": content,
            },
        ],
        "edges": [],
    }
    atomic_json(base / "build_graph/graph.json", graph)
    atomic_jsonl(
        base / "candidate_rank/candidates_ranked.jsonl",
        [
            {
                "candidate_id": "cand-1",
                "snapshot_id": "snapshot",
                "source_node_id": "source" if endpoint else None,
                "sink_node_id": "sink",
                "rank_pre_llm": 1,
            }
        ],
    )
    database = run / "databases/opaque-case"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("language: java\n")
    (database / "src.zip").write_bytes(b"source archive fixture")
    (database / "db-java/default").mkdir(parents=True)
    (database / "db-java/default/data.rel").write_bytes(b"relation fixture")
    from maxvera.research_database import freeze_database

    frozen_ctx = Context(tmp_path, run, base / "static_extract", {"case_id": "opaque-case"}, {}, {})
    database_identity = freeze_database(frozen_ctx, "snapshot")
    pack = tmp_path / "src/static_analysis/queries/v2"
    pack.mkdir(parents=True)
    (pack / "qlpack.yml").write_text(
        "name: test/research\nversion: 1.0.0\ndependencies:\n  codeql/java-all: 9.2.2\n"
    )
    binary = tmp_path / "codeql"
    binary.write_text("placeholder")
    return Context(
        tmp_path,
        run,
        stage,
        {"case_id": "opaque-case"},
        {
            "selected_variant": {"targeted_verification": True},
            "codeql": {
                "research_binary": "codeql",
                "per_query_timeout_s": 30,
                "ram_mb": 1024,
                "threads": 1,
            },
            "research": {"max_verification_queries_per_case": 40},
        },
        {
            "static_extract": {
                "result": {
                    **database_identity,
                    "analyzed_snapshot_id": "snapshot",
                    "analyzed_files": {"App.java": content},
                }
            }
        },
    )


@pytest.mark.parametrize(
    "sources,sinks,flow_count,want",
    [
        (1, 1, 1, "FLOW_FOUND"),
        (1, 1, 0, "NO_FLOW_FOUND"),
        (0, 1, 0, "UNSUPPORTED_SPEC"),
        (1, 0, 0, "UNSUPPORTED_SPEC"),
        (2, 1, 0, "UNSUPPORTED_SPEC"),
    ],
)
def test_actual_flow_result_and_unresolved_endpoints_have_distinct_statuses(
    sources, sinks, flow_count, want
):
    from maxvera.research_verification import classify_verification

    assert classify_verification(sources, sinks, flow_count) == want


def test_targeted_queries_bind_both_endpoint_columns_and_never_use_oracle_labels(tmp_path):
    from maxvera.research_verification import render_queries

    ctx = context(tmp_path)
    graph = json.loads((ctx.run_dir / "stages/opaque-case/build_graph/graph.json").read_text())
    endpoint_query, flow_query = render_queries("cand-1", graph["nodes"][0], graph["nodes"][1])
    assert "TaintTracking::Global" in flow_query
    for query in (endpoint_query, flow_query):
        assert '"App.java"' in query
        assert "getStartColumn() = 3" in query
        assert "getEndColumn() = 9" in query
        assert "getStartColumn() = 4" in query
        assert "getEndColumn() = 12" in query
        assert "CVE" not in query and "CWE" not in query


def test_absent_explicit_source_is_unsupported_without_running_tools(tmp_path, monkeypatch):
    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path, endpoint=False)

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported candidate must not run an unconstrained query")

    monkeypatch.setattr("maxvera.research_verification.command", unexpected)
    result = targeted_verify(ctx)
    records = read_jsonl(ctx.stage_dir / "verification.jsonl")
    assert records[0]["status"] == "UNSUPPORTED_SPEC"
    assert records[0]["decision"] == "REVIEW"
    assert result["flow_found"] == 0


@pytest.mark.parametrize("flows,want", [(0, "NO_FLOW_FOUND"), (1, "FLOW_FOUND")])
def test_result_is_derived_from_decoded_codeql_output(tmp_path, monkeypatch, flows, want):
    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path)
    original = (
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    ).read_bytes()

    def tool(args, **kwargs):
        if args[1:3] == ["bqrs", "decode"]:
            output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
            if "endpoints" in output.name:
                output.write_text("source_count,sink_count\n1,1\n")
            else:
                output.write_text(
                    "source_file,source_line,source_start_column,source_end_line,source_end_column,"
                    "sink_file,sink_line,sink_start_column,sink_end_line,sink_end_column\n"
                    + ("App.java,2,3,2,9,App.java,5,4,5,12\n" if flows else "")
                )
        elif args[1:3] == ["query", "run"]:
            assert f"--database={ctx.run_dir}/databases/opaque-case" in args
            output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
            output.write_text("bqrs fixture")
        kwargs["log"].write_text("tool complete")

    monkeypatch.setattr("maxvera.research_verification.command", tool)
    result = targeted_verify(ctx)
    records = read_jsonl(ctx.stage_dir / "verification.jsonl")
    assert records[0]["status"] == want
    assert records[0]["decision"] == "REVIEW"
    assert records[0]["query_invocations"] == 2
    assert result["flow_found"] == flows
    assert (
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    ).read_bytes() == original


@pytest.mark.parametrize("failure", ["TIMEOUT", "QUERY_INVALID"])
def test_tool_failure_is_explicit_and_never_flow_found(tmp_path, monkeypatch, failure):
    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path)

    def tool(args, **kwargs):
        raise StageFailure(failure, "fixture CodeQL failure")

    monkeypatch.setattr("maxvera.research_verification.command", tool)
    result = targeted_verify(ctx)
    rows = read_jsonl(ctx.stage_dir / "verification.jsonl")
    assert rows[0]["status"] == failure
    assert rows[0]["decision"] == "REVIEW"
    assert result["flow_found"] == 0


def test_verifier_refuses_mutated_source_snapshot(tmp_path, monkeypatch):
    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path)
    (ctx.run_dir / "stages/opaque-case/static_extract/workspace/App.java").write_text("mutated")
    result = targeted_verify(ctx)
    rows = read_jsonl(ctx.stage_dir / "verification.jsonl")
    assert rows[0]["status"] == "UNSUPPORTED_SPEC"
    assert result["flow_found"] == 0


@pytest.mark.parametrize("csv_text", ["", "unrelated_column\nanything\n"])
def test_malformed_flow_table_is_query_invalid_not_no_flow(tmp_path, monkeypatch, csv_text):
    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path)

    def tool(args, **kwargs):
        if args[1:3] == ["bqrs", "decode"]:
            output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
            output.write_text(
                "source_count,sink_count\n1,1\n" if "endpoints" in output.name else csv_text
            )
        elif args[1:3] == ["query", "run"]:
            output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
            output.write_text("fixture")
        kwargs["log"].write_text("complete")

    monkeypatch.setattr("maxvera.research_verification.command", tool)
    targeted_verify(ctx)
    rows = read_jsonl(ctx.stage_dir / "verification.jsonl")
    assert rows[0]["status"] == "QUERY_INVALID"


@pytest.mark.parametrize("attack", ["mutate", "replace", "add_relation", "delete_archive"])
def test_database_changed_after_extraction_cannot_run_verification(tmp_path, monkeypatch, attack):
    import shutil

    from maxvera.research_verification import targeted_verify

    ctx = context(tmp_path)
    database = ctx.run_dir / "databases/opaque-case"
    if attack == "mutate":
        (database / "codeql-database.yml").write_text("different database")
    elif attack == "replace":
        shutil.rmtree(database)
        database.mkdir()
        (database / "codeql-database.yml").write_text("replacement database")
    elif attack == "add_relation":
        relation = database / "db-java/default/injected.rel"
        relation.parent.mkdir(parents=True, exist_ok=True)
        relation.write_text("injected relation")
    else:
        (database / "src.zip").unlink()

    def unexpected(*args, **kwargs):
        pytest.fail("changed research database must fail before any query invocation")

    monkeypatch.setattr("maxvera.research_verification.command", unexpected)
    with pytest.raises(StageFailure, match=r"database|identity|integrity"):
        targeted_verify(ctx)


def test_semantic_endpoint_identity_preserves_full_database_binding(tmp_path):
    from maxvera.research_database import validate_database
    from maxvera.research_verification import _endpoints

    ctx = context(tmp_path)
    extraction = ctx.results["static_extract"]["result"]
    extraction["semantic_snapshot_id"] = "semantic-source"
    graph_path = ctx.run_dir / "stages/opaque-case/build_graph/graph.json"
    graph = json.loads(graph_path.read_text())
    graph["snapshot_id"] = "semantic-source"
    candidate = read_jsonl(
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    )[0]
    candidate["snapshot_id"] = "semantic-source"
    source, sink = _endpoints(ctx, candidate, graph)
    assert source["node_id"] == "source" and sink["node_id"] == "sink"
    assert validate_database(ctx)["analyzed_snapshot_id"] == "snapshot"


@pytest.mark.parametrize("foreign", ["graph", "candidate"])
def test_semantic_identity_does_not_allow_foreign_build_endpoints(tmp_path, foreign):
    from maxvera.research_verification import _endpoints

    ctx = context(tmp_path)
    ctx.results["static_extract"]["result"]["semantic_snapshot_id"] = "snapshot"
    graph = json.loads((ctx.run_dir / "stages/opaque-case/build_graph/graph.json").read_text())
    candidate = read_jsonl(
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    )[0]
    if foreign == "graph":
        graph["analyzed_snapshot_id"] = "other-build"
    else:
        candidate["provenance"] = {"analyzed_snapshot_id": "other-build"}
    with pytest.raises(ValueError, match="different analyzed build"):
        _endpoints(ctx, candidate, graph)


def test_static_alert_retains_exact_endpoint_spec_without_volatile_rank_identity():
    from maxvera.candidates import generate

    graph = {
        "case_id": "opaque",
        "snapshot_id": "snapshot",
        "nodes": [],
        "edges": [],
        "graph_hash": "empty",
    }
    semantic = {
        "file": "App.java",
        "start_line": 2,
        "start_column": 3,
        "end_line": 2,
        "end_column_exclusive": 10,
    }
    alert = {
        "locations": [{"file": "App.java", "start_line": 2, "end_line": 2}],
        "path_evidence": "CODEQL_FLOW",
        "static_endpoint_spec": {
            "schema_version": "1.0",
            "status": "EXACT_SPAN",
            "source": semantic,
            "sink": semantic,
            "sarif_sha256": "build-one",
            "selector": [0, 0, 0, 0],
        },
    }
    first = generate(graph, [alert])[0]
    assert first.get("static_endpoint_spec") == alert["static_endpoint_spec"]
    alert["static_endpoint_spec"] = {
        **alert["static_endpoint_spec"],
        "sarif_sha256": "build-two",
        "selector": [1, 2, 3, 4],
    }
    second = generate(graph, [alert])[0]
    assert first["candidate_id"] == second["candidate_id"]
    assert first["semantic_rank_key"] == second["semantic_rank_key"]


def sarif_context(tmp_path, *, missing_column=False, duplicate=False):
    """Exercise raw SARIF -> normalized alert -> boundary -> retained candidate."""
    from maxvera.reproduction import normalize_sarif
    from maxvera.research import candidate_generate
    from maxvera.sarif_endpoints import attach_endpoint_specs
    from src.common.provenance import sha256_file

    ctx = context(tmp_path)
    base = ctx.stage_dir.parent
    source = base / "static_extract/workspace/App.java"
    source.write_text(
        "class App {\n  String source = getInput();\n  void run() {\n    use(source);\n  }\n}\n"
    )
    ctx.results["static_extract"]["result"]["analyzed_files"]["App.java"] = sha256_file(source)
    locations = []
    for line, start, end in [(2, 19, 29), (4, 9, 15)]:
        region = {"startLine": line, "startColumn": start, "endColumn": end}
        if missing_column:
            region.pop("endColumn")
        locations.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "App.java", "uriBaseId": "%SRCROOT%"},
                        "region": region,
                    }
                }
            }
        )
    result = {"ruleId": "java/fixture", "codeFlows": [{"threadFlows": [{"locations": locations}]}]}
    sarif = {
        "version": "2.1.0",
        "runs": [{"results": []}, {"columnKind": "utf16CodeUnits", "results": [result]}],
    }
    if duplicate:
        sarif["runs"][1]["results"].append(result)
    path = base / "static_extract/static.sarif"
    atomic_json(path, sarif)
    alerts = attach_endpoint_specs(normalize_sarif(path, "opaque-case", "static_alerts"), path)
    atomic_jsonl(base / "static_extract/static_signals.jsonl", alerts)
    generation = base / "candidate_generate"
    generation.mkdir()
    config = {
        "selected_variant": {"graph_enabled": False, "candidate_sources": ["static_alerts"]},
        "research": {},
        "evidence": {"max_graph_hops": 5},
    }
    candidate_generate(Context(ctx.root, ctx.run_dir, generation, ctx.case, config, ctx.results))
    candidate = read_jsonl(generation / "candidates_raw.jsonl")[0]
    atomic_jsonl(base / "candidate_rank/candidates_ranked.jsonl", [candidate])
    atomic_json(
        base / "build_graph/graph.json", {"snapshot_id": "snapshot", "nodes": [], "edges": []}
    )
    return ctx, candidate, path


def test_sarif_full_spans_survive_candidate_generation_and_convert_exclusive_columns(tmp_path):
    from maxvera.research_verification import _endpoints, render_queries

    ctx, candidate, _ = sarif_context(tmp_path)
    assert candidate["static_endpoint_spec"]["selector"] == [1, 0, 0, 0]
    assert candidate["source_node_id"] is None and candidate["sink_node_id"] is None
    graph = json.loads((ctx.stage_dir.parent / "build_graph/graph.json").read_text())
    source, sink = _endpoints(ctx, candidate, graph)
    assert (source["start_line"], source["start_column"], source["end_column"]) == (2, 19, 28)
    assert (sink["start_line"], sink["start_column"], sink["end_column"]) == (4, 9, 14)
    query, _ = render_queries(candidate["candidate_id"], source, sink)
    assert "getEndColumn() = 28" in query
    assert "getEndColumn() = 29" not in query
    assert "DataFlow::exprNode" in query and "DataFlow::parameterNode" in query


@pytest.mark.parametrize("missing,duplicate", [(True, False), (False, True)])
def test_incomplete_or_ambiguous_sarif_remains_retained_unsupported(
    tmp_path, monkeypatch, missing, duplicate
):
    from maxvera.research_verification import targeted_verify

    ctx, candidate, _ = sarif_context(tmp_path, missing_column=missing, duplicate=duplicate)
    assert candidate["discovery_status"] == "STATIC_CONFIRMED"
    monkeypatch.setattr(
        "maxvera.research_verification.command",
        lambda *a, **k: pytest.fail("unsupported SARIF must not query"),
    )
    targeted_verify(ctx)
    record = read_jsonl(ctx.stage_dir / "verification.jsonl")[0]
    assert record["status"] == "UNSUPPORTED_SPEC" and record["query_invocations"] == 0


@pytest.mark.parametrize(
    "attack",
    [
        "raw",
        "selector",
        "span",
        "locations",
        "source",
        "boundary",
        "mixed",
        "path_symlink",
        "provenance",
    ],
)
def test_sarif_linkage_integrity_and_source_boundary_fail_closed(tmp_path, monkeypatch, attack):
    from maxvera.research_verification import targeted_verify

    ctx, candidate, path = sarif_context(tmp_path)
    if attack == "raw":
        path.write_text(path.read_text() + "\n")
    elif attack == "selector":
        candidate["static_endpoint_spec"]["selector"][1] = 999
    elif attack == "span":
        candidate["static_endpoint_spec"]["source"]["start_column"] += 1
    elif attack == "locations":
        candidate["locations"][0]["start_line"] += 1
    elif attack == "source":
        (path.parent / "workspace/App.java").write_text("changed source")
    elif attack == "boundary":
        candidate["static_signal_scope"]["status"] = "PARTIAL_EXTERNAL_FLOW"
    elif attack == "mixed":
        candidate["static_signal_scope"]["excluded_location_count"] = 1
    elif attack == "path_symlink":
        source = path.parent / "workspace/App.java"
        original = path.parent / "outside.java"
        source.replace(original)
        source.symlink_to(original)
    else:
        candidate["provenance"]["analyzed_snapshot_id"] = "foreign-build"
    atomic_jsonl(ctx.stage_dir.parent / "candidate_rank/candidates_ranked.jsonl", [candidate])
    monkeypatch.setattr(
        "maxvera.research_verification.command",
        lambda *a, **k: pytest.fail("integrity failure must not query"),
    )
    targeted_verify(ctx)
    record = read_jsonl(ctx.stage_dir / "verification.jsonl")[0]
    assert record["status"] == "UNSUPPORTED_SPEC" and record["query_invocations"] == 0


@pytest.mark.parametrize(
    "source_count,sink_count,want,queries",
    [
        (0, 1, "UNSUPPORTED_SPEC", 1),
        (1, 0, "UNSUPPORTED_SPEC", 1),
        (2, 1, "UNSUPPORTED_SPEC", 1),
        (1, 2, "UNSUPPORTED_SPEC", 1),
        (1, 1, "NO_FLOW_FOUND", 2),
    ],
)
def test_exact_sarif_binding_requires_unique_both_endpoints(
    tmp_path, monkeypatch, source_count, sink_count, want, queries
):
    from maxvera.research_verification import targeted_verify

    ctx, _, _ = sarif_context(tmp_path)

    def tool(args, **kwargs):
        output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
        if args[1:3] == ["bqrs", "decode"]:
            output.write_text(
                f"source_count,sink_count\n{source_count},{sink_count}\n"
                if output.stem == "endpoints"
                else "source_file,source_line,source_start_column,"
                "source_end_line,source_end_column,"
                "sink_file,sink_line,sink_start_column,sink_end_line,sink_end_column\n"
            )
        else:
            output.write_text("fixture")
        kwargs["log"].write_text("complete")

    monkeypatch.setattr("maxvera.research_verification.command", tool)
    targeted_verify(ctx)
    record = read_jsonl(ctx.stage_dir / "verification.jsonl")[0]
    assert record["status"] == want and record["query_invocations"] == queries
    assert record["decision"] == "REVIEW" and record["is_safety_verdict"] is False


def test_flow_query_returns_full_endpoint_spans_for_decoded_result_validation(tmp_path):
    from maxvera.research_verification import _endpoints, render_queries

    ctx, candidate, _ = sarif_context(tmp_path)
    graph = json.loads((ctx.stage_dir.parent / "build_graph/graph.json").read_text())
    source, sink = _endpoints(ctx, candidate, graph)
    _, flow = render_queries(candidate["candidate_id"], source, sink)
    for role in ("source", "sink"):
        for column in ("start_column", "end_line", "end_column"):
            assert f"as {role}_{column}" in flow


@pytest.mark.parametrize("attack", ["column", "line", "file", "nonnumeric", "negative_count"])
def test_decoded_sarif_flow_output_must_match_every_frozen_coordinate(
    tmp_path, monkeypatch, attack
):
    from maxvera.research_verification import FLOW_COLUMNS, targeted_verify

    ctx, _, _ = sarif_context(tmp_path)

    def tool(args, **kwargs):
        output = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output=")))
        if args[1:3] == ["bqrs", "decode"]:
            if output.stem == "endpoints":
                output.write_text(
                    "source_count,sink_count\n"
                    + ("-1,1\n" if attack == "negative_count" else "1,1\n")
                )
            else:
                values = ["App.java", "2", "19", "2", "28", "App.java", "4", "9", "4", "14"]
                index, replacement = {
                    "column": (9, "13"),
                    "line": (8, "5"),
                    "file": (0, "Other.java"),
                    "nonnumeric": (2, "NaN"),
                }[attack]
                values[index] = replacement
                output.write_text(",".join(FLOW_COLUMNS) + "\n" + ",".join(values) + "\n")
        else:
            output.write_text("fixture")
        kwargs["log"].write_text("complete")

    monkeypatch.setattr("maxvera.research_verification.command", tool)
    targeted_verify(ctx)
    record = read_jsonl(ctx.stage_dir / "verification.jsonl")[0]
    assert record["status"] == "QUERY_INVALID"
    assert record["decision"] == "REVIEW" and record["is_safety_verdict"] is False


@pytest.mark.parametrize("uri", ["/App.java", "file:///App.java", "%2fApp.java", "../App.java"])
def test_sarif_absolute_or_escaping_uri_cannot_alias_repository_file(tmp_path, uri):
    from maxvera.reproduction import normalize_sarif
    from maxvera.sarif_endpoints import attach_endpoint_specs

    _, _, path = sarif_context(tmp_path)
    raw = json.loads(path.read_text())
    entry = raw["runs"][1]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0]
    entry["location"]["physicalLocation"]["artifactLocation"]["uri"] = uri
    atomic_json(path, raw)
    alert = attach_endpoint_specs(normalize_sarif(path, "opaque-case", "static_alerts"), path)[0]
    assert alert["static_endpoint_spec"]["status"] == "UNSUPPORTED_SPAN"


def test_changing_exact_endpoint_columns_changes_static_candidate_semantic_identity():
    from maxvera.candidates import generate

    graph = {
        "case_id": "opaque",
        "snapshot_id": "snapshot",
        "nodes": [],
        "edges": [],
        "graph_hash": "empty",
    }
    endpoint = {
        "file": "App.java",
        "start_line": 2,
        "start_column": 3,
        "end_line": 2,
        "end_column_exclusive": 10,
    }
    alert = {
        "locations": [{"file": "App.java", "start_line": 2, "end_line": 2}],
        "path_evidence": "CODEQL_FLOW",
        "static_endpoint_spec": {
            "status": "EXACT_SPAN",
            "source": endpoint,
            "sink": endpoint,
            "binding_policy": "EXACT",
        },
    }
    original = generate(graph, [alert])[0]
    alert["static_endpoint_spec"] = {
        **alert["static_endpoint_spec"],
        "source": {**endpoint, "start_column": 4},
    }
    changed = generate(graph, [alert])[0]
    assert original["candidate_id"] != changed["candidate_id"]
    assert original["semantic_rank_key"] != changed["semantic_rank_key"]


def test_sarif_unknown_uri_base_and_column_unit_remain_uncertain(tmp_path):
    from maxvera.reproduction import normalize_sarif
    from maxvera.sarif_endpoints import attach_endpoint_specs

    _, _, path = sarif_context(tmp_path)
    raw = json.loads(path.read_text())
    entry = raw["runs"][1]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0]
    entry["location"]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%EXTERNAL%"
    atomic_json(path, raw)
    alert = attach_endpoint_specs(normalize_sarif(path, "opaque-case", "static_alerts"), path)[0]
    assert alert["static_endpoint_spec"]["status"] == "UNSUPPORTED_SPAN"
    entry["location"]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
    raw["runs"][1]["columnKind"] = "unicodeCodePoints"
    atomic_json(path, raw)
    alert = attach_endpoint_specs(normalize_sarif(path, "opaque-case", "static_alerts"), path)[0]
    assert alert["static_endpoint_spec"]["status"] == "UNSUPPORTED_SPAN"
