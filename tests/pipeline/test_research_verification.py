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
                    "source_file,source_line,sink_file,sink_line\n"
                    + ("App.java,2,App.java,5\n" if flows else "")
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
