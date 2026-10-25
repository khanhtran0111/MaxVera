"""Pinned CodeQL's actual SARIF binds exact source-backed endpoints, without graph IDs."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("MAXVERA_RUN_CODEQL_FIXTURE") != "1",
    reason="opt-in tiny local SARIF CodeQL fixture; no benchmark/API runs",
)
def test_real_sarif_exact_endpoint_binding_and_modeled_flow(tmp_path):
    from maxvera.candidates import generate
    from maxvera.graph_provenance import scope_static_signals
    from maxvera.orchestration import Context
    from maxvera.reproduction import normalize_sarif
    from maxvera.research_database import freeze_database
    from maxvera.research_verification import targeted_verify
    from maxvera.sarif_endpoints import attach_endpoint_specs
    from src.common.provenance import sha256_file
    from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl

    case = {"case_id": "opaque-sarif"}
    run_dir = tmp_path / "run"
    extraction = run_dir / "stages/opaque-sarif/static_extract"
    workspace = extraction / "workspace"
    workspace.mkdir(parents=True)
    # A supplementary Unicode character before the endpoints distinguishes UTF-16
    # source columns from Unicode code-point columns.
    (workspace / "App.java").write_text(
        "class App {\n  void run() throws Exception {\n"
        '    String label = "😀"; String input = System.getenv("COMMAND");\n'
        "    Runtime.getRuntime().exec(input);\n  }\n}\n",
        encoding="utf-8",
    )
    codeql = ROOT / ".cache/toolchains/codeql-2.26.2/codeql"
    javac = ROOT / ".cache/toolchains/cwe_bench_java/jdk-17/bin/javac"
    database = run_dir / "databases/opaque-sarif"
    database.parent.mkdir(parents=True)

    def command(args):
        completed = subprocess.run(args, cwd=workspace, capture_output=True, text=True, timeout=300)
        assert completed.returncode == 0, completed.stdout + completed.stderr

    print("SARIF fixture: extracting independent Java source", flush=True)
    command(
        [
            str(codeql),
            "database",
            "create",
            str(database),
            "--language=java",
            "--threads=1",
            "--ram=2048",
            "--source-root=" + str(workspace),
            "--command="
            + shlex.join(
                [str(javac), "-encoding", "UTF-8", "-d", str(tmp_path / "classes"), "App.java"]
            ),
        ]
    )
    query = ROOT / (
        ".cache/toolchains/codeql-2.26.2/qlpacks/codeql/java-queries/1.11.7/"
        "Security/CWE/CWE-078/ExecTainted.ql"
    )
    raw = extraction / "static.sarif"
    print(
        "SARIF fixture: analyzing official command injection query (environment threat model)",
        flush=True,
    )
    command(
        [
            str(codeql),
            "database",
            "analyze",
            str(database),
            str(query),
            "--threat-model=environment",
            "--format=sarif-latest",
            "--output=" + str(raw),
            "--threads=1",
            "--ram=2048",
        ]
    )
    alerts = attach_endpoint_specs(normalize_sarif(raw, case["case_id"], "static_alerts"), raw)
    assert len(alerts) == 1
    files = {"App.java": sha256_file(workspace / "App.java")}
    scoped, boundary = scope_static_signals(alerts, workspace, files)
    assert boundary["excluded_locations"] == 0
    graph = {
        "case_id": case["case_id"],
        "snapshot_id": "snapshot",
        "nodes": [],
        "edges": [],
        "graph_hash": "empty",
    }
    candidates = generate(graph, scoped)
    assert len(candidates) == 1 and candidates[0]["source_node_id"] is None
    base = extraction.parent
    atomic_json(base / "build_graph/graph.json", graph)
    atomic_jsonl(base / "candidate_rank/candidates_ranked.jsonl", candidates)
    frozen_ctx = Context(ROOT, run_dir, extraction, case, {}, {})
    identity = freeze_database(frozen_ctx, "snapshot")
    ctx = Context(
        ROOT,
        run_dir,
        base / "targeted_verify",
        case,
        {
            "selected_variant": {"targeted_verification": True},
            "codeql": {
                "research_binary": str(codeql),
                "per_query_timeout_s": 300,
                "ram_mb": 2048,
                "threads": 1,
            },
            "research": {"max_verification_queries_per_case": 4},
        },
        {
            "static_extract": {
                "result": {**identity, "analyzed_snapshot_id": "snapshot", "analyzed_files": files}
            }
        },
    )
    ctx.stage_dir.mkdir()
    print("SARIF fixture: binding both exact endpoints and querying modeled flow", flush=True)
    result = targeted_verify(ctx)
    record = read_jsonl(ctx.stage_dir / "verification.jsonl")[0]
    assert record["source_count"] == 1 and record["sink_count"] == 1, record
    assert record["status"] == "FLOW_FOUND", record
    assert result["query_invocations"] == 2 and record["is_safety_verdict"] is False
    # An exact but non-AST interior span must yield zero bindings, never nearest-node flow.
    altered = json.loads(raw.read_text())
    for thread in altered["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"]:
        thread["locations"][0]["location"]["physicalLocation"]["region"]["startColumn"] += 1
    atomic_json(raw, altered)
    alerts = attach_endpoint_specs(normalize_sarif(raw, case["case_id"], "static_alerts"), raw)
    scoped, _ = scope_static_signals(alerts, workspace, files)
    atomic_jsonl(base / "candidate_rank/candidates_ranked.jsonl", generate(graph, scoped))
    zero_ctx = Context(ROOT, run_dir, base / "targeted_verify_zero", case, ctx.config, ctx.results)
    zero_ctx.stage_dir.mkdir()
    print("SARIF fixture: rejecting zero exact endpoint bindings", flush=True)
    result = targeted_verify(zero_ctx)
    record = read_jsonl(zero_ctx.stage_dir / "verification.jsonl")[0]
    assert record["source_count"] == 0 and record["status"] == "UNSUPPORTED_SPEC", record
    assert result["query_invocations"] == 1 and record["decision"] == "REVIEW"
