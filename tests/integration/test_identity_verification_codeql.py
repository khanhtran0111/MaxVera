"""Opt-in decoded CodeQL proof for a directly consumed source expression."""

from __future__ import annotations

import csv
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("MAXVERA_RUN_CODEQL_FIXTURE") != "1",
    reason="opt-in local identity CodeQL fixture; no benchmark/API runs",
)
def test_direct_source_sink_identity_verifies_with_decoded_codeql_flow(tmp_path):
    from maxvera.candidates import generate
    from maxvera.graph import normalize_graph
    from maxvera.research_verification import classify_verification, render_queries

    codeql = ROOT / ".cache/toolchains/codeql-2.26.2/codeql"
    javac = ROOT / ".cache/toolchains/cwe_bench_java/jdk-17/bin/javac"
    source = tmp_path / "source"
    source.mkdir()
    classes = source / "classes"
    classes.mkdir()
    (source / "App.java").write_text(
        'class App {\n  void run() throws Exception {\n'
        '    Runtime.getRuntime().exec(System.getenv("COMMAND"));\n  }\n}\n'
    )
    database = tmp_path / "database"
    pack = tmp_path / "queries"
    pack.mkdir()
    (pack / "qlpack.yml").write_text(
        "name: maxvera/identity-fixture\nversion: 1.0.0\ndependencies:\n"
        "  codeql/java-all: 9.2.2\n"
    )
    original_pack = ROOT / "src/static_analysis/queries/v2"
    for name in ("Grounding.qll", "ProgramCore.qll", "program_nodes.ql"):
        shutil.copyfile(original_pack / name, pack / name)

    def run(args):
        result = subprocess.run(args, cwd=source, capture_output=True, text=True, timeout=240)
        assert result.returncode == 0, result.stdout + result.stderr

    print("identity fixture: extracting one Java file", flush=True)
    run(
        [
            str(codeql),
            "database",
            "create",
            str(database),
            "--language=java",
            "--threads=1",
            "--ram=2048",
            "--source-root=" + str(source),
            "--command=" + shlex.join([str(javac), "-d", str(classes), "App.java"]),
        ]
    )

    def query_rows(name):
        print("identity fixture: running " + name, flush=True)
        bqrs = tmp_path / (name + ".bqrs")
        decoded = tmp_path / (name + ".csv")
        run(
            [
                str(codeql),
                "query",
                "run",
                str(pack / (name + ".ql")),
                "--database=" + str(database),
                "--output=" + str(bqrs),
                "--threads=1",
                "--ram=2048",
                "--compilation-cache=" + str(tmp_path / "compiled"),
                "--no-default-compilation-cache",
            ]
        )
        run([str(codeql), "bqrs", "decode", str(bqrs), "--format=csv", "--output=" + str(decoded)])
        with decoded.open(newline="") as handle:
            return list(csv.DictReader(handle))

    graph = normalize_graph(
        "opaque-identity", "fixture-snapshot", query_rows("program_nodes"), [], "fixture-query"
    )
    identities = [
        c
        for c in generate(graph, [], max_hops=0)
        if c["source_node_id"] is not None and c["source_node_id"] == c["sink_node_id"]
    ]
    assert len(identities) == 1
    candidate = identities[0]
    assert candidate["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
    assert candidate["graph_path_edge_ids"] == []
    endpoint = next(n for n in graph["nodes"] if n["node_id"] == candidate["source_node_id"])
    assert endpoint["roles"] == ["sink", "source"]
    assert (endpoint["file"], endpoint["start_line"], endpoint["start_column"]) == (
        "App.java",
        3,
        31,
    )
    endpoint_query, flow_query = render_queries(candidate["candidate_id"], endpoint, endpoint)
    (pack / "endpoints.ql").write_text(endpoint_query)
    (pack / "flow.ql").write_text(flow_query)

    inventory = query_rows("endpoints")
    assert inventory == [{"source_count": "1", "sink_count": "1"}]
    flows = query_rows("flow")
    assert flows == [
        {"source_file": "App.java", "source_line": "3", "sink_file": "App.java", "sink_line": "3"}
    ]
    assert classify_verification(1, 1, len(flows)) == "FLOW_FOUND"
    print(
        json.dumps(
            {"source_count": 1, "sink_count": 1, "flow_rows": len(flows), "status": "FLOW_FOUND"}
        ),
        flush=True,
    )
