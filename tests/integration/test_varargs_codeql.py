"""Opt-in real extraction regression, using only a tiny independent Java fixture."""

from __future__ import annotations

import csv
import os
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("MAXVERA_RUN_CODEQL_FIXTURE") != "1", reason="opt-in tiny local CodeQL fixture"
)
def test_expanded_varargs_link_every_argument_to_the_declared_parameter(tmp_path):
    from maxvera.candidates import generate
    from maxvera.graph import normalize_graph

    source = tmp_path / "source"
    source.mkdir()
    (source / "Varargs.java").write_text("""class Varargs {
  static void variable(String... args) throws Exception { Runtime.getRuntime().exec(args[1]); }
  static void ordinary(String a, String b) throws Exception { Runtime.getRuntime().exec(b); }
  void expanded() throws Exception { variable("fixed", System.getenv("INPUT")); }
  void control() throws Exception { ordinary("fixed", System.getenv("INPUT")); }
  void explicitArray() throws Exception { variable(new String[]{"fixed", System.getenv("INPUT")}); }
}
""")
    codeql = ROOT / ".cache/toolchains/codeql-2.26.2/codeql"
    javac = ROOT / ".cache/toolchains/cwe_bench_java/jdk-17/bin/javac"

    def run(args):
        result = subprocess.run(args, cwd=source, capture_output=True, text=True, timeout=240)
        assert result.returncode == 0, result.stdout + result.stderr

    database = tmp_path / "database"
    run(
        [
            str(codeql),
            "database",
            "create",
            str(database),
            "--language=java",
            "--threads=1",
            "--ram=2500",
            f"--source-root={source}",
            "--command="
            + shlex.join([str(javac), "-d", str(source / "classes"), str(source / "Varargs.java")]),
        ]
    )
    rows = {}
    for name in ("program_nodes", "program_edges"):
        bqrs, csv_path = tmp_path / f"{name}.bqrs", tmp_path / f"{name}.csv"
        run(
            [
                str(codeql),
                "query",
                "run",
                str(ROOT / f"src/static_analysis/queries/v2/{name}.ql"),
                f"--database={database}",
                f"--output={bqrs}",
                "--ram=2500",
                "--threads=1",
            ]
        )
        run([str(codeql), "bqrs", "decode", str(bqrs), "--format=csv", f"--output={csv_path}"])
        with csv_path.open(newline="") as handle:
            rows[name] = list(csv.DictReader(handle))
    graph = normalize_graph(
        "opaque-varargs", "snapshot", rows["program_nodes"], rows["program_edges"], "query"
    )
    by_id = {node["node_id"]: node for node in graph["nodes"]}
    complete_sources = {
        by_id[c["source_node_id"]]["start_line"]
        for c in generate(graph, [], max_hops=10)
        if c["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
    }
    assert {4, 5, 6} <= complete_sources
