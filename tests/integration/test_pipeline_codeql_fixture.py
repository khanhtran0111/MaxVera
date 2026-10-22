"""Opt-in tiny Java extraction; never contacts a model or uses benchmark cases."""

from __future__ import annotations

import csv
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("MAXVERA_RUN_CODEQL_FIXTURE") != "1",
    reason="opt-in local CodeQL fixture; no benchmark/API runs",
)
def test_real_codeql_extracts_cross_file_candidates(tmp_path):
    from maxvera.candidates import generate, rank
    from maxvera.graph import normalize_graph

    codeql = ROOT / ".cache/toolchains/codeql-2.26.2/codeql"
    javac = ROOT / ".cache/toolchains/cwe_bench_java/jdk-17/bin/javac"
    source = tmp_path / "opaque-source"
    shutil.copytree(ROOT / "tests/fixtures/java_pipeline", source)
    database = tmp_path / "database"
    compile_args = [
        str(javac),
        "-d",
        str(source / "classes"),
        *[str(p) for p in source.glob("*.java")],
    ]

    def run(args):
        result = subprocess.run(args, cwd=source, capture_output=True, text=True, timeout=240)
        assert result.returncode == 0, result.stdout + result.stderr

    run(
        [
            str(codeql),
            "database",
            "create",
            str(database),
            "--language=java",
            "--threads=1",
            "--ram=2500",
            "--source-root=" + str(source),
            "--command=" + shlex.join(compile_args),
        ]
    )
    rows = {}
    for name in ("program_nodes", "program_edges"):
        bqrs, csv_path = tmp_path / (name + ".bqrs"), tmp_path / (name + ".csv")
        run(
            [
                str(codeql),
                "query",
                "run",
                str(ROOT / "src/static_analysis/queries/v2" / (name + ".ql")),
                "--database=" + str(database),
                "--output=" + str(bqrs),
                "--ram=2500",
                "--threads=1",
            ]
        )
        run([str(codeql), "bqrs", "decode", str(bqrs), "--format=csv", "--output=" + str(csv_path)])
        with csv_path.open(newline="") as handle:
            rows[name] = list(csv.DictReader(handle))
    graph = normalize_graph(
        "opaque-fixture",
        "fixture-snapshot",
        rows["program_nodes"],
        rows["program_edges"],
        "fixture-query",
    )
    candidates = rank(generate(graph, [], max_hops=10), top_k=20)
    paths = [c for c in candidates if c["discovery_status"] == "COMPLETE_CANDIDATE_PATH"]
    assert paths, graph["quality"]
    assert any(
        {"Controller.java", "Service.java", "Repository.java"}
        <= {loc["file"] for loc in c["locations"]}
        for c in paths
    )
    assert graph["quality"]["cross_file_edges"] >= 2
    assert all(c["verification_status"] == "NOT_ATTEMPTED" for c in candidates)
    # Distinct overload signatures cannot collapse into the same endpoint identity.
    signatures = {n["symbol"] for n in graph["nodes"] if n["file"] == "Service.java"}
    assert any("java.lang.String" in s or "String" in s for s in signatures)


@pytest.mark.skipif(
    os.environ.get("MAXVERA_RUN_CODEQL_FIXTURE") != "1",
    reason="opt-in local sandboxed CLI fixture; no benchmark/API runs",
)
def test_real_research_cli_preserves_snapshot_in_filesystem_sandbox(tmp_path):
    import json
    import sys

    import yaml

    from maxvera.sandbox import landlock_available

    if not landlock_available():
        pytest.skip("Landlock unavailable")
    root = tmp_path / "workspace"
    source = root / "data/processed/analysis_input/projects/opaque-1"
    source.parent.mkdir(parents=True)
    shutil.copytree(ROOT / "tests/fixtures/java_pipeline", source)
    original = (source / "Controller.java").read_bytes()
    tools = ROOT / ".cache/toolchains"
    (root / ".cache").mkdir()
    (root / ".cache/toolchains").symlink_to(tools, target_is_directory=True)
    query_root = root / "src/static_analysis/queries"
    query_root.mkdir(parents=True)
    shutil.copytree(
        ROOT / "src/static_analysis/queries/v2",
        query_root / "v2",
        ignore=shutil.ignore_patterns(".cache", ".codeql", "*.qlx", "__pycache__"),
    )
    (query_root / "qlpack.yml").write_text(
        "name: fixture/empty-alerts\nversion: 0.0.1\ndependencies:\n  codeql/java-all: 9.2.2\n"
    )
    (query_root / "empty_alerts.ql").write_text("""/**
 * @name Empty default-alert fixture
 * @kind problem
 * @problem.severity warning
 * @id java/fixture/empty-alerts
 */
import java
from MethodCall call
where 1 = 2
select call, "Fixture only"
""")
    java_home = tools / "cwe_bench_java/jdk-17"
    (source / "build.runtime.json").write_text(
        json.dumps(
            {
                "attempts": [
                    {
                        "command": [
                            str(java_home / "bin/javac"),
                            "-d",
                            "classes",
                            "Controller.java",
                            "Service.java",
                            "Repository.java",
                            "LanguageEdges.java",
                        ],
                        "environment": {"JAVA_HOME": str(java_home)},
                    }
                ]
            }
        )
    )
    (source.parent.parent / "cases.csv").write_text(
        "project_id,source_dir\nopaque-1,projects/opaque-1\n"
    )
    protected = root / "data/processed/evaluator_only"
    protected.mkdir()
    (protected / "labels").write_text("POISON_STAYS_UNREAD_AND_UNCHANGED")
    config = root / "research.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "pipeline": "research",
                "dataset": {
                    "analysis_manifest": "data/processed/analysis_input/cases.csv",
                    "expected_cases": 1,
                },
                "codeql": {
                    "research_binary": str(tools / "codeql-2.26.2/codeql"),
                    "generic_suite": "src/static_analysis/queries/empty_alerts.ql",
                    "per_query_timeout_s": 240,
                    "threads": 1,
                    "ram_mb": 2500,
                },
                "research": {"max_nodes": 10000, "max_edges": 10000},
                "evidence": {"top_k": [5, 10, 20], "max_graph_hops": 10},
            }
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "maxvera",
            "--root",
            str(root),
            "pipeline",
            "research",
            "--config",
            str(config),
            "--mode",
            "smoke",
            "--limit",
            "1",
            "--run-id",
            "sandbox_fixture",
            "--execute",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    run = root / "results/_smoke/research/sandbox_fixture"
    errors = (run / "errors.jsonl").read_text() if (run / "errors.jsonl").exists() else ""
    logs = "\n".join(p.read_text()[-3000:] for p in run.rglob("*.log"))
    assert result.returncode == 0, result.stdout + result.stderr + errors + logs
    candidates = [
        json.loads(line) for line in (run / "candidates_pre_llm.jsonl").read_text().splitlines()
    ]
    assert any(c["discovery_status"] == "COMPLETE_CANDIDATE_PATH" for c in candidates)
    assert (source / "Controller.java").read_bytes() == original
    assert not (source / "classes").exists()
    assert (protected / "labels").read_text() == "POISON_STAYS_UNREAD_AND_UNCHANGED"
    assert not (run / "llm_calls.jsonl").read_text().strip()
