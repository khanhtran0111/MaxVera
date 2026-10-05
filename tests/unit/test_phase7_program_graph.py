from __future__ import annotations

import csv
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from src.graphs.program.build_databases import (
    _build_command,
    _build_environment,
    _compatible_attempts,
    _output_path,
    _preferred_attempt,
    _seed_node_coverage,
)
from src.graphs.program.model import EDGE_KINDS, graph_digest, node_id, normalize_graph
from src.graphs.program.prepare import prepare_databases
from src.graphs.program.query import query_graph, select_seed
from src.graphs.program.runner import (
    _assert_database_cache_unlocked,
    _parser,
    _run_command,
    _validate_extracted_graph,
)
from src.graphs.program.validate import validate_project_graph
from src.reproduction.common import atomic_json, atomic_jsonl

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_phase7_builder_targets_seed_modules_and_compiles_tests(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "module-a").mkdir(parents=True)
    (source / "module-a/pom.xml").write_text("<project />\n", encoding="utf-8")
    maven = _build_command(
        ["mvn", "clean", "package", "-B"],
        {"jdk": "17", "maven": "3.9.8"},
        source,
        ["module-a/src/test/java/ExampleTest.java"],
    )
    assert maven[:5] == ["mvn", "-pl", "module-a", "-am", "test-compile"]
    assert "package" not in maven

    (source / "module-b").mkdir()
    (source / "module-b/build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
    gradle = _build_command(
        ["gradle", "--no-daemon", "build", "-x", "test"],
        {"jdk": "17", "gradle": "8.9"},
        source,
        ["module-b/src/main/java/Main.java", "module-b/src/test/java/Test.java"],
    )
    assert gradle == [
        "gradle",
        "--no-daemon",
        ":module-b:classes",
        ":module-b:testClasses",
    ]
    (source / "spring-web").mkdir()
    (source / "spring-web/spring-web.gradle").write_text("apply plugin: 'java'\n")
    spring = _build_command(
        ["./gradlew", "--no-daemon", "clean"],
        {"jdk": "17", "gradlew": True},
        source,
        ["spring-web/src/main/java/Request.java"],
    )
    assert spring == ["./gradlew", "--no-daemon", ":spring-web:classes"]


def test_phase7_builder_uses_declared_build_system_and_java_on_path(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins {}\n", encoding="utf-8")
    row = {
        "jdk_version": "17",
        "maven_version": "n/a",
        "gradle_version": "n/a",
        "use_gradlew": "1",
    }
    assert _preferred_attempt(row) == {"jdk": "17", "gradlew": True}
    attempts = _compatible_attempts(
        row,
        {"build_attempts": [{"jdk": "8u202", "maven": "3.5.0"}]},
        tmp_path,
    )
    assert attempts == [{"jdk": "17", "gradlew": True}]
    environment = _build_environment({"JAVA_HOME": "/jdk/17", "PATH": "/tools"}, {"jdk": "17"})
    assert environment["PATH"].startswith("/jdk/17/bin:")
    assert "-XX:-UseContainerSupport" in environment["JAVA_TOOL_OPTIONS"]
    assert _output_path(tmp_path, Path("pilots/db"), tmp_path / "default") == (
        tmp_path / "pilots/db"
    )


def test_phase7_builder_checks_nodes_in_seed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["bqrs", "decode"]:
            output = next(
                value.split("=", 1)[1] for value in command if value.startswith("--output=")
            )
            Path(output).write_text(
                '"TYPE","Class","src/Example.java",1,1,1,7,"Example","Example"\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("src.graphs.program.build_databases._run_command", fake_run)
    matched, reason = _seed_node_coverage(
        tmp_path / "codeql",
        tmp_path / "database",
        tmp_path / "nodes.ql",
        ["src/Example.java", "src/Other.java"],
        30,
    )
    assert matched == 1
    assert reason == "1/2 seed files have CodeQL nodes"
    assert _parser().parse_args(
        ["--run-id", "pilot_001", "--database-root", "pilots/db"]
    ).database_root == Path("pilots/db")


def _node_row(prefix: str, *, file: str, line: int, subkind: str) -> dict[str, str]:
    return {
        f"{prefix}kind": "EXPR",
        f"{prefix}subkind": subkind,
        f"{prefix}file": file,
        f"{prefix}start_line": str(line),
        f"{prefix}start_column": "1",
        f"{prefix}end_line": str(line),
        f"{prefix}end_column": "8",
        f"{prefix}symbol": "value",
        f"{prefix}type_name": "String",
    }


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_phase7_normalization_is_deterministic_and_closes_edge_endpoints() -> None:
    first = _node_row("node_", file="src/Example.java", line=2, subkind="VarRead")
    edge = {
        "edge_kind": "DATA_FLOW",
        **_node_row("source_", file="src/Example.java", line=2, subkind="VarRead"),
        **_node_row("target_", file="src/Example.java", line=3, subkind="MethodCall"),
    }
    provenance = {"tool": "CodeQL", "query_sha256": "abc"}
    nodes, edges = normalize_graph(
        "proj_test",
        [first],
        [edge],
        node_provenance=provenance,
        edge_provenance=provenance,
    )
    repeated_nodes, repeated_edges = normalize_graph(
        "proj_test",
        list(reversed([first])),
        list(reversed([edge])),
        node_provenance=provenance,
        edge_provenance=provenance,
    )
    assert len(nodes) == 2
    assert len(edges) == 1
    assert {edges[0]["source_id"], edges[0]["target_id"]} <= {node["node_id"] for node in nodes}
    assert (nodes, edges) == (repeated_nodes, repeated_edges)
    assert graph_digest(nodes, edges) == graph_digest(repeated_nodes, repeated_edges)


def test_phase7_neighborhood_and_slice_directions_are_bounded() -> None:
    provenance = {"tool": "CodeQL", "query_sha256": "abc"}
    node_rows = [
        _node_row("node_", file="src/Example.java", line=line, subkind=f"Expr{line}")
        for line in (2, 3, 4)
    ]
    edge_rows = []
    for source_line, target_line in ((2, 3), (3, 4)):
        edge_rows.append(
            {
                "edge_kind": "DATA_FLOW",
                **_node_row(
                    "source_",
                    file="src/Example.java",
                    line=source_line,
                    subkind=f"Expr{source_line}",
                ),
                **_node_row(
                    "target_",
                    file="src/Example.java",
                    line=target_line,
                    subkind=f"Expr{target_line}",
                ),
            }
        )
    nodes, edges = normalize_graph(
        "proj_test",
        node_rows,
        edge_rows,
        node_provenance=provenance,
        edge_provenance=provenance,
    )
    seed = select_seed(nodes, node_id=None, file="src/Example.java", line=2)
    one_hop = query_graph(
        nodes,
        edges,
        seed_id=seed,
        hops=1,
        direction="out",
        edge_kinds={"DATA_FLOW"},
    )
    two_hops = query_graph(
        nodes,
        edges,
        seed_id=seed,
        hops=2,
        direction="out",
        edge_kinds={"DATA_FLOW"},
    )
    assert one_hop["node_count"] == 2
    assert one_hop["edge_count"] == 1
    assert two_hops["node_count"] == 3
    assert two_hops["edge_count"] == 2
    assert set(two_hops["edge_kinds"]) <= EDGE_KINDS


def test_phase7_database_preparation_is_development_only_and_opaque(tmp_path: Path) -> None:
    source_manifest = tmp_path / "source.csv"
    target_manifest = tmp_path / "target.csv"
    development = tmp_path / "development.csv"
    phase2_status = tmp_path / "status.jsonl"
    source_root = tmp_path / "source_dbs"
    target_root = tmp_path / "target_dbs"
    preparation_manifest = tmp_path / "preparation.json"
    _write_csv(
        source_manifest,
        [
            {
                "project_id": "proj_source",
                "project_slug": "owner__repository_release",
                "buggy_commit_id": "abc123",
            }
        ],
    )
    _write_csv(
        target_manifest,
        [
            {
                "project_id": "proj_development",
                "project_slug": "owner__repository_release",
                "buggy_commit_id": "abc123",
            },
            {
                "project_id": "proj_locked",
                "project_slug": "owner__repository_release",
                "buggy_commit_id": "abc123",
            },
        ],
    )
    _write_csv(development, [{"project_id": "proj_development", "split": "development"}])
    phase2_status.write_text(
        json.dumps({"project_id": "proj_source", "status": "SUCCESS"}) + "\n",
        encoding="utf-8",
    )
    database = source_root / "proj_source"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("primaryLanguage: java\n", encoding="utf-8")
    result = prepare_databases(
        tmp_path,
        source_manifest=source_manifest,
        target_manifest=target_manifest,
        development_split=development,
        source_database_root=source_root,
        target_database_root=target_root,
        phase2_status_path=phase2_status,
        preparation_manifest=preparation_manifest,
    )
    assert result["selected_projects"] == 1
    assert result["available_databases"] == 1
    assert (target_root / "proj_development").is_symlink()
    assert not (target_root / "proj_locked").exists()
    persisted = preparation_manifest.read_text(encoding="utf-8")
    assert "proj_source" not in persisted
    assert "owner__repository_release" not in persisted


def test_phase7_protocol_and_locked_phase6_dependency_are_explicit() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase7_program_graph.yaml").read_text(encoding="utf-8")
    )
    assert config["protocol_version"] == "1.4.0"
    assert config["phase6_lock"]["run_id"] == "p6_static_v2_dev_full_001"
    assert config["phase6_lock"]["top_k"] == 10
    assert config["extractor"]["scope"] == "phase6_hypothesis_files_plus_one_edge_endpoint"
    assert set(config["extractor"]["edge_kinds"]) == EDGE_KINDS
    assert config["selection_lock"]["canonical_run_id"] == "p7_pg_dev_full_004"
    assert config["selection_lock"]["analysis_successes"] == 81
    assert config["selection_lock"]["analysis_failures"] == 15
    assert config["selection_lock"]["edge_reference_ratio"] == 1.0


def test_phase7_empty_graph_is_an_analysis_failure() -> None:
    with pytest.raises(ValueError, match="graph has no nodes"):
        _validate_extracted_graph([], [], max_nodes=10, max_edges=10)


def test_phase7_command_timeout_terminates_process_group(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    program = (
        "import os, pathlib, signal, subprocess, sys, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "child=subprocess.Popen([sys.executable, '-c', "
        "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        "time.sleep(60)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        _run_command(
            [os.fspath(Path(os.sys.executable)), "-c", program, os.fspath(child_pid_path)],
            timeout=1,
        )
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    # SIGKILL can finish before init has reaped the orphaned child's PID.
    deadline = time.monotonic() + 2
    while True:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            pytest.fail("timed-out command left a surviving child process")
        time.sleep(0.01)


def test_phase7_database_cache_lock_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "db-java/default/cache/.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.touch()

    def reject_lock(*_args: object) -> None:
        raise BlockingIOError

    monkeypatch.setattr("src.graphs.program.runner.fcntl.lockf", reject_lock)
    with pytest.raises(RuntimeError, match="database cache is locked"):
        _assert_database_cache_unlocked(tmp_path)


def test_phase7_project_graph_rejects_crossed_location_range(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = source_root / "src/Example.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Example {}\n", encoding="utf-8")
    descriptor = {
        "kind": "CALLABLE",
        "subkind": "Method",
        "file": "src/Example.java",
        "start_line": 2,
        "start_column": 1,
        "end_line": 1,
        "end_column": 16,
        "symbol": "example",
        "type_name": "void",
    }
    project_id = "proj_test"
    node = {
        "schema_version": 1,
        "project_id": project_id,
        "node_id": node_id(project_id, descriptor),
        "kind": descriptor["kind"],
        "subkind": descriptor["subkind"],
        "symbol": descriptor["symbol"],
        "type_name": descriptor["type_name"],
        "location": {
            key: descriptor[key]
            for key in ("file", "start_line", "start_column", "end_line", "end_column")
        },
        "provenance": {"tool": "CodeQL"},
    }
    project_root = tmp_path / "graph"
    project_root.mkdir()
    atomic_jsonl(project_root / "nodes.jsonl", [node])
    atomic_jsonl(project_root / "edges.jsonl", [])
    atomic_json(
        project_root / "graph_summary.json",
        {
            "nodes": 1,
            "edges": 0,
            "edge_references_resolved": 0,
            "edge_reference_ratio": 1.0,
            "edge_kinds": {},
            "graph_sha256": graph_digest([node], []),
        },
    )
    with pytest.raises(ValueError, match="line range is invalid"):
        validate_project_graph(project_root, project_id, source_root)


def test_phase7_queries_bind_one_location_per_node_descriptor() -> None:
    node_query = (REPO_ROOT / "src/static_analysis/queries/phase7_nodes.ql").read_text(
        encoding="utf-8"
    )
    edge_query = (REPO_ROOT / "src/static_analysis/queries/phase7_edges.ql").read_text(
        encoding="utf-8"
    )
    assert "nodeLocation = node.getLocation()" in node_query
    assert "nodeLocation.getFile().getRelativePath()" in node_query
    assert node_query.count("node.getLocation()") == 1
    assert "sourceLocation = source.getLocation()" in edge_query
    assert "targetLocation = target.getLocation()" in edge_query
    assert edge_query.count("source.getLocation()") == 1
    assert edge_query.count("target.getLocation()") == 1
