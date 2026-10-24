"""Virtual archive sources have an explicit scope without hiding missing project code."""

from __future__ import annotations

import csv
import json
import zipfile

import pytest

from maxvera.contracts import digest
from maxvera.orchestration import Context
from maxvera.research import build_graph
from src.common.provenance import sha256_file


def fixture_context(tmp_path, *, dependency_file="lib/dependency.jar/org/Dependency.java"):
    case = "opaque-sources"
    base = tmp_path / "run/stages" / case
    extraction = base / "static_extract"
    workspace = extraction / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "App.java").write_text("class App {}\n")
    (workspace / "Sink.java").write_text("class Sink {}\n")
    (workspace / "lib").mkdir()
    with zipfile.ZipFile(workspace / "lib/dependency.jar", "w") as archive:
        archive.writestr("org/Dependency.class", b"fixture bytecode")
    (tmp_path / "src/static_analysis/queries/v2").mkdir(parents=True)
    stage = base / "build_graph"
    stage.mkdir()
    rows = []
    for key, file, role in [
        ("app", "App.java", "source"),
        ("sink", "Sink.java", "sink"),
        ("dependency", dependency_file, "source"),
        ("dependency", dependency_file, "sink"),
    ]:
        rows.append(
            {
                "key": key,
                "file": file,
                "start_line": "1",
                "start_column": "1",
                "end_line": "1",
                "end_column": "10",
                "kind": "MethodCall",
                "symbol": "Fixture#run()",
                "role": role,
                "expression": key,
            }
        )
    edges = [
        {"source": "app", "target": "sink", "kind": "MAY_FLOW"},
        {"source": "app", "target": "dependency", "kind": "MAY_FLOW"},
        {"source": "dependency", "target": "sink", "kind": "MAY_FLOW"},
    ]
    for name, records in [("program_nodes.csv", rows), ("program_edges.csv", edges)]:
        with (extraction / name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=records[0])
            writer.writeheader()
            writer.writerows(records)
    analyzed = {name: sha256_file(workspace / name) for name in ("App.java", "Sink.java")}
    return Context(
        tmp_path,
        tmp_path / "run",
        stage,
        {"case_id": case},
        {"research": {"max_nodes": 100, "max_edges": 100}},
        {
            "static_extract": {
                "result": {
                    "graph_enabled": True,
                    "analyzed_snapshot_id": "snapshot",
                    "analyzed_files": analyzed,
                },
                "seconds": 1,
            }
        },
    )


def test_virtual_archive_nodes_and_incident_edges_have_explicit_scope_provenance(tmp_path):
    ctx = fixture_context(tmp_path)
    result = build_graph(ctx)
    graph = json.loads((ctx.stage_dir / "graph.json").read_text())
    quality = graph["quality"]
    scope = quality["source_boundary"]

    assert {node["file"] for node in graph["nodes"]} == {"App.java", "Sink.java"}
    assert all(node["content_hash"] for node in graph["nodes"])
    assert len(graph["edges"]) == 1
    assert quality["nodes_by_kind"] == {"MethodCall": 2}
    assert quality["edges_by_kind"] == {"MAY_FLOW": 1}
    assert quality["orphan_nodes"] == 0
    assert quality["cross_file_edges"] == 1
    assert quality["provenance_coverage"] == 1.0
    assert scope["excluded_node_rows"] == 2
    assert scope["excluded_nodes"] == 1
    assert scope["excluded_files"] == 1
    assert scope["excluded_edges"] == 2
    assert scope["excluded_edge_rows"] == 2
    assert scope["archives"] == [
        {
            "file": "lib/dependency.jar",
            "sha256": sha256_file(
                ctx.stage_dir.parent / "static_extract/workspace/lib/dependency.jar"
            ),
            "excluded_source_files": ["lib/dependency.jar/org/Dependency.java"],
        }
    ]
    assert graph["graph_hash"] == digest([graph["nodes"], graph["edges"]])
    assert result["source_boundary"] == scope


@pytest.mark.parametrize(
    "missing",
    ["Missing.java", "lib/missing.jar/org/Missing.java", "lib/dependency.jar/Missing.txt"],
)
def test_arbitrary_missing_sources_still_fail(tmp_path, missing):
    with pytest.raises(ValueError, match=r"backed|snapshot"):
        build_graph(fixture_context(tmp_path, dependency_file=missing))


def test_archive_shaped_file_must_really_be_an_archive(tmp_path):
    ctx = fixture_context(tmp_path)
    (ctx.stage_dir.parent / "static_extract/workspace/lib/dependency.jar").write_text("not a jar")
    with pytest.raises(ValueError, match=r"archive|backed|snapshot"):
        build_graph(ctx)


def test_archive_symlink_does_not_bypass_source_boundary(tmp_path):
    ctx = fixture_context(tmp_path)
    archive = ctx.stage_dir.parent / "static_extract/workspace/lib/dependency.jar"
    outside = tmp_path / "outside.jar"
    archive.replace(outside)
    archive.symlink_to(outside)
    with pytest.raises(ValueError, match=r"symlink|unsafe|backed|snapshot"):
        build_graph(ctx)


def test_excluded_archive_cannot_hide_an_unexpected_dangling_endpoint(tmp_path):
    ctx = fixture_context(tmp_path)
    edge_file = ctx.stage_dir.parent / "static_extract/program_edges.csv"
    with edge_file.open("a") as handle:
        handle.write("dependency,unexpected,MAY_FLOW\n")
    with pytest.raises(ValueError, match="dangling"):
        build_graph(ctx)


def test_virtual_archive_path_still_rejects_oracle_identifiers(tmp_path):
    ctx = fixture_context(tmp_path, dependency_file="lib/CVE-2026-1234.jar/org/Dependency.java")
    with pytest.raises(ValueError, match="oracle"):
        build_graph(ctx)
