"""Discovery readiness regressions use only synthetic source/graph fixtures."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from maxvera.candidates import generate, rank
from maxvera.contracts import digest
from maxvera.graph import normalize_graph
from maxvera.snapshots import source_inventory


def graph_rows(count=40):
    nodes = [
        {
            "key": f"{role}{i}",
            "file": f"F{i}.java",
            "start_line": str(1 if role == "source" else 2),
            "start_column": "1",
            "end_line": str(1 if role == "source" else 2),
            "end_column": "2",
            "kind": "Expr",
            "symbol": f"m{i}",
            "role": role,
        }
        for i in range(count)
        for role in ("source", "sink")
    ]
    edges = [
        {"source": f"source{i}", "target": f"sink{i}", "kind": "MAY_FLOW"} for i in range(count)
    ]
    return nodes, edges


def test_semantic_inventory_excludes_runtime_cache_but_binds_generated_java(tmp_path):
    from maxvera.snapshots import semantic_inventory

    (tmp_path / "App.java").write_text("class App {}")
    (tmp_path / "pom.xml").write_text("<project/>")
    (tmp_path / "build.runtime.json").write_text('{"home":"/old/path"}')
    (tmp_path / "snapshot.files.json").write_text("preparation provenance")
    baseline = source_inventory(tmp_path)
    (tmp_path / "target/generated-sources").mkdir(parents=True)
    generated = tmp_path / "target/generated-sources/Generated.java"
    generated.write_text("class Generated {}")
    (tmp_path / "target/pom.properties").write_text("#timestamp one")
    (tmp_path / ".maven-runtime").mkdir()
    (tmp_path / ".maven-runtime/Dependency.java").write_text("class Dependency {}")
    first = source_inventory(tmp_path, include_generated=True)
    semantic = semantic_inventory(first, baseline)
    assert set(semantic) == {"App.java", "pom.xml", "target/generated-sources/Generated.java"}
    (tmp_path / "target/pom.properties").write_text("#timestamp two")
    (tmp_path / "build.runtime.json").write_text('{"home":"/new/path"}')
    second = source_inventory(tmp_path, include_generated=True)
    assert digest(first) != digest(second)
    assert semantic_inventory(second, baseline) == semantic
    generated.write_text("class Generated { int changed; }")
    assert (
        semantic_inventory(source_inventory(tmp_path, include_generated=True), baseline) != semantic
    )


def test_semantic_rank_order_does_not_use_snapshot_salted_node_or_candidate_ids():
    nodes, edges = graph_rows()
    orders = []
    for snapshot in ("first-build", "second-build"):
        graph = normalize_graph("opaque-1", snapshot, nodes, edges, "query")
        orders.append([c["locations"] for c in rank(generate(graph, []), top_k=5)])
    assert orders[0] == orders[1]


class CountedEdges(list):
    def __init__(self, rows):
        super().__init__(rows)
        self.visits = 0

    def __iter__(self):
        for edge in super().__iter__():
            self.visits += 1
            yield edge


def test_empty_path_retention_does_not_scan_every_graph_edge_per_source():
    count = 100
    nodes = [
        {
            "node_id": f"n{i}",
            "file": "X.java",
            "start_line": i + 1,
            "end_line": i + 1,
            "roles": ["source"],
        }
        for i in range(count)
    ]
    edges = CountedEdges(
        [
            {"edge_id": f"e{i}", "src": f"n{i}", "dst": f"n{i}", "kind": "AST_PARENT"}
            for i in range(count)
        ]
    )
    graph = dict(case_id="opaque-1", snapshot_id="s", nodes=nodes, edges=edges, graph_hash="g")
    assert len(generate(graph, [])) == count
    assert edges.visits <= 2 * count


def wide_graph(count=4100):
    nodes = [
        {"node_id": key, "file": "X.java", "start_line": 1, "end_line": 1, "roles": roles}
        for key, roles in (("source", ["source"]), ("sink", ["sink"]), ("zz-bridge", []))
    ]
    nodes[2]["file"] = "ZZ.java"
    nodes += [
        {
            "node_id": f"{prefix}{i:04d}",
            "file": "X.java",
            "start_line": i + 2,
            "end_line": i + 2,
            "roles": [],
        }
        for prefix in ("a", "b")
        for i in range(count)
    ]
    edges = (
        [
            {"edge_id": f"s{i}", "src": "source", "dst": f"a{i:04d}", "kind": "MAY_FLOW"}
            for i in range(count)
        ]
        + [
            {"edge_id": f"t{i}", "src": f"b{i:04d}", "dst": "sink", "kind": "MAY_FLOW"}
            for i in range(count)
        ]
        + [
            {"edge_id": "bridge-in", "src": "source", "dst": "zz-bridge", "kind": "MAY_FLOW"},
            {"edge_id": "bridge-out", "src": "zz-bridge", "dst": "sink", "kind": "MAY_FLOW"},
        ]
    )
    return dict(case_id="opaque-1", snapshot_id="s", nodes=nodes, edges=edges, graph_hash="g")


def test_node_cap_is_reported_and_larger_explicit_budget_recovers_existing_flow():
    graph = wide_graph()
    limited = {}
    candidates = generate(graph, [], max_traversal_nodes=4096, diagnostics=limited)
    assert limited["cap_reached"] is True
    assert limited["truncated_traversals"] == 2
    assert len(limited["truncated_slices"]) == 2
    assert all(c["discovery_truncated"] for c in candidates)
    assert not any(c["discovery_status"] == "COMPLETE_CANDIDATE_PATH" for c in candidates)
    complete = {}
    candidates = generate(graph, [], max_traversal_nodes=10000, diagnostics=complete)
    assert complete["cap_reached"] is False
    assert any(c["discovery_status"] == "COMPLETE_CANDIDATE_PATH" for c in candidates)


def location(file, line=1):
    return {"file": file, "start_line": line, "end_line": line}


def test_static_scope_preserves_source_flows_and_accounts_for_external_locations(tmp_path):
    from maxvera.graph_provenance import scope_static_signals

    for name in ("Source.java", "Sink.java"):
        (tmp_path / name).write_text("class Fixture {}")
    files = source_inventory(tmp_path)
    alerts = [
        {
            "locations": [
                location("Source.java"),
                location("dep.jar/D.java"),
                location("Sink.java"),
            ],
            "path_evidence": "CODEQL_FLOW",
        },
        {
            "locations": [location("dep.jar/D.java"), location("Sink.java")],
            "path_evidence": "CODEQL_FLOW",
        },
        {"locations": [location("dep.jar/D.java")], "path_evidence": "CODEQL_FLOW"},
    ]
    scoped, report = scope_static_signals(alerts, tmp_path, files)
    assert report["input_alerts"] == 3
    assert report["retained_alerts"] == 2
    assert report["excluded_alerts"] == 1
    assert report["partial_alerts"] == 1
    assert report["excluded_locations"] == 3
    assert scoped[0]["path_evidence"] == "CODEQL_FLOW"
    assert scoped[0]["locations"] == [location("Source.java"), location("Sink.java")]
    assert scoped[1]["path_evidence"] == "LOCATION_ONLY"
    assert scoped[1]["scope_status"] == "PARTIAL_EXTERNAL_FLOW"


@pytest.mark.parametrize(
    "file", ["../secret.java", "/absolute/App.java", "a\\App.java", "CVE-2026-1234/App.java"]
)
def test_static_scope_rejects_unsafe_paths_instead_of_classifying_them_external(tmp_path, file):
    from maxvera.graph_provenance import scope_static_signals

    with pytest.raises(ValueError):
        scope_static_signals([{"locations": [location(file)]}], tmp_path, {})


@pytest.mark.parametrize("change", ["modified", "missing", "symlink"])
def test_static_scope_rejects_changed_or_symlinked_sources(tmp_path, change):
    from maxvera.graph_provenance import scope_static_signals

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "App.java"
    source.write_text("class App {}")
    files = source_inventory(workspace)
    if change == "modified":
        source.write_text("class App { int changed; }")
    elif change == "missing":
        source.unlink()
    else:
        outside = tmp_path / "Outside.java"
        outside.write_text("class Outside {}")
        source.unlink()
        source.symlink_to(outside)
        files = {}  # An unlisted symlink must fail as well.
    with pytest.raises(ValueError, match=r"integrity|symlink|escape"):
        scope_static_signals([{"locations": [location("App.java")]}], workspace, files)


def test_candidate_generation_persists_scope_and_traversal_diagnostics(tmp_path):
    from maxvera.orchestration import Context
    from maxvera.research import candidate_generate

    base = tmp_path / "run/stages/opaque-1"
    workspace = base / "static_extract/workspace"
    workspace.mkdir(parents=True)
    (workspace / "App.java").write_text("class App {}")
    alerts = [
        {"locations": [location("missing.jar/External.java")], "path_evidence": "CODEQL_FLOW"}
    ]
    (workspace.parent / "static_signals.jsonl").write_text(json.dumps(alerts[0]) + "\n")
    stage = base / "candidate_generate"
    stage.mkdir()
    ctx = Context(
        tmp_path,
        tmp_path / "run",
        stage,
        {"case_id": "opaque-1"},
        {
            "selected_variant": {"graph_enabled": False, "candidate_sources": ["static_alerts"]},
            "research": {"max_traversal_nodes": 32},
            "evidence": {"max_graph_hops": 5},
        },
        {
            "static_extract": {
                "result": {
                    "analyzed_snapshot_id": "full",
                    "semantic_snapshot_id": "semantic",
                    "analyzed_files": source_inventory(workspace),
                }
            }
        },
    )
    result = candidate_generate(ctx)
    assert result["static_signal_scope"]["excluded_alerts"] == 1
    assert result["discovery_diagnostics"]["max_traversal_nodes"] == 32
    assert result["discovery_diagnostics"]["cap_reached"] is False
    assert (stage / "candidates_raw.jsonl").read_text() == ""
    assert {
        "discovery_diagnostics.json",
        "static_signal_scope.json",
        "static_signals_scoped.jsonl",
    } <= set(result["artifacts"])


def test_two_private_builds_bind_full_bytes_but_preserve_semantic_graph_ids(tmp_path, monkeypatch):
    from maxvera.orchestration import Context
    from maxvera.research import build_graph, ingest, static_extract

    original = tmp_path / "data/processed/analysis_input/projects/opaque-1"
    original.mkdir(parents=True)
    (original / "App.java").write_text("class App {}")
    (original / "build.runtime.json").write_text(
        json.dumps(
            {
                "attempts": [{"command": ["fixture-build"], "environment": {}}],
            }
        )
    )
    binary = tmp_path / "codeql"
    binary.write_text("fake executable")
    (tmp_path / "src/static_analysis/queries/v2").mkdir(parents=True)
    records = []
    for run_name in ("first-build", "second-build"):
        base = tmp_path / run_name / "stages/opaque-1"
        stage = base / "ingest"
        stage.mkdir(parents=True)
        config = {
            "codeql": {
                "research_binary": str(binary),
                "generic_suite": "suite",
                "ram_mb": 256,
                "threads": 1,
                "per_query_timeout_s": 10,
            },
            "budgets": {"timeout_case_s": 10},
            "research": {"max_nodes": 10, "max_edges": 10},
            "selected_variant": {"graph_enabled": False},
        }
        ctx = Context(
            tmp_path,
            tmp_path / run_name,
            stage,
            {"case_id": "opaque-1", "source_dir": "projects/opaque-1"},
            config,
            {},
        )
        frozen = ingest(ctx)
        ctx.stage_dir = base / "static_extract"
        ctx.stage_dir.mkdir()
        ctx.results = {"ingest": {"result": frozen}}

        def command(args, *, cwd, log, stamp=run_name, **kwargs):
            log.write_text("fixture")
            if args[0] == "fixture-build":
                (cwd / "target").mkdir(exist_ok=True)
                (cwd / "target/Generated.java").write_text("class Generated {}")
                (cwd / "target/pom.properties").write_text(f"#timestamp {stamp}\n")
            elif args[1:3] == ["database", "create"]:
                database = Path(args[3])
                (database / "db-java/default").mkdir(parents=True)
                (database / "codeql-database.yml").write_text("primaryLanguage: java\n")
                (database / "src.zip").write_bytes(b"fixture")
                (database / "db-java/default/data.rel").write_bytes(b"fixture")
            elif args[1:3] == ["database", "analyze"]:
                Path(
                    next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
                ).write_text('{"runs":[{"results":[]}]}')

        monkeypatch.setattr("maxvera.research.command", command)
        extracted = static_extract(ctx)
        assert "target/Generated.java" in extracted["semantic_files"]
        assert "target/pom.properties" not in extracted["semantic_files"]
        assert (
            json.loads((ctx.stage_dir / "db_identity.json").read_text())["analyzed_snapshot_id"]
            == extracted["analyzed_snapshot_id"]
        )
        nodes, edges = graph_rows(1)
        nodes[0]["file"], nodes[1]["file"] = "App.java", "target/Generated.java"
        for name, rows in (("program_nodes", nodes), ("program_edges", edges)):
            with (ctx.stage_dir / f"{name}.csv").open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
        ctx.results["static_extract"] = {
            "result": {**extracted, "graph_enabled": True},
            "seconds": 0,
        }
        ctx.stage_dir = base / "build_graph"
        ctx.stage_dir.mkdir()
        build_graph(ctx)
        graph = json.loads((ctx.stage_dir / "graph.json").read_text())
        assert graph["snapshot_id"] == extracted["semantic_snapshot_id"]
        assert graph["analyzed_snapshot_id"] == extracted["analyzed_snapshot_id"]
        records.append((extracted, rank(generate(graph, []), top_k=5)))
    assert records[0][0]["analyzed_snapshot_id"] != records[1][0]["analyzed_snapshot_id"]
    assert records[0][0]["semantic_snapshot_id"] == records[1][0]["semantic_snapshot_id"]
    assert [c["candidate_id"] for c in records[0][1]] == [c["candidate_id"] for c in records[1][1]]
    assert [c["semantic_rank_key"] for c in records[0][1]] == [
        c["semantic_rank_key"] for c in records[1][1]
    ]
