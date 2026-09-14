from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml

from src.graphs.program.model import EDGE_KINDS, graph_digest, normalize_graph
from src.graphs.program.prepare import prepare_databases
from src.graphs.program.query import query_graph, select_seed

REPO_ROOT = Path(__file__).resolve().parents[2]


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
