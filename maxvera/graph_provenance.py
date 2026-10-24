"""Scope validated graphs to workspace source files with explicit archive exclusions."""

from __future__ import annotations

import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from maxvera.contracts import digest
from maxvera.graph import relative_file
from src.common.provenance import sha256_file

ARCHIVE_SUFFIXES = {".jar", ".zip", ".war", ".ear", ".jmod"}


def _backing_archive(workspace: Path, file: str) -> tuple[str, Path] | None:
    parts = PurePosixPath(file).parts
    if PurePosixPath(file).suffix != ".java":
        return None
    for index, part in enumerate(parts[:-1]):
        if PurePosixPath(part).suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        relative = PurePosixPath(*parts[: index + 1]).as_posix()
        archive = workspace / relative
        ancestors = [workspace.joinpath(*parts[:i]) for i in range(1, index + 2)]
        if any(path.is_symlink() for path in ancestors):
            raise ValueError("unsafe archive source path contains symlink")
        if not archive.resolve().is_relative_to(workspace):
            raise ValueError("unsafe archive source path escapes workspace")
        if archive.is_file():
            return relative, archive
    return None


def scope_graph_sources(
    graph: dict, node_rows: list[dict], edge_rows: list[dict], workspace: Path, analyzed_files: dict
) -> dict:
    """Apply only after normalize_graph has validated every node and edge, including exclusions."""
    workspace = workspace.resolve()
    retained, excluded_ids, excluded_files, archives = [], set(), {}, {}
    for node in graph["nodes"]:
        file = node["file"]
        content_hash = analyzed_files.get(file)
        if content_hash is not None:
            retained.append({**node, "content_hash": content_hash})
            continue
        backing = _backing_archive(workspace, file)
        if backing is None:
            raise ValueError("extracted node is not backed by input snapshot or workspace archive")
        relative, archive = backing
        if relative not in archives:
            if not zipfile.is_zipfile(archive):
                raise ValueError("virtual dependency source lacks a valid backing archive")
            archives[relative] = {"file": relative, "sha256": sha256_file(archive)}
        excluded_ids.add(node["node_id"])
        excluded_files[file] = relative
    excluded_keys = {
        row["key"] for row in node_rows if relative_file(row["file"]) in excluded_files
    }
    retained_edges = [
        edge for edge in graph["edges"] if not {edge["src"], edge["dst"]} & excluded_ids
    ]
    scope = {
        "policy": "workspace-source-files-v1",
        "scope": "WORKSPACE_SOURCE_ONLY",
        "excluded_node_rows": sum(
            relative_file(row["file"]) in excluded_files for row in node_rows
        ),
        "excluded_nodes": len(excluded_ids),
        "excluded_files": len(excluded_files),
        "excluded_edges": len(graph["edges"]) - len(retained_edges),
        "excluded_edge_rows": sum(
            bool({row["source"], row["target"]} & excluded_keys) for row in edge_rows
        ),
        "archives": [
            {
                **archives[archive],
                "excluded_source_files": sorted(
                    file for file, backing in excluded_files.items() if backing == archive
                ),
            }
            for archive in sorted(archives)
        ],
    }
    by_id = {node["node_id"]: node for node in retained}
    connected = {edge[key] for edge in retained_edges for key in ("src", "dst")}
    quality = {
        **graph["quality"],
        "nodes_by_kind": dict(Counter(node["kind"] for node in retained)),
        "edges_by_kind": dict(Counter(edge["kind"] for edge in retained_edges)),
        "orphan_nodes": sum(node["node_id"] not in connected for node in retained),
        "cross_file_edges": sum(
            by_id[edge["src"]]["file"] != by_id[edge["dst"]]["file"] for edge in retained_edges
        ),
        "provenance_coverage": 1.0 if retained else 0.0,
        "source_boundary": scope,
    }
    if excluded_ids:
        quality["limitations"] = [
            *quality["limitations"],
            "Virtual dependency nodes and incident edges are outside workspace-source scope",
        ]
    return {
        **graph,
        "nodes": retained,
        "edges": retained_edges,
        "graph_hash": digest([retained, retained_edges]),
        "quality": quality,
    }
