"""Scope validated graphs to workspace source files with explicit archive exclusions."""

from __future__ import annotations

import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from maxvera.contracts import digest
from maxvera.graph import relative_file
from src.common.provenance import sha256_file

ARCHIVE_SUFFIXES = {".jar", ".zip", ".war", ".ear", ".jmod"}


def scope_static_signals(
    alerts: list[dict], workspace: Path, analyzed_files: dict[str, str]
) -> tuple[list[dict], dict]:
    """Keep repository evidence and account explicitly for every external location.

    A source-to-source CodeQL flow can cross dependencies; its repository endpoints
    remain valid flow evidence. An external endpoint leaves only partial location
    evidence. Raw SARIF and unscoped signals remain immutable extraction artifacts.
    """
    workspace = workspace.resolve()
    retained, records = [], []
    excluded_locations = partial_alerts = 0
    backing_cache = {}

    def backed_source(file):
        relative = relative_file(file)
        target = workspace / relative
        ancestors = [
            workspace.joinpath(*PurePosixPath(relative).parts[:i])
            for i in range(1, len(PurePosixPath(relative).parts) + 1)
        ]
        if any(path.is_symlink() for path in ancestors):
            raise ValueError("static signal source path contains symlink")
        if not target.resolve().is_relative_to(workspace):
            raise ValueError("static signal source path escapes workspace")
        if relative not in backing_cache:
            expected = analyzed_files.get(relative)
            if expected is None:
                backing_cache[relative] = False
            else:
                try:
                    if not target.is_file() or sha256_file(target) != expected:
                        raise ValueError("static signal source integrity mismatch")
                except OSError as error:
                    raise ValueError("static signal source integrity unreadable") from error
                backing_cache[relative] = True
        return backing_cache[relative]

    for index, alert in enumerate(alerts):
        locations = alert.get("locations", [])
        valid, excluded = [], []
        for position, location in enumerate(locations):
            file = location.get("file", "")
            if backed_source(file):
                valid.append((position, location))
            else:
                excluded.append(
                    {
                        "position": position,
                        "location": location,
                        "reason": "OUTSIDE_WORKSPACE_SOURCE_INVENTORY",
                    }
                )
        excluded_locations += len(excluded)
        status = "EXCLUDED_NO_REPOSITORY_LOCATION"
        if valid:
            complete_endpoints = valid[0][0] == 0 and valid[-1][0] == len(locations) - 1
            partial = alert.get("path_evidence") == "CODEQL_FLOW" and not complete_endpoints
            status = "PARTIAL_EXTERNAL_FLOW" if partial else "REPOSITORY_ENDPOINTS"
            partial_alerts += partial
            retained.append(
                {
                    **alert,
                    "locations": [location for _, location in valid],
                    "path_evidence": "LOCATION_ONLY" if partial else alert.get("path_evidence"),
                    "scope_status": status,
                    "excluded_location_count": len(excluded),
                    "scope_policy": "workspace-source-files-v1",
                }
            )
        records.append(
            {
                "alert_index": index,
                "finding_id": alert.get("finding_id"),
                "status": status,
                "retained_locations": len(valid),
                "excluded_locations": excluded,
            }
        )
    return retained, {
        "schema_version": "1.0",
        "policy": "workspace-source-files-v1",
        "input_alerts": len(alerts),
        "retained_alerts": len(retained),
        "excluded_alerts": len(alerts) - len(retained),
        "partial_alerts": partial_alerts,
        "excluded_locations": excluded_locations,
        "alerts": records,
    }


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
