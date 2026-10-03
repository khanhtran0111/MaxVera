"""Conservative source-location remapping for vulnerable/fixed verification.

Only locations in exact unchanged diff blocks are mapped. Changed, deleted,
ambiguous, or unavailable locations remain unresolved and can never support a
differential verdict.
"""

from __future__ import annotations

import copy
import hashlib
import zipfile
from collections.abc import Mapping, Sequence
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, cast

LOCATION_ROLES = ("sources", "sinks", "sanitizers", "propagators")


def unchanged_line_mapping(before: Sequence[str], after: Sequence[str]) -> dict[int, int]:
    """Map one-based lines in exact matching blocks with at least two lines."""

    mapping: dict[int, int] = {}
    for block in SequenceMatcher(None, before, after, autojunk=False).get_matching_blocks():
        if block.size < 2:
            continue
        for offset in range(block.size):
            old_line = block.a + offset + 1
            new_line = block.b + offset + 1
            if before[old_line - 1].strip():
                mapping[old_line] = new_line
    return mapping


def archive_source(archive: Path, relative: str) -> tuple[str, list[str]]:
    """Read exactly one suffix-matching source from a CodeQL source archive."""

    candidate = Path(relative)
    if not relative or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("endpoint file must be a safe relative source path")
    with zipfile.ZipFile(archive) as handle:
        matches = [
            name for name in handle.namelist() if name == relative or name.endswith("/" + relative)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"source archive requires one match for {relative}; found {len(matches)}"
            )
        data = handle.read(matches[0])
    return hashlib.sha256(data).hexdigest(), data.decode(
        "utf-8", errors="replace"
    ).splitlines()


def node_location(node: Mapping[str, Any]) -> tuple[str, int] | None:
    """Return a line-bound descriptor, or None for stable semantic descriptors."""

    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    if node.get("layer") == "program":
        location = properties.get("location")
        if not isinstance(location, Mapping):
            return None
        file_name, line = location.get("file"), location.get("start_line")
    elif node.get("layer") == "evidence":
        file_name, line = properties.get("file"), properties.get("line")
    else:
        return None
    if isinstance(file_name, str) and isinstance(line, int) and line > 0:
        return file_name, line
    return None


def remap_nodes_for_fixed(
    specification: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    vulnerable_archive: Path,
    fixed_archive: Path,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Any]]:
    """Return remapped nodes plus a complete, fail-closed mapping record."""

    remapped: dict[str, Mapping[str, Any]] = dict(nodes)
    endpoints: list[dict[str, Any]] = []
    cache: dict[str, tuple[str, str, list[str], list[str], dict[int, int]]] = {}
    complete = True
    for role in LOCATION_ROLES:
        entries = specification.get(role, [])
        if not isinstance(entries, list):
            complete = False
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                complete = False
                continue
            node_id = str(entry.get("node_id", ""))
            node = nodes.get(node_id)
            if node is None:
                endpoints.append({"role": role, "node_id": node_id, "status": "NODE_MISSING"})
                complete = False
                continue
            location = node_location(node)
            if location is None:
                endpoints.append(
                    {"role": role, "node_id": node_id, "status": "SEMANTIC_DESCRIPTOR"}
                )
                continue
            file_name, old_line = location
            try:
                if file_name not in cache:
                    vulnerable_sha, vulnerable_lines = archive_source(
                        vulnerable_archive, file_name
                    )
                    fixed_sha, fixed_lines = archive_source(fixed_archive, file_name)
                    cache[file_name] = (
                        vulnerable_sha,
                        fixed_sha,
                        vulnerable_lines,
                        fixed_lines,
                        unchanged_line_mapping(vulnerable_lines, fixed_lines),
                    )
                vulnerable_sha, fixed_sha, vulnerable_lines, fixed_lines, mapping = cache[
                    file_name
                ]
                new_line = mapping.get(old_line)
                status = (
                    "UNCHANGED_AT_SAME_LINE"
                    if new_line == old_line
                    else "UNCHANGED_BUT_MOVED"
                    if new_line is not None
                    else "CHANGED_REMOVED_OR_AMBIGUOUS"
                )
                endpoints.append(
                    {
                        "role": role,
                        "node_id": node_id,
                        "file": file_name,
                        "vulnerable_line": old_line,
                        "fixed_line": new_line,
                        "status": status,
                        "vulnerable_text_sha256": hashlib.sha256(
                            vulnerable_lines[old_line - 1].encode()
                        ).hexdigest()
                        if old_line <= len(vulnerable_lines)
                        else None,
                        "fixed_text_sha256": hashlib.sha256(
                            fixed_lines[new_line - 1].encode()
                        ).hexdigest()
                        if new_line is not None and new_line <= len(fixed_lines)
                        else None,
                        "vulnerable_source_sha256": vulnerable_sha,
                        "fixed_source_sha256": fixed_sha,
                    }
                )
            except (OSError, ValueError, zipfile.BadZipFile) as error:
                new_line = None
                endpoints.append(
                    {
                        "role": role,
                        "node_id": node_id,
                        "file": file_name,
                        "vulnerable_line": old_line,
                        "fixed_line": None,
                        "status": "SOURCE_MAPPING_FAILED",
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
            if new_line is None:
                complete = False
                continue
            mapped = copy.deepcopy(dict(node))
            properties = cast(dict[str, Any], mapped["properties"])
            if mapped.get("layer") == "program":
                location_record = cast(dict[str, Any], properties["location"])
                delta = new_line - old_line
                location_record["start_line"] = new_line
                end_line = location_record.get("end_line")
                if isinstance(end_line, int):
                    location_record["end_line"] = end_line + delta
            else:
                properties["line"] = new_line
            remapped[node_id] = mapped
    return remapped, {
        "schema_version": 1,
        "strategy": "exact_unchanged_diff_blocks_minimum_two_lines_v1",
        "complete": complete,
        "entries": endpoints,
    }
