"""Exact SARIF path endpoints, with immutable linkage and source validation.

SARIF regions end exclusively; Java CodeQL locations end inclusively. Only
explicit full spans are accepted. No graph-node or line-neighbour guessing occurs.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse

from maxvera.contracts import digest
from maxvera.graph import relative_file
from src.common.provenance import sha256_file
from src.reproduction.common import normalize_uri

BINDING_POLICY = "EXPR_OR_PARAMETER_EXACT_SPAN_V1"


def _width(text):
    return len(text.encode("utf-16-le")) // 2


def _positive(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("SARIF endpoint requires positive explicit line/column coordinates")
    return value


def _point(entry):
    physical = entry.get("location", {}).get("physicalLocation", {})
    return physical.get("artifactLocation", {}).get("uri"), physical.get("region", {})


def _span(entry):
    uri, region = _point(entry)
    artifact = entry.get("location", {}).get("physicalLocation", {}).get("artifactLocation", {})
    decoded = unquote(uri or "")
    if (
        decoded.startswith("/")
        or "\\" in decoded
        or urlparse(decoded).scheme
        or artifact.get("uriBaseId") not in (None, "%SRCROOT%")
    ):
        raise ValueError("SARIF endpoint requires a repository-relative source URI")
    start = _positive(region.get("startLine"))
    result = {
        "file": relative_file(normalize_uri(uri or "")),
        "start_line": start,
        "start_column": _positive(region.get("startColumn")),
        "end_line": _positive(region.get("endLine", start)),
        "end_column_exclusive": _positive(region.get("endColumn")),
    }
    if (result["end_line"], result["end_column_exclusive"]) <= (
        result["start_line"],
        result["start_column"],
    ):
        raise ValueError("SARIF endpoint span is empty or reversed")
    return result


def _index(raw, sarif_hash):
    paths = defaultdict(list)
    for ri, run in enumerate(raw.get("runs", [])):
        for si, result in enumerate(run.get("results", [])):
            for fi, flow in enumerate(result.get("codeFlows", [])):
                for ti, thread in enumerate(flow.get("threadFlows", [])):
                    entries = thread.get("locations", [])
                    points = []
                    for entry in entries:
                        uri, region = _point(entry)
                        line = region.get("startLine")
                        if uri and isinstance(line, int) and not isinstance(line, bool):
                            points.append((normalize_uri(uri), line))
                    if not points:
                        continue
                    spec = {
                        "schema_version": "1.0",
                        "status": "EXACT_SPAN",
                        "binding_policy": BINDING_POLICY,
                        "sarif_sha256": sarif_hash,
                        "selector": [ri, si, fi, ti],
                        "thread_sha256": digest(thread),
                        "rule_id": result.get("ruleId"),
                        "column_kind": run.get("columnKind", "utf16CodeUnits"),
                    }
                    try:
                        if len(points) != len(entries):
                            raise ValueError("SARIF path has unlocated thread flow steps")
                        if spec["column_kind"] != "utf16CodeUnits":
                            raise ValueError("unsupported SARIF column measurement")
                        spec.update({"source": _span(entries[0]), "sink": _span(entries[-1])})
                    except ValueError as error:
                        spec.update({"status": "UNSUPPORTED_SPAN", "reason": str(error)})
                    paths[tuple(points)].append(spec)
    return paths


def attach_endpoint_specs(alerts: list[dict], sarif_path: Path) -> list[dict]:
    """Attach only uniquely linked raw paths; preserve uncertain alerts for review."""
    sarif_hash = sha256_file(sarif_path)
    paths = _index(json.loads(sarif_path.read_text()), sarif_hash)
    output = []
    for alert in alerts:
        item = {**alert}
        if alert.get("path_evidence") == "CODEQL_FLOW":
            key = tuple((loc["file"], loc["start_line"]) for loc in alert["locations"])
            matches = paths.get(key, [])
            item["static_endpoint_spec"] = (
                matches[0]
                if len(matches) == 1
                else {
                    "schema_version": "1.0",
                    "status": "AMBIGUOUS_SARIF_LINKAGE",
                    "sarif_sha256": sarif_hash,
                    "matches": len(matches),
                }
            )
        output.append(item)
    return output


def resolve_endpoints(
    candidate: dict, sarif_path: Path, workspace: Path, analyzed_files: dict
) -> tuple[dict, dict]:
    """Reconstruct a candidate's exact specification from its original raw SARIF."""
    spec = candidate.get("static_endpoint_spec", {})
    scope = candidate.get("static_signal_scope", {})
    if (
        spec.get("status") != "EXACT_SPAN"
        or scope.get("status") != "REPOSITORY_ENDPOINTS"
        or scope.get("excluded_location_count") != 0
        or scope.get("policy") != "workspace-source-files-v1"
    ):
        raise ValueError("SARIF endpoint specification is incomplete or outside source boundary")
    if sarif_path.is_symlink() or spec.get("sarif_sha256") != sha256_file(sarif_path):
        raise ValueError("SARIF endpoint provenance integrity mismatch")
    reconstructed = attach_endpoint_specs(
        [{"locations": candidate["locations"], "path_evidence": "CODEQL_FLOW"}], sarif_path
    )[0]["static_endpoint_spec"]
    if reconstructed != spec:
        raise ValueError("SARIF endpoint linkage or specification changed")
    if any(path.is_symlink() for path in (workspace, *workspace.parents)):
        raise ValueError("SARIF endpoint source workspace contains symlink")
    workspace = workspace.resolve()
    nodes = []
    for role in ("source", "sink"):
        endpoint = spec[role]
        file = relative_file(endpoint["file"])
        target = workspace / file
        ancestors = [
            workspace.joinpath(*Path(file).parts[:i]) for i in range(1, len(Path(file).parts) + 1)
        ]
        expected = analyzed_files.get(file)
        if (
            any(path.is_symlink() for path in ancestors)
            or not target.resolve().is_relative_to(workspace)
            or not expected
            or not target.is_file()
            or sha256_file(target) != expected
        ):
            raise ValueError("SARIF endpoint source changed from analyzed snapshot")
        lines = target.read_text(encoding="utf-8").split("\n")
        start, end = endpoint["start_line"], endpoint["end_line"]
        start_column, exclusive = endpoint["start_column"], endpoint["end_column_exclusive"]
        if not 1 <= start <= end <= len(lines):
            raise ValueError("SARIF endpoint is outside analyzed source lines")
        # CodeQL Java and the pinned CodeQL SARIF producer use UTF-16 columns.
        if start_column > _width(lines[start - 1]) or exclusive > _width(lines[end - 1]) + 1:
            raise ValueError("SARIF endpoint is outside analyzed source columns")
        if exclusive == 1:
            end -= 1
            end_column = _width(lines[end - 1])
        else:
            end_column = exclusive - 1
        if end_column < 1:
            raise ValueError("SARIF endpoint ends on an empty line")
        span = {
            "file": file,
            "start_line": start,
            "start_column": start_column,
            "end_line": end,
            "end_column": end_column,
        }
        nodes.append(
            {
                **span,
                "node_id": "sarif-" + digest([role, span])[:24],
                "roles": [role],
                "content_hash": expected,
                "binding_policy": BINDING_POLICY,
            }
        )
    return nodes[0], nodes[1]
