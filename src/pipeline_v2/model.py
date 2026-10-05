"""Endpoint identity, grounding and fail-closed cross-version equivalence."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

DESCRIPTOR_VERSION = "java-dataflow-endpoint-v2"
SEMANTIC_FIELDS = (
    "enclosing_callable",
    "expression_kind",
    "dataflow_kind",
    "slot",
    "target_signature",
    "expression",
    "source_text_sha256",
)


def identifier(prefix: str, value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return prefix + "_" + hashlib.sha256(payload).hexdigest()[:24]


def descriptor_key(descriptor: Mapping[str, Any], *, include_file: bool = True) -> tuple[str, ...]:
    fields = ("file", *SEMANTIC_FIELDS) if include_file else SEMANTIC_FIELDS
    return tuple(str(descriptor[field]) for field in fields)


def validate_descriptor(descriptor: Mapping[str, Any]) -> None:
    if descriptor.get("version") != DESCRIPTOR_VERSION:
        raise ValueError("unsupported semantic endpoint descriptor")
    file = str(descriptor.get("file", ""))
    path = PurePosixPath(file)
    if not file or path.is_absolute() or ".." in path.parts or "\\" in file:
        raise ValueError("endpoint file must be a normalized relative path")
    for field in SEMANTIC_FIELDS:
        if not isinstance(descriptor.get(field), str):
            raise ValueError(f"missing endpoint semantic field: {field}")
    if not descriptor["enclosing_callable"] or not descriptor["expression"]:
        raise ValueError("endpoint requires callable and expression evidence")
    if descriptor["dataflow_kind"] not in {"expr", "parameter"}:
        raise ValueError("unsupported endpoint dataflow node")
    for field in ("start_line", "start_column", "end_line", "end_column"):
        value = descriptor.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("invalid endpoint span")
    start = (descriptor["start_line"], descriptor["start_column"])
    end = (descriptor["end_line"], descriptor["end_column"])
    if end < start:
        raise ValueError("reversed endpoint span")
    digest = str(descriptor.get("source_sha256", ""))
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("endpoint requires source checksum")
    expression_digest = descriptor["source_text_sha256"]
    if len(expression_digest) != 64 or any(c not in "0123456789abcdef" for c in expression_digest):
        raise ValueError("endpoint requires a checksum of its exact source expression")


def inventory_records(
    project_id: str,
    rows: Sequence[Mapping[str, str]],
    source_hashes: Mapping[str, str],
    provenance: Mapping[str, Any],
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for row in rows:
        descriptor: dict[str, Any] = {
            "version": DESCRIPTOR_VERSION,
            "file": row["file"],
            "source_sha256": source_hashes[row["file"]],
            **{field: row[field] for field in SEMANTIC_FIELDS},
            **{
                field: int(row[field])
                for field in ("start_line", "start_column", "end_line", "end_column")
            },
        }
        validate_descriptor(descriptor)
        node_id = identifier("epn", [project_id, descriptor])
        record = records.setdefault(
            node_id,
            {
                "schema_version": 2,
                "project_id": project_id,
                "node_id": node_id,
                "semantic_id": identifier("eps", [project_id, descriptor_key(descriptor)]),
                "database_entity_id": row.get("resolved_node_entity_id", ""),
                "descriptor": descriptor,
                "roles": [],
                "models": [],
                "provenance": dict(provenance),
            },
        )
        role = row["role"]
        if role not in {"source", "sink"} or not row["basis"]:
            raise ValueError("endpoint requires typed role provenance")
        if role not in record["roles"]:
            record["roles"].append(role)
        model = {"role": role, "candidate_cwe": row["cwe"], "basis": row["basis"]}
        if model not in record["models"]:
            record["models"].append(model)
    for record in records.values():
        record["roles"].sort()
        record["models"].sort(key=lambda m: (m["role"], m["candidate_cwe"], m["basis"]))
    return [records[key] for key in sorted(records)]


def span_key(descriptor: Mapping[str, Any]) -> tuple[object, ...]:
    return tuple(
        descriptor[field]
        for field in (
            "file",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
            "dataflow_kind",
        )
    )


def candidates_from_flows(
    project_id: str,
    endpoints: Sequence[Mapping[str, Any]],
    flows: Sequence[Mapping[str, str]],
    *,
    top_k: int = 10,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bindings: dict[tuple[object, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for endpoint in endpoints:
        bindings[span_key(endpoint["descriptor"])].append(endpoint)
    candidates: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for flow in flows:
        selected: dict[str, Mapping[str, Any]] = {}
        for role in ("source", "sink"):
            key = (
                flow[f"{role}_file"],
                int(flow[f"{role}_line"]),
                int(flow[f"{role}_column"]),
                int(flow[f"{role}_end_line"]),
                int(flow[f"{role}_end_column"]),
                flow[f"{role}_dataflow_kind"],
            )
            matches = [
                endpoint
                for endpoint in bindings[key]
                if role in endpoint["roles"]
                and (
                    role == "source"
                    or any(
                        model["candidate_cwe"] == flow["cwe"] and model["role"] == "sink"
                        for model in endpoint["models"]
                    )
                )
            ]
            if len(matches) != 1:
                rejected.append(
                    {
                        "project_id": project_id,
                        "reason": "AMBIGUOUS_OR_MISSING_BINDING",
                        "role": role,
                        "matches": len(matches),
                        "flow": dict(flow),
                    }
                )
                break
            selected[role] = matches[0]
        if len(selected) != 2:
            continue
        source, sink = selected["source"], selected["sink"]
        if source["node_id"] == sink["node_id"]:
            rejected.append(
                {"project_id": project_id, "reason": "DEGENERATE_SOURCE_SINK", "flow": dict(flow)}
            )
            continue
        hypothesis_id = identifier(
            "hyp2", [project_id, flow["cwe"], source["node_id"], sink["node_id"]]
        )
        evidence_kind = flow.get("evidence_kind", "GLOBAL_TAINT_CANDIDATE")
        scores = {
            "GLOBAL_TAINT_CANDIDATE": 0.9,
            "SAME_CALLABLE_NO_FLOW_PROOF": 0.7,
            "CALL_BOUNDARY_NO_FLOW_PROOF": 0.6,
        }
        if evidence_kind not in scores:
            raise ValueError("unknown candidate relation provenance")
        if (
            hypothesis_id in candidates
            and scores[candidates[hypothesis_id]["evidence_kind"]] >= scores[evidence_kind]
        ):
            continue
        test_segments = {"test", "tests", "testsuite", "examples", "samples"}
        non_application = any(
            test_segments & set(PurePosixPath(endpoint["descriptor"]["file"]).parts)
            for endpoint in (source, sink)
        )
        ranking_score = scores[evidence_kind] - (0.3 if non_application else 0.0)
        candidates[hypothesis_id] = {
            "schema_version": 2,
            "hypothesis_id": hypothesis_id,
            "project_id": project_id,
            "candidate_cwe": [flow["cwe"]],
            "generator": "typed_codeql_candidate_discovery_v2",
            "ranking_version": "typed_family_balanced_v2",
            "score": round(ranking_score, 3),
            "application_source_priority": not non_application,
            "evidence_kind": evidence_kind,
            "source_candidates": [dict(source)],
            "sink_candidates": [dict(sink)],
            "grounding_status": "SOURCE_SINK_RESOLVED",
            "verification_status": "UNVERIFIED",
            "provenance": {
                "flow_rule": evidence_kind,
                "source": source["provenance"],
                "sink": sink["provenance"],
            },
        }
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in sorted(
        candidates.values(), key=lambda row: (-row["score"], row["hypothesis_id"])
    ):
        families[candidate["candidate_cwe"][0]].append(candidate)
    selected_hypotheses: list[dict[str, Any]] = []
    depth = 0
    while len(selected_hypotheses) < top_k:
        layer = [
            families[family][depth] for family in sorted(families) if depth < len(families[family])
        ]
        if not layer:
            break
        selected_hypotheses.extend(layer[: top_k - len(selected_hypotheses)])
        depth += 1
    for rank, hypothesis in enumerate(selected_hypotheses, 1):
        hypothesis["rank"] = rank
    return selected_hypotheses, rejected


def map_endpoint(
    endpoint: Mapping[str, Any],
    fixed_inventory: Sequence[Mapping[str, Any]],
    *,
    unchanged_line: int | None = None,
) -> tuple[Mapping[str, Any] | None, dict[str, Any]]:
    """Require full semantic equivalence; line/path guesses never establish equivalence."""
    descriptor = endpoint["descriptor"]
    validate_descriptor(descriptor)
    equivalent: list[Mapping[str, Any]] = []
    for candidate in fixed_inventory:
        validate_descriptor(candidate["descriptor"])
        if descriptor_key(candidate["descriptor"], include_file=False) != descriptor_key(
            descriptor, include_file=False
        ):
            continue
        if set(endpoint["roles"]) - set(candidate["roles"]):
            continue
        required = {(m["role"], m["candidate_cwe"], m["basis"]) for m in endpoint["models"]}
        available = {(m["role"], m["candidate_cwe"], m["basis"]) for m in candidate["models"]}
        if required <= available:
            equivalent.append(candidate)
    same_path = [
        candidate
        for candidate in equivalent
        if candidate["descriptor"]["file"] == descriptor["file"]
    ]
    if unchanged_line is not None:
        exact = [
            candidate
            for candidate in same_path
            if candidate["descriptor"]["start_line"] == unchanged_line
        ]
        if len(exact) == 1 and len(same_path) == 1:
            return exact[0], {
                "complete": True,
                "strategy": "EXACT_LINE_AND_SEMANTICS",
                "alternatives": len(equivalent),
            }
    pool = same_path or equivalent
    if len(pool) != 1:
        return None, {
            "complete": False,
            "strategy": "UNRESOLVED_OR_AMBIGUOUS",
            "alternatives": len(pool),
        }
    strategy = "CALLABLE_SYMBOL_SEMANTICS" if same_path else "FILE_RENAME_AND_SEMANTICS"
    return pool[0], {"complete": True, "strategy": strategy, "alternatives": 1}
