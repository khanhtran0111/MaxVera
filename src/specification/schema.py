"""Strict schema and semantic validation for Phase 10 specifications."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
ROLES = ("sources", "sinks", "sanitizers", "propagators")


def specification_json_schema(
    *,
    hypothesis_id: str,
    candidate_cwes: Sequence[str],
    allowed_endpoint_ids_by_role: Mapping[str, Sequence[str]],
    allowed_evidence_ids: Sequence[str],
    max_role_items: int,
    max_preconditions: int,
) -> dict[str, Any]:
    endpoints = sorted(
        {node_id for role_ids in allowed_endpoint_ids_by_role.values() for node_id in role_ids}
    )
    evidence = sorted(set(allowed_evidence_ids))
    if not endpoints:
        raise ValueError("specification schema requires at least one endpoint candidate")
    precondition = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "minLength": 1, "maxLength": 500},
            "evidence_node_ids": {
                "type": "array",
                "items": {"type": "string", "enum": evidence or endpoints},
                "maxItems": 8,
            },
        },
        "required": ["text", "evidence_node_ids"],
        "additionalProperties": False,
    }
    role_properties: dict[str, Any] = {}
    for role in ROLES:
        role_ids = sorted(set(allowed_endpoint_ids_by_role.get(role, [])))
        endpoint = {
            "type": "object",
            "properties": {
                # JSON Schema forbids an empty enum. Optional roles with no
                # grounded candidates are forced empty by maxItems=0, while a
                # non-empty fallback enum keeps the schema provider-valid.
                "node_id": {"type": "string", "enum": role_ids or endpoints},
                "rationale": {"type": "string", "minLength": 1, "maxLength": 500},
            },
            "required": ["node_id", "rationale"],
            "additionalProperties": False,
        }
        role_properties[role] = {
            "type": "array",
            "items": endpoint,
            "minItems": 1 if role in {"sources", "sinks"} else 0,
            "maxItems": min(max_role_items, len(role_ids)),
        }
    return {
        "type": "object",
        "properties": {
            "specification": {
                "type": "object",
                "properties": {
                    "hypothesis_id": {"type": "string", "enum": [hypothesis_id]},
                    "candidate_cwe": {
                        "type": "string",
                        "enum": sorted(set(candidate_cwes)),
                    },
                    **role_properties,
                    "preconditions": {
                        "type": "array",
                        "items": precondition,
                        "maxItems": max_preconditions,
                    },
                    "summary": {"type": "string", "minLength": 1, "maxLength": 800},
                },
                "required": [
                    "hypothesis_id",
                    "candidate_cwe",
                    *ROLES,
                    "preconditions",
                    "summary",
                ],
                "additionalProperties": False,
            }
        },
        "required": ["specification"],
        "additionalProperties": False,
    }


def _json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            candidate = "\n".join(lines[1:-1])
    loaded = json.loads(candidate)
    if not isinstance(loaded, dict):
        raise ValueError("model response must be a JSON object")
    return loaded


def _external_kind(node: Mapping[str, Any]) -> str:
    properties = node.get("properties")
    return str(properties.get("external_kind", "")) if isinstance(properties, Mapping) else ""


def endpoint_role_allowed(role: str, node: Mapping[str, Any]) -> bool:
    if role not in ROLES:
        return False
    properties = node.get("properties")
    if isinstance(properties, Mapping) and properties.get("grounding_version") == 2:
        from src.pipeline_v2.model import validate_descriptor

        descriptor = properties.get("semantic_descriptor")
        if not isinstance(descriptor, Mapping):
            return False
        try:
            validate_descriptor(descriptor)
        except ValueError:
            return False
        expected_role = {
            "sources": "source",
            "sinks": "sink",
            "sanitizers": "sanitizer",
            "propagators": "propagator",
        }[role]
        return (
            properties.get("binding_status") == "RESOLVED_VULNERABLE"
            and expected_role in properties.get("endpoint_roles", [])
            and any(
                isinstance(model, Mapping)
                and model.get("role") == expected_role
                and model.get("basis")
                for model in properties.get("models", [])
            )
        )
    layer = node.get("layer")
    if layer == "program":
        return True
    if layer == "evidence":
        properties = node.get("properties")
        expected = {
            "sources": "source",
            "sinks": "sink",
            "sanitizers": "sanitizer",
            "propagators": "propagator",
        }[role]
        if not isinstance(properties, Mapping):
            return False
        return bool(
            properties.get("assertion_type") == "source_location"
            and properties.get("role") == expected
        )
    if layer != "security":
        return False
    expected = {
        "sources": "SOURCE",
        "sinks": "SINK",
        "sanitizers": "SANITIZER",
        "propagators": "PROPAGATOR",
    }[role]
    return _external_kind(node) == expected


def _validate_endpoint_role(role: str, node: Mapping[str, Any]) -> None:
    if not endpoint_role_allowed(role, node):
        raise ValueError(f"{role} node does not support the requested semantic role")


def parse_specification(
    response: str,
    *,
    project_id: str,
    hypothesis_id: str,
    candidate_cwes: Sequence[str],
    context_id: str,
    context_nodes: Mapping[str, Mapping[str, Any]],
    allowed_node_ids: set[str],
    baseline_id: str,
    attempt: int,
    max_role_items: int,
    max_preconditions: int,
) -> dict[str, Any]:
    loaded = _json_object(response)
    raw = loaded.get("specification")
    if not isinstance(raw, Mapping):
        raise ValueError("response.specification must be an object")
    if raw.get("hypothesis_id") != hypothesis_id:
        raise ValueError("specification hypothesis_id does not match the requested hypothesis")
    cwe = raw.get("candidate_cwe")
    if not isinstance(cwe, str) or not CWE_PATTERN.fullmatch(cwe):
        raise ValueError("candidate_cwe must use canonical CWE-N syntax")
    if cwe not in set(candidate_cwes):
        raise ValueError("candidate_cwe is not present in the locked hypothesis")

    normalized_roles: dict[str, list[dict[str, str]]] = {}
    for role in ROLES:
        items = raw.get(role)
        if not isinstance(items, list) or len(items) > max_role_items:
            raise ValueError(f"{role} must be a list with at most {max_role_items} items")
        if role in {"sources", "sinks"} and not items:
            raise ValueError(f"{role} must contain at least one grounded endpoint")
        seen: set[str] = set()
        normalized: list[dict[str, str]] = []
        for item in items:
            if not isinstance(item, Mapping):
                raise ValueError(f"{role} entries must be objects")
            node_id = item.get("node_id")
            rationale = item.get("rationale")
            if not isinstance(node_id, str) or node_id not in allowed_node_ids:
                raise ValueError(f"{role} references a node outside serialized context")
            node = context_nodes.get(node_id)
            if node is None:
                raise ValueError(f"{role} references an unknown context node")
            _validate_endpoint_role(role, node)
            if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 500:
                raise ValueError(f"{role} rationale must be 1-500 characters")
            if node_id in seen:
                continue
            seen.add(node_id)
            normalized.append({"node_id": node_id, "rationale": rationale.strip()})
        normalized_roles[role] = normalized

    raw_preconditions = raw.get("preconditions")
    if not isinstance(raw_preconditions, list) or len(raw_preconditions) > max_preconditions:
        raise ValueError("preconditions list exceeds the configured maximum")
    preconditions: list[dict[str, Any]] = []
    for item in raw_preconditions:
        if not isinstance(item, Mapping):
            raise ValueError("precondition entries must be objects")
        text = item.get("text")
        evidence_ids = item.get("evidence_node_ids")
        if not isinstance(text, str) or not text.strip() or len(text) > 500:
            raise ValueError("precondition text must be 1-500 characters")
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 8:
            raise ValueError("precondition evidence_node_ids must be a bounded list")
        if any(
            not isinstance(value, str) or value not in allowed_node_ids for value in evidence_ids
        ):
            raise ValueError("precondition references a node outside serialized context")
        preconditions.append(
            {"text": text.strip(), "evidence_node_ids": list(dict.fromkeys(evidence_ids))}
        )
    summary = raw.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 800:
        raise ValueError("summary must be 1-800 characters")
    identity_payload = json.dumps(
        {
            "baseline_id": baseline_id,
            "context_id": context_id,
            "hypothesis_id": hypothesis_id,
            "candidate_cwe": cwe,
            **normalized_roles,
            "preconditions": preconditions,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    spec_id = f"spec_{hashlib.sha256(identity_payload.encode()).hexdigest()[:24]}"
    return {
        "schema_version": 1,
        "specification_version": "phase10-spec-v1",
        "specification_id": spec_id,
        "baseline_id": baseline_id,
        "project_id": project_id,
        "hypothesis_id": hypothesis_id,
        "context_id": context_id,
        "candidate_cwe": cwe,
        **normalized_roles,
        "preconditions": preconditions,
        "summary": summary.strip(),
        "synthesis_attempt": attempt,
        "status": "SYNTHESIZED_UNVERIFIED",
    }
