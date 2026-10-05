"""CodeQL queries that resolve every frozen endpoint's span and semantic contract."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from src.pipeline_v2.model import validate_descriptor
from src.verification.query import query_id


def _string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def bindings(
    specification: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    frozen: dict[tuple[str, str], dict[str, Any]] = {}
    for field, role in (("sources", "source"), ("sinks", "sink")):
        entries = specification.get(field, [])
        if not entries:
            raise ValueError("specification must bind both endpoint roles")
        for entry in entries:
            node = nodes[str(entry["node_id"])]
            properties = node["properties"]
            descriptor = properties["semantic_descriptor"]
            validate_descriptor(descriptor)
            if properties.get(
                "binding_status"
            ) != "RESOLVED_VULNERABLE" or role not in properties.get("endpoint_roles", []):
                raise ValueError("specification endpoint lacks grounded role provenance")
            record = {
                "node_id": properties["endpoint_id"],
                "descriptor": dict(descriptor),
                "roles": [role],
                "models": [dict(model) for model in properties["models"] if model["role"] == role],
                "role": role,
            }
            key = (role, record["node_id"])
            if key in frozen and frozen[key] != record:
                raise ValueError("endpoint aliases have conflicting semantic contracts")
            frozen[key] = record
    source = {node_id for role, node_id in frozen if role == "source"}
    sink = {node_id for role, node_id in frozen if role == "sink"}
    if source & sink:
        raise ValueError("source/sink dataflow bindings overlap")
    return [frozen[key] for key in sorted(frozen)]


def common_predicates(entries: Sequence[Mapping[str, Any]], cwe: str) -> str:
    clauses: list[str] = []
    for entry in entries:
        descriptor = entry["descriptor"]
        validate_descriptor(descriptor)
        semantics = [
            "v2Callable(node.getEnclosingCallable()) = "
            + _string(descriptor["enclosing_callable"]),
            f"node.getExpressionKind() = {_string(descriptor['expression_kind'])}",
            f"node.getDataFlowKind() = {_string(descriptor['dataflow_kind'])}",
            f"v2Slot(node, role) = {_string(descriptor['slot'])}",
            f"v2TargetSignature(node, role) = {_string(descriptor['target_signature'])}",
            f"node.toString() = {_string(descriptor['expression'])}",
            f"location.getFile().getRelativePath() = {_string(descriptor['file'])}",
            *(
                f"location.get{method}() = {descriptor[field]}"
                for field, method in (
                    ("start_line", "StartLine"),
                    ("start_column", "StartColumn"),
                    ("end_line", "EndLine"),
                    ("end_column", "EndColumn"),
                )
            ),
        ]
        models = []
        for model in entry["models"]:
            if entry["role"] == "source":
                models.append(f"v2Source(node, {_string(model['basis'])})")
            elif model["candidate_cwe"] == cwe:
                models.append(f"v2Sink(node, {_string(cwe)}, {_string(model['basis'])})")
        if not models:
            raise ValueError("frozen endpoint lacks a matching source/sink semantic model")
        body = " and\n      ".join(semantics)
        clauses.append(f"""(role = {_string(entry["role"])} and
    endpointId = {_string(entry["node_id"])} and
    exists(Location location | location = node.getLocation() and
      {body} and ({" or ".join(models)})
    ))""")
    if not clauses:
        raise ValueError("empty frozen endpoint contract")
    return (
        "predicate frozenEndpoint(string role, string endpointId, V2Node node) {\n  "
        + "\n  or\n  ".join(clauses)
        + "\n}\n"
    )


def endpoint_query(specification: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]) -> str:
    spec_id = str(specification["specification_id"])
    return f"""/**
 * @name MaxVera verifier v3 endpoint semantics {spec_id}
 * @kind table
 * @id {query_id(spec_id, endpoints=True)}
 */
import Grounding
{common_predicates(entries, str(specification["candidate_cwe"]))}
from string role, string endpointId, V2Node node
where frozenEndpoint(role, endpointId, node)
select role, endpointId, node as resolved_node,
  node.getLocation().getFile().getRelativePath() as file,
  node.getLocation().getStartLine() as line
"""


def path_query(specification: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]) -> str:
    spec_id, cwe = str(specification["specification_id"]), str(specification["candidate_cwe"])
    return f"""/**
 * @name MaxVera verifier v3 frozen semantic path {spec_id}
 * @description Unverified candidate until fail-closed fixed-side equivalence succeeds.
 * @kind path-problem
 * @problem.severity warning
 * @id {query_id(spec_id)}
 */
import Grounding
{common_predicates(entries, cwe)}
module FrozenConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node node) {{ frozenEndpoint("source", _, node) }}
  predicate isSink(DataFlow::Node node) {{ frozenEndpoint("sink", _, node) }}
  predicate isBarrier(DataFlow::Node node) {{ v2Barrier(node, {_string(cwe)}) }}
}}
module FrozenFlow = TaintTracking::Global<FrozenConfig>;
import FrozenFlow::PathGraph
from FrozenFlow::PathNode source, FrozenFlow::PathNode sink
where FrozenFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "{cwe} candidate from $@.", source.getNode(), "source"
"""


def resolution_complete(
    entries: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, str]]
) -> bool:
    expected = {(str(entry["role"]), str(entry["node_id"])) for entry in entries}
    counts = Counter((row["role"], row["endpointId"]) for row in rows)
    return set(counts) == expected and all(count == 1 for count in counts.values())
