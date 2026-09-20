"""Render Phase 11 endpoint and global-taint CodeQL queries."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def _ql_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def query_id(specification_id: str, *, endpoints: bool = False) -> str:
    """Return a CodeQL-valid, stable query identifier for one specification."""

    suffix = specification_id.replace("_", "-")
    tail = "/endpoints" if endpoints else ""
    return f"java/maxvera/phase11/{suffix}{tail}"


def _descriptor(node: Mapping[str, Any], variable: str = "expr") -> str | None:
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    if node.get("layer") == "program":
        location = properties.get("location")
        if not isinstance(location, Mapping):
            return None
        file_name = location.get("file")
        line = location.get("start_line")
        if isinstance(file_name, str) and isinstance(line, int) and line > 0:
            return f"phase11AtLocation({variable}, {_ql_string(file_name)}, {line})"
        return None
    if node.get("layer") == "evidence":
        file_name = properties.get("file")
        line = properties.get("line")
        if isinstance(file_name, str) and isinstance(line, int) and line > 0:
            return f"phase11AtLocation({variable}, {_ql_string(file_name)}, {line})"
        return None
    if node.get("layer") != "security":
        return None
    fact = properties.get("fact_properties")
    if not isinstance(fact, Mapping):
        return None
    callable_name = str(fact.get("callable", "")).strip()
    type_name = str(fact.get("type", "")).strip()
    if callable_name and type_name:
        return f"phase11Method({variable}, {_ql_string(callable_name)}, {_ql_string(type_name)})"
    if callable_name:
        return f"phase11MethodName({variable}, {_ql_string(callable_name)})"
    if type_name:
        return f"phase11TypeName({variable}, {_ql_string(type_name)})"
    return None


def _role_predicate(
    name: str,
    entries: object,
    nodes: Mapping[str, Mapping[str, Any]],
) -> str:
    descriptors: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            node = nodes.get(str(entry.get("node_id")))
            if node is not None and (descriptor := _descriptor(node)):
                descriptors.append(descriptor)
    unique = sorted(set(descriptors))
    body = "\n    or\n    ".join(unique) if unique else "none()"
    return f"predicate phase11{name}(Expr expr) {{\n    {body}\n}}"


def _common_predicates(
    specification: Mapping[str, Any], nodes: Mapping[str, Mapping[str, Any]]
) -> str:
    roles = [
        _role_predicate("Source", specification.get("sources"), nodes),
        _role_predicate("Sink", specification.get("sinks"), nodes),
        _role_predicate("Sanitizer", specification.get("sanitizers"), nodes),
        _role_predicate("Propagator", specification.get("propagators"), nodes),
    ]
    return f"""predicate phase11AtLocation(Expr expr, string file, int line) {{
  expr.getLocation().getFile().getRelativePath() = file and
  expr.getLocation().getStartLine() = line
}}

predicate phase11MethodName(Expr expr, string callableName) {{
  exists(MethodCall call |
    expr = call and call.getMethod().getName() = callableName
  )
}}

predicate phase11Method(Expr expr, string callableName, string typeName) {{
  exists(MethodCall call |
    expr = call and
    call.getMethod().getName() = callableName and
    call.getMethod().getDeclaringType().getName() = typeName
  )
}}

predicate phase11TypeName(Expr expr, string typeName) {{
  expr.getType().getName() = typeName
}}

{chr(10).join(roles)}"""


def render_endpoint_query(
    specification: Mapping[str, Any], nodes: Mapping[str, Mapping[str, Any]]
) -> str:
    """Render an inventory query used to distinguish unresolved endpoints from no-path."""

    spec_id = str(specification["specification_id"])
    common = _common_predicates(specification, nodes)
    return f"""/**
 * @name MaxVera Phase 11 endpoint inventory {spec_id}
 * @description Resolves graph-grounded endpoint descriptors before verification.
 * @kind table
 * @id {query_id(spec_id, endpoints=True)}
 */

import java

{common}

from Expr endpoint, string role
where
  role = "source" and phase11Source(endpoint)
  or
  role = "sink" and phase11Sink(endpoint)
select role, endpoint.getLocation().getFile().getRelativePath(),
  endpoint.getLocation().getStartLine(), endpoint.toString()
"""


def render_path_query(
    specification: Mapping[str, Any], nodes: Mapping[str, Mapping[str, Any]]
) -> str:
    """Render a path-problem query whose result is authoritative only after differential."""

    spec_id = str(specification["specification_id"])
    cwe = str(specification["candidate_cwe"])
    common = _common_predicates(specification, nodes)
    return f'''/**
 * @name MaxVera Phase 11 taint path {spec_id}
 * @description Static verification candidate for {cwe} from a frozen Phase 10 specification.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id {query_id(spec_id)}
 */

import java
import semmle.code.java.dataflow.TaintTracking

{common}

module Phase11Config implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node node) {{ phase11Source(node.asExpr()) }}

  predicate isSink(DataFlow::Node node) {{ phase11Sink(node.asExpr()) }}

  predicate isBarrier(DataFlow::Node node) {{ phase11Sanitizer(node.asExpr()) }}

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {{
    exists(MethodCall call, Expr input |
      phase11Propagator(call) and
      (input = call.getQualifier() or input = call.getAnArgument()) and
      node1.asExpr() = input and node2.asExpr() = call
    )
  }}
}}

module Phase11Flow = TaintTracking::Global<Phase11Config>;
import Phase11Flow::PathGraph

from Phase11Flow::PathNode source, Phase11Flow::PathNode sink
where Phase11Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "{cwe} candidate has a path from $@.", source.getNode(), "source"
'''
