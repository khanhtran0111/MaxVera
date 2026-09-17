"""Render and syntax-check Phase 10 CodeQL template constraints."""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _ql_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _program_descriptor(node: Mapping[str, Any]) -> str | None:
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    location = properties.get("location")
    if not isinstance(location, Mapping):
        return None
    file_name = location.get("file")
    line = location.get("start_line")
    if not isinstance(file_name, str) or not isinstance(line, int) or line < 1:
        return None
    return f"phase10AtLocation(element, {_ql_string(file_name)}, {line})"


def _evidence_descriptor(node: Mapping[str, Any]) -> str | None:
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    file_name = properties.get("file")
    line = properties.get("line")
    if not isinstance(file_name, str) or not isinstance(line, int) or line < 1:
        return None
    return f"phase10AtLocation(element, {_ql_string(file_name)}, {line})"


def _security_descriptor(node: Mapping[str, Any]) -> str | None:
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        return None
    fact = properties.get("fact_properties")
    if not isinstance(fact, Mapping):
        return None
    callable_name = str(fact.get("callable", "")).strip()
    type_name = str(fact.get("type", "")).strip()
    if callable_name and type_name:
        return (
            "phase10Method(element, "
            f"{_ql_string(callable_name)}, {_ql_string(type_name)})"
        )
    if callable_name:
        return f"phase10MethodName(element, {_ql_string(callable_name)})"
    if type_name:
        return f"phase10TypeName(element, {_ql_string(type_name)})"
    return None


def _role_predicate(
    role: str,
    entries: object,
    nodes: Mapping[str, Mapping[str, Any]],
) -> str:
    descriptors: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            node = nodes.get(str(entry.get("node_id")))
            if node is None:
                continue
            if node.get("layer") == "program":
                descriptor = _program_descriptor(node)
            elif node.get("layer") == "evidence":
                descriptor = _evidence_descriptor(node)
            else:
                descriptor = _security_descriptor(node)
            if descriptor:
                descriptors.append(descriptor)
    if not descriptors:
        raise ValueError(f"{role} has no compilable Program/Security descriptor")
    body = "\n    or\n    ".join(sorted(set(descriptors)))
    return f"predicate phase10{role.title()}(Element element) {{\n    {body}\n}}"


def render_query(
    specification: Mapping[str, Any], context_nodes: Mapping[str, Mapping[str, Any]]
) -> str:
    source = _role_predicate("source", specification.get("sources"), context_nodes)
    sink = _role_predicate("sink", specification.get("sinks"), context_nodes)
    optional: list[str] = []
    for role, field in (("sanitizer", "sanitizers"), ("propagator", "propagators")):
        entries = specification.get(field)
        if isinstance(entries, list) and entries:
            optional.append(_role_predicate(role, entries, context_nodes))
    sanitizer_guard = (
        " and not phase10Sanitizer(sink)" if specification.get("sanitizers") else ""
    )
    spec_id = str(specification["specification_id"])
    cwe = str(specification["candidate_cwe"])
    return f'''/**
 * @name MaxVera Phase 10 synthesized constraint {spec_id}
 * @description Unverified graph-grounded candidate for {cwe}; verification is Phase 11.
 * @kind problem
 * @problem.severity warning
 * @id java/maxvera/phase10/{spec_id}
 */

import java

predicate phase10AtLocation(Element element, string file, int line) {{
  exists(Location location |
    location = element.getLocation() and
    location.getFile().getRelativePath() = file and
    location.getStartLine() = line
  )
}}

predicate phase10MethodName(Element element, string callableName) {{
  exists(MethodCall call |
    element = call and call.getMethod().getName() = callableName
  )
}}

predicate phase10Method(Element element, string callableName, string typeName) {{
  exists(MethodCall call |
    element = call and
    call.getMethod().getName() = callableName and
    call.getMethod().getDeclaringType().getName() = typeName
  )
}}

predicate phase10TypeName(Element element, string typeName) {{
  exists(Type type | element = type and type.getName() = typeName)
}}

{source}

{sink}

{chr(10).join(optional)}

from Element source, Element sink
where phase10Source(source) and phase10Sink(sink){sanitizer_guard}
select sink, "{cwe} candidate with graph-grounded source $@.", source, "source"
'''


def compile_query(
    *,
    codeql: Path,
    query_path: Path,
    timeout_seconds: int,
    ram_mb: int,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        process = subprocess.run(
            [
                str(codeql),
                "query",
                "compile",
                "--check-only",
                "--threads=1",
                f"--ram={ram_mb}",
                "--",
                str(query_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return {
            "status": "COMPILED" if process.returncode == 0 else "COMPILE_FAILED",
            "exit_code": process.returncode,
            "seconds": round(time.monotonic() - started, 3),
            "stdout": process.stdout[-4000:],
            "stderr": process.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as error:
        return {
            "status": "COMPILE_TIMEOUT",
            "exit_code": None,
            "seconds": round(time.monotonic() - started, 3),
            "stdout": (error.stdout or "")[-4000:] if isinstance(error.stdout, str) else "",
            "stderr": (error.stderr or "")[-4000:] if isinstance(error.stderr, str) else "",
        }
