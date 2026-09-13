"""Strict, label-free hypothesis schema shared by Phase 5 LLM baselines."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,4}$")


def hypotheses_json_schema(allowed_files: Sequence[str], *, top_k: int) -> dict[str, Any]:
    files = sorted(set(allowed_files))
    if not files:
        raise ValueError("structured hypothesis schema requires at least one source file")
    hypothesis = {
        "type": "object",
        "properties": {
            "candidate_cwe": {"type": "string", "pattern": r"^CWE-[1-9][0-9]{0,4}$"},
            "title": {"type": "string", "minLength": 1, "maxLength": 300},
            "file": {"type": "string", "enum": files},
            "line": {"type": "integer", "minimum": 1},
            "source_symbol": {"type": ["string", "null"], "maxLength": 300},
            "sink_symbol": {"type": ["string", "null"], "maxLength": 300},
            "evidence": {
                "type": "array",
                "items": {"type": "string", "maxLength": 500},
                "maxItems": 8,
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": [
            "candidate_cwe",
            "title",
            "file",
            "line",
            "source_symbol",
            "sink_symbol",
            "evidence",
            "confidence",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "hypotheses": {
                "type": "array",
                "items": hypothesis,
                "maxItems": top_k,
            }
        },
        "required": ["hypotheses"],
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


def _relative_java_path(value: Any, source_root: Path) -> str:
    if not isinstance(value, str) or not value.endswith(".java"):
        raise ValueError("file must be a relative .java path")
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError("file must stay inside the project source root")
    candidate = source_root / pure
    if not candidate.is_file():
        raise ValueError(f"reported source file does not exist: {normalized}")
    return pure.as_posix()


def parse_hypotheses(
    response: str,
    *,
    project_id: str,
    source_root: Path,
    top_k: int,
    generator: str,
) -> list[dict[str, object]]:
    loaded = _json_object(response)
    raw_items = loaded.get("hypotheses")
    if not isinstance(raw_items, list):
        raise ValueError("response.hypotheses must be a list")
    if len(raw_items) > top_k:
        raise ValueError(f"response contains more than top_k={top_k} hypotheses")
    result: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for index, untyped in enumerate(raw_items, start=1):
        if not isinstance(untyped, Mapping):
            raise ValueError("each hypothesis must be an object")
        cwe = untyped.get("candidate_cwe")
        if not isinstance(cwe, str) or not CWE_PATTERN.fullmatch(cwe):
            raise ValueError("candidate_cwe must use canonical CWE-N syntax")
        path = _relative_java_path(untyped.get("file"), source_root)
        line = untyped.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError("line must be a positive integer")
        line_count = len((source_root / path).read_text(errors="replace").splitlines())
        if line > line_count:
            raise ValueError("reported line is outside the source file")
        confidence = untyped.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            raise ValueError("confidence must be numeric")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        title = untyped.get("title")
        if not isinstance(title, str) or not title.strip() or len(title) > 300:
            raise ValueError("title must be non-empty and at most 300 characters")
        evidence = untyped.get("evidence", [])
        if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes)):
            raise ValueError("evidence must be a list")
        if len(evidence) > 8 or any(not isinstance(item, str) for item in evidence):
            raise ValueError("evidence must contain at most eight strings")
        key = (cwe, path, line)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "schema_version": 1,
                "hypothesis_id": f"{project_id}:{index}",
                "project_id": project_id,
                "candidate_cwe": cwe,
                "title": title.strip(),
                "file": path,
                "line": line,
                "source_symbol": _optional_text(untyped.get("source_symbol")),
                "sink_symbol": _optional_text(untyped.get("sink_symbol")),
                "evidence": [str(item)[:500] for item in evidence],
                "confidence": float(confidence),
                "generator": generator,
                "rank": len(result) + 1,
            }
        )
    return result


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 300:
        raise ValueError("symbol fields must be null or strings up to 300 characters")
    return value


def findings_sarif(hypotheses: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for item in hypotheses:
        cwe = str(item["candidate_cwe"])
        rules.setdefault(
            cwe,
            {
                "id": cwe,
                "name": "Zero-hint vulnerability hypothesis",
                "shortDescription": {"text": cwe},
            },
        )
        results.append(
            {
                "ruleId": cwe,
                "level": "warning",
                "message": {"text": str(item["title"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(item["file"])},
                            "region": {"startLine": int(str(item["line"]))},
                        }
                    }
                ],
                "properties": {
                    "project_id": str(item["project_id"]),
                    "hypothesis_id": str(item["hypothesis_id"]),
                    "rank": int(str(item["rank"])),
                    "confidence": float(str(item["confidence"])),
                    "generator": str(item["generator"]),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "MaxVera Phase 5", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
