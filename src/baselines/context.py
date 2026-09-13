"""Deterministic Java source chunking for the Phase 5 context baselines."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

IGNORED_PARTS = frozenset(
    {".git", ".gradle", ".idea", "build", "dist", "generated", "node_modules", "target"}
)

SECURITY_TERMS: tuple[str, ...] = (
    "request",
    "parameter",
    "header",
    "cookie",
    "inputstream",
    "readobject",
    "deserialize",
    "resolve",
    "normalize",
    "canonical",
    "file",
    "path",
    "processbuilder",
    "runtime.exec",
    "scriptengine",
    "evaluate",
    "render",
    "template",
    "html",
    "escape",
    "encode",
    "sanitize",
    "executequery",
    "statement",
)


@dataclass(frozen=True)
class SourceChunk:
    path: str
    start_line: int
    end_line: int
    text: str

    def serialize(self) -> str:
        numbered = "\n".join(
            f"{self.start_line + offset:06d}: {line}"
            for offset, line in enumerate(self.text.splitlines())
        )
        return f"// FILE: {self.path} LINES: {self.start_line}-{self.end_line}\n{numbered}"


def estimate_tokens(text: str) -> int:
    """Return a conservative dependency-free token estimate for budget planning."""
    return max(1, math.ceil(len(text.encode("utf-8")) / 3.5))


def java_files(source_root: Path, *, max_file_bytes: int) -> list[Path]:
    result: list[Path] = []
    for path in source_root.rglob("*.java"):
        relative = path.relative_to(source_root)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        try:
            if path.is_file() and path.stat().st_size <= max_file_bytes:
                result.append(path)
        except OSError:
            continue
    return sorted(result, key=lambda item: item.relative_to(source_root).as_posix())


def source_chunks(
    source_root: Path,
    *,
    chunk_lines: int,
    overlap_lines: int,
    max_file_bytes: int,
) -> list[SourceChunk]:
    if chunk_lines < 1 or overlap_lines < 0 or overlap_lines >= chunk_lines:
        raise ValueError("chunk_lines must be positive and overlap_lines smaller")
    chunks: list[SourceChunk] = []
    step = chunk_lines - overlap_lines
    for path in java_files(source_root, max_file_bytes=max_file_bytes):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        relative = path.relative_to(source_root).as_posix()
        for offset in range(0, len(lines), step):
            selected = lines[offset : offset + chunk_lines]
            if not selected:
                break
            chunks.append(
                SourceChunk(
                    path=relative,
                    start_line=offset + 1,
                    end_line=offset + len(selected),
                    text="\n".join(selected),
                )
            )
            if offset + chunk_lines >= len(lines):
                break
    return chunks


def _fit(chunks: Iterable[SourceChunk], token_budget: int) -> list[SourceChunk]:
    selected: list[SourceChunk] = []
    used = 0
    for chunk in chunks:
        cost = estimate_tokens(chunk.serialize())
        if cost > token_budget:
            continue
        if used + cost > token_budget:
            break
        selected.append(chunk)
        used += cost
    return selected


def select_raw(chunks: Sequence[SourceChunk], token_budget: int) -> list[SourceChunk]:
    """Sample the repository breadth-first without security-aware ranking."""
    if not chunks:
        return []
    by_path: dict[str, list[SourceChunk]] = {}
    for chunk in chunks:
        by_path.setdefault(chunk.path, []).append(chunk)
    interleaved: list[SourceChunk] = []
    depth = 0
    while True:
        added = False
        for path in sorted(by_path):
            if depth < len(by_path[path]):
                interleaved.append(by_path[path][depth])
                added = True
        if not added:
            break
        depth += 1
    return _fit(interleaved, token_budget)


def _rag_score(chunk: SourceChunk, query_terms: Sequence[str]) -> tuple[int, int, str, int]:
    lowered = chunk.text.casefold()
    term_hits = sum(len(re.findall(re.escape(term.casefold()), lowered)) for term in query_terms)
    distinct = sum(term.casefold() in lowered for term in query_terms)
    # Deterministic tie-breaking; no evaluator label or repository identity is used.
    return distinct, term_hits, chunk.path, -chunk.start_line


def select_text_rag(
    chunks: Sequence[SourceChunk],
    token_budget: int,
    *,
    query_terms: Sequence[str] = SECURITY_TERMS,
) -> list[SourceChunk]:
    ranked = sorted(chunks, key=lambda item: _rag_score(item, query_terms), reverse=True)
    return _fit(ranked, token_budget)


STATIC_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "CWE-22",
        "filesystem_sink",
        "File/path operation",
        re.compile(r"\b(?:File|Paths?)\s*\.|new\s+File\s*\(|\.resolve\s*\(", re.I),
    ),
    (
        "CWE-78",
        "process_sink",
        "Process execution",
        re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec|new\s+ProcessBuilder\s*\(", re.I),
    ),
    (
        "CWE-79",
        "html_sink",
        "HTML/template output",
        re.compile(r"\.write\s*\(|\.print(?:ln)?\s*\(|render\s*\(|setContentType\s*\(", re.I),
    ),
    (
        "CWE-94",
        "code_sink",
        "Dynamic code evaluation",
        re.compile(r"ScriptEngine|\.eval\s*\(|GroovyShell|ExpressionFactory", re.I),
    ),
)


def static_hypotheses(
    chunks: Sequence[SourceChunk], *, project_id: str, top_k: int
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for chunk in chunks:
        for line_offset, line in enumerate(chunk.text.splitlines()):
            line_number = chunk.start_line + line_offset
            for cwe, signal, title, pattern in STATIC_PATTERNS:
                if not pattern.search(line):
                    continue
                key = (cwe, chunk.path, line_number)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "schema_version": 1,
                        "hypothesis_id": f"{project_id}:{len(candidates) + 1}",
                        "project_id": project_id,
                        "candidate_cwe": cwe,
                        "title": title,
                        "file": chunk.path,
                        "line": line_number,
                        "source_symbol": None,
                        "sink_symbol": signal,
                        "evidence": [line.strip()[:500]],
                        "confidence": 0.35,
                        "generator": "static",
                        "rank": 0,
                    }
                )
    by_cwe: dict[str, list[dict[str, object]]] = {}
    for item in sorted(
        candidates,
        key=lambda candidate: (str(candidate["file"]), int(str(candidate["line"]))),
    ):
        by_cwe.setdefault(str(item["candidate_cwe"]), []).append(item)
    ordered: list[dict[str, object]] = []
    depth = 0
    while len(ordered) < top_k:
        added = False
        for cwe in sorted(by_cwe):
            if depth < len(by_cwe[cwe]):
                ordered.append(by_cwe[cwe][depth])
                added = True
                if len(ordered) == top_k:
                    break
        if not added:
            break
        depth += 1
    for rank, item in enumerate(ordered, start=1):
        item["rank"] = rank
    return ordered


def serialize_context(chunks: Sequence[SourceChunk]) -> str:
    return "\n\n".join(chunk.serialize() for chunk in chunks)


def chunk_inventory(chunks: Sequence[SourceChunk]) -> list[Mapping[str, object]]:
    return [
        {
            "path": chunk.path,
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
            "estimated_tokens": estimate_tokens(chunk.serialize()),
        }
        for chunk in chunks
    ]
