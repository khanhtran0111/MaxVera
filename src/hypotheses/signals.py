"""Deterministic, label-free Java signals for Phase 6 hypothesis generation."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Any

from src.baselines.context import java_files

PATTERN_VERSION = "phase6-java-signals-v1"
HINT_LITERAL = re.compile(r"\b(?:CVE-\d{4}-\d+|CWE-\d+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class SignalRule:
    rule_id: str
    role: str
    candidate_cwes: tuple[str, ...]
    title: str
    pattern: Pattern[str]
    weight: float


RULES: tuple[SignalRule, ...] = (
    SignalRule(
        "source.http.parameter",
        "source",
        (),
        "HTTP-controlled input",
        re.compile(
            r"(?:getParameter|getHeader|getCookies|getQueryString)\s*\(|"
            r"@(?:RequestParam|PathVariable|RequestBody)\b",
            re.I,
        ),
        0.22,
    ),
    SignalRule(
        "source.external.runtime",
        "source",
        (),
        "Externally controlled runtime input",
        re.compile(r"System\s*\.\s*(?:getenv|getProperty)\s*\(|\bargs\s*\[", re.I),
        0.16,
    ),
    SignalRule(
        "source.deserialization",
        "source",
        ("CWE-94",),
        "Deserialized input",
        re.compile(r"\.(?:readObject|readValue|readUnshared|decode)\s*\(", re.I),
        0.2,
    ),
    SignalRule(
        "sink.path.file-construction",
        "sink",
        ("CWE-22",),
        "User-influenced filesystem path",
        re.compile(
            r"new\s+File\s*\(|(?:Paths?|FileSystems\s*\.\s*getDefault\s*\(\))"
            r"\s*\.\s*(?:get|resolve)\s*\(|\.resolve\s*\(",
            re.I,
        ),
        0.5,
    ),
    SignalRule(
        "sink.path.archive",
        "sink",
        ("CWE-22",),
        "Archive entry path write",
        re.compile(r"(?:ZipEntry|TarArchiveEntry|getNextEntry|\.getName\s*\(\))", re.I),
        0.42,
    ),
    SignalRule(
        "sink.process.execution",
        "sink",
        ("CWE-78",),
        "Operating-system command execution",
        re.compile(
            r"Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec\s*\(|"
            r"new\s+ProcessBuilder\s*\(",
            re.I,
        ),
        0.7,
    ),
    SignalRule(
        "sink.html.response",
        "sink",
        ("CWE-79",),
        "Unescaped web or template output",
        re.compile(
            r"(?:getWriter\s*\(\)\s*\.)?(?:write|print|println)\s*\(|"
            r"(?:render|renderTemplate|setAttribute)\s*\(",
            re.I,
        ),
        0.42,
    ),
    SignalRule(
        "sink.code.evaluation",
        "sink",
        ("CWE-94",),
        "Dynamic code or expression evaluation",
        re.compile(
            r"(?:ScriptEngine|GroovyShell|ExpressionFactory|"
            r"SpelExpressionParser|MVEL)\b|\.eval\s*\(",
            re.I,
        ),
        0.68,
    ),
    SignalRule(
        "sanitizer.path",
        "sanitizer",
        ("CWE-22",),
        "Path normalization or canonicalization",
        re.compile(r"\.(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile)\s*\(", re.I),
        0.2,
    ),
    SignalRule(
        "sanitizer.output",
        "sanitizer",
        ("CWE-79",),
        "Output escaping or encoding",
        re.compile(r"(?:escapeHtml|htmlEncode|encodeForHTML|sanitize)\s*\(", re.I),
        0.2,
    ),
    SignalRule(
        "boundary.public-api",
        "boundary",
        (),
        "Public or framework entry point",
        re.compile(
            r"\bpublic\s+(?:static\s+)?[\w<>,?\[\].]+\s+\w+\s*\(|"
            r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b",
            re.I,
        ),
        0.08,
    ),
)

PRECONDITIONS: Mapping[str, tuple[str, ...]] = {
    "CWE-22": ("An external value can influence a filesystem path.",),
    "CWE-78": ("An external value can influence a process command or argument.",),
    "CWE-79": ("Untrusted content can reach a browser-visible response.",),
    "CWE-94": ("Untrusted content can reach a dynamic evaluator or code loader.",),
}


def _stable_id(*parts: object) -> str:
    value = "\0".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(value).hexdigest()[:20]


def _safe_evidence(line: str) -> str:
    return HINT_LITERAL.sub("[REDACTED_HINT]", " ".join(line.strip().split()))[:500]


def _code_fragment(line: str) -> str:
    """Remove the common single-line comment form before signal matching."""
    return line.split("//", 1)[0]


def _symbol(fragment: str) -> str | None:
    matches = re.findall(r"([A-Za-z_$][\w$]*)\s*\(", fragment)
    return matches[-1] if matches else None


def scan_project(
    source_root: Path,
    *,
    project_id: str,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extract ordered source/sink/sanitizer/boundary signals from Java source."""
    signals: list[dict[str, Any]] = []
    for path in java_files(source_root, max_file_bytes=max_file_bytes):
        relative = path.relative_to(source_root).as_posix()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_number, raw_line in enumerate(lines, start=1):
            fragment = _code_fragment(raw_line)
            if not fragment.strip():
                continue
            for rule in RULES:
                if not rule.pattern.search(fragment):
                    continue
                signals.append(
                    {
                        "schema_version": 1,
                        "signal_id": "sig_"
                        + _stable_id(project_id, relative, line_number, rule.rule_id),
                        "project_id": project_id,
                        "pattern_version": PATTERN_VERSION,
                        "rule_id": rule.rule_id,
                        "role": rule.role,
                        "candidate_cwes": list(rule.candidate_cwes),
                        "title": rule.title,
                        "file": relative,
                        "line": line_number,
                        "symbol": _symbol(fragment),
                        "evidence": _safe_evidence(raw_line),
                        "weight": rule.weight,
                    }
                )
    return sorted(
        signals,
        key=lambda item: (str(item["file"]), int(item["line"]), str(item["rule_id"])),
    )


def _compatible(signal: Mapping[str, Any], cwe: str) -> bool:
    families = signal.get("candidate_cwes", [])
    return not families or cwe in families


def _nearest(
    signals: Sequence[Mapping[str, Any]],
    sink: Mapping[str, Any],
    *,
    role: str,
    cwe: str,
    window_lines: int,
    limit: int,
) -> list[Mapping[str, Any]]:
    same_file = [
        signal
        for signal in signals
        if signal.get("role") == role
        and signal.get("file") == sink.get("file")
        and _compatible(signal, cwe)
        and abs(int(signal["line"]) - int(sink["line"])) <= window_lines
    ]
    return sorted(
        same_file,
        key=lambda item: (abs(int(item["line"]) - int(sink["line"])), int(item["line"])),
    )[:limit]


def _location(signal: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "file": str(signal["file"]),
        "line": int(signal["line"]),
        "role": str(signal["role"]),
        "symbol": signal.get("symbol"),
    }


def generate_candidates(
    signals: Sequence[Mapping[str, Any]],
    *,
    project_id: str,
    source_window_lines: int,
    sanitizer_window_lines: int,
    max_candidates: int,
) -> list[dict[str, Any]]:
    """Ground hypotheses at sinks and rank them without evaluator information."""
    candidates: list[dict[str, Any]] = []
    for sink in (signal for signal in signals if signal.get("role") == "sink"):
        for cwe in sink.get("candidate_cwes", []):
            cwe = str(cwe)
            sources = _nearest(
                signals,
                sink,
                role="source",
                cwe=cwe,
                window_lines=source_window_lines,
                limit=3,
            )
            boundaries = _nearest(
                signals,
                sink,
                role="boundary",
                cwe=cwe,
                window_lines=source_window_lines,
                limit=1,
            )
            sanitizers = _nearest(
                signals,
                sink,
                role="sanitizer",
                cwe=cwe,
                window_lines=sanitizer_window_lines,
                limit=3,
            )
            score = float(sink["weight"])
            if sources:
                score += max(float(source["weight"]) for source in sources)
            if boundaries:
                score += float(boundaries[0]["weight"])
            if sanitizers:
                score -= max(float(item["weight"]) for item in sanitizers)
            score = round(min(0.99, max(0.01, score)), 4)
            evidence_signals = [sink, *sources, *boundaries, *sanitizers]
            hypothesis_id = "hyp_" + _stable_id(
                project_id, cwe, sink["file"], sink["line"], sink["rule_id"]
            )
            candidates.append(
                {
                    "schema_version": 1,
                    "hypothesis_id": hypothesis_id,
                    "project_id": project_id,
                    "candidate_cwe": [cwe],
                    "source_candidates": [_location(item) for item in sources],
                    "sink_candidates": [_location(sink)],
                    "preconditions": list(PRECONDITIONS.get(cwe, ())),
                    "locations": [_location(item) for item in [sink, *sources]],
                    "generator": "static_rules",
                    "score": score,
                    "rank": 0,
                    "provenance": [
                        {
                            "kind": "source_signal",
                            "signal_id": str(item["signal_id"]),
                            "rule_id": str(item["rule_id"]),
                            "pattern_version": PATTERN_VERSION,
                            "file": str(item["file"]),
                            "line": int(item["line"]),
                            "evidence": str(item["evidence"]),
                        }
                        for item in evidence_signals
                    ],
                }
            )
    ordered = sorted(
        candidates,
        key=lambda item: (
            -float(item["score"]),
            str(item["candidate_cwe"][0]),
            str(item["sink_candidates"][0]["file"]),
            int(item["sink_candidates"][0]["line"]),
            str(item["hypothesis_id"]),
        ),
    )[:max_candidates]
    for rank, item in enumerate(ordered, start=1):
        item["rank"] = rank
    return ordered


def select_top_k(candidates: Sequence[Mapping[str, Any]], top_k: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for rank, candidate in enumerate(candidates[:top_k], start=1):
        item = dict(candidate)
        item["rank"] = rank
        selected.append(item)
    return selected
