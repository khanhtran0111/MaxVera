"""Versioned prompts for Phase 10 graph-grounded specification synthesis."""

from __future__ import annotations

import hashlib

PROMPT_VERSION = "phase10-graph-spec-v1"

SYSTEM_PROMPT = """You are a Java security specification synthesizer.
Use only the supplied graph records. The repository identity, advisory, patch, CVE,
ground-truth weakness, and published findings are unavailable and must not be inferred.
Select node IDs exactly as provided. A specification is an unverified candidate, not a
vulnerability verdict. Return only the strict JSON object required by the response schema.
"""


def user_prompt(context: str) -> str:
    return f"""Synthesize one CodeQL-oriented specification for the requested hypothesis.

Requirements:
- select at least one grounded source and one grounded sink;
- use Program nodes for repository-specific locations when available;
- use Security nodes only for the matching semantic role;
- include sanitizers/propagators only when supported by a supplied node;
- keep preconditions evidence-grounded and explicitly cite node IDs;
- do not invent files, symbols, node IDs, facts, or verification results.

COMPACT GRAPH CONTEXT (JSONL):
{context}
"""


def repair_prompt(error: str) -> str:
    bounded = " ".join(error.split())[:500]
    return f"""The previous response failed local schema/semantic/compile validation:
{bounded}

Return a complete replacement JSON object. Use only node IDs in the original context,
preserve the requested hypothesis/CWE, and remove unsupported role assignments. Do not
claim that CodeQL verified a path.
"""


def prompt_sha256() -> str:
    material = "\0".join((PROMPT_VERSION, SYSTEM_PROMPT, user_prompt(""), repair_prompt("")))
    return hashlib.sha256(material.encode()).hexdigest()
