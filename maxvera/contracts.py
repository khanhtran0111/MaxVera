"""Versioned configuration, resource ceilings and safe serialized contracts."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = "2.0"
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
ORACLE_PATTERN = re.compile(r"CVE-\d{4}-\d+|(?:target|true|ground_truth)[_-]cwe", re.I)
SECRET_KEYS = re.compile(r"api.?key|authorization|password|secret|access.?token", re.I)


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def safe_id(value: str) -> str:
    if not ID_PATTERN.fullmatch(value) or value in {".", ".."}:
        raise ValueError("invalid opaque identifier or run ID")
    return value


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if SECRET_KEYS.search(str(k)) else redact(v) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"(?i)(?:Bearer\s+\S+|sk-(?:or-v1-)?[a-zA-Z0-9_-]{12,})", "[REDACTED]", value)
    return value


def require_keys(value: dict, allowed: set[str], name: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unknown/protected {name} keys: {sorted(unknown)}")


@dataclass(frozen=True)
class Budgets:
    max_calls_per_case: int = 30
    max_input_tokens_per_case: int = 160000
    max_output_tokens_per_case: int = 60000
    max_cost_usd_per_case: float = 1.0
    timeout_case_s: int = 7200

    def __post_init__(self):
        for f in dataclasses.fields(self):
            if isinstance(getattr(self, f.name), bool) or getattr(self, f.name) <= 0:
                raise ValueError(f"{f.name} must be positive")


@dataclass(frozen=True)
class Runtime:
    project_workers: int = 1
    llm_concurrency: int = 1
    timeout_case_s: int = 7200
    dry_run_default: bool = True

    def __post_init__(self):
        if self.project_workers != 1 or self.llm_concurrency != 1:
            raise ValueError("v2 core requires one project worker and one LLM request")
        if self.timeout_case_s <= 0:
            raise ValueError("timeout must be positive")


@dataclass(frozen=True)
class PipelineConfig:
    pipeline: str
    runtime: Runtime = field(default_factory=Runtime)
    budgets: Budgets = field(default_factory=Budgets)
    dataset: dict = field(default_factory=dict)
    codeql: dict = field(default_factory=dict)
    llm: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    reproduction: dict = field(default_factory=dict)
    research: dict = field(default_factory=dict)
    variants: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> PipelineConfig:
        raw = yaml.safe_load(path.read_text())
        if not isinstance(raw, dict):
            raise ValueError("config must be a mapping")
        if "extends" in raw:
            base = (path.parent / raw.pop("extends")).resolve()
            defaults = yaml.safe_load(base.read_text())
            if not isinstance(defaults, dict) or "extends" in defaults:
                raise ValueError("runtime defaults must be a mapping without recursion")
            raw = {
                **defaults,
                **{
                    k: {**defaults.get(k, {}), **v} if isinstance(v, dict) else v
                    for k, v in raw.items()
                },
            }
        require_keys(raw, {f.name for f in dataclasses.fields(cls)}, "config")
        if raw.get("pipeline") not in {"reproduce", "research"}:
            raise ValueError("pipeline must be reproduce or research")
        for name in (
            "runtime",
            "budgets",
            "dataset",
            "codeql",
            "llm",
            "evidence",
            "reproduction",
            "research",
            "variants",
        ):
            if not isinstance(raw.get(name, {}), dict):
                raise ValueError(f"{name} must be a mapping")
        require_keys(
            raw.get("dataset", {}),
            {
                "config",
                "analysis_manifest",
                "oracle_manifest",
                "labels",
                "fix_locations",
                "expected_cases",
                "split",
                "track",
            },
            "dataset",
        )
        require_keys(
            raw.get("codeql", {}),
            {
                "repro_binary",
                "research_binary",
                "reference_suite",
                "generic_suite",
                "per_query_timeout_s",
                "ram_mb",
                "threads",
                "repro_java_all_version",
                "compatibility",
            },
            "codeql",
        )
        require_keys(
            raw.get("llm", {}),
            {
                "model_config",
                "provider_route",
                "max_output_tokens",
                "model",
                "temperature",
                "top_p",
                "request_timeout_s",
                "max_retries",
            },
            "llm",
        )
        require_keys(
            raw.get("evidence", {}),
            {"top_k", "max_graph_hops", "max_context_tokens_per_call"},
            "evidence",
        )
        require_keys(
            raw.get("research", {}),
            {"default_variant", "graph_signal_approved", "max_nodes", "max_edges"},
            "research",
        )
        require_keys(
            raw.get("reproduction", {}),
            {"iris_root", "raw_root", "toolchains", "iris_commit", "dataset_commit"},
            "reproduction",
        )
        if raw["pipeline"] == "research":
            if (
                "graph_signal_approved" in raw.get("research", {})
                and type(raw["research"]["graph_signal_approved"]) is not bool
            ):
                raise ValueError("graph_signal_approved must be boolean")
            ds = raw.get("dataset", {})
            if set(ds) & {"oracle_manifest", "labels", "fix_locations"}:
                raise ValueError("protected oracle inputs in research config")
            encoded = json.dumps(raw)
            if ORACLE_PATTERN.search(encoded) or "evaluator_only" in encoded:
                raise ValueError("protected oracle metadata in research config")
        try:
            raw["runtime"] = Runtime(**raw.get("runtime", {}))
            raw["budgets"] = Budgets(**raw.get("budgets", {}))
        except TypeError as e:
            raise ValueError(f"unknown runtime/budget key: {e}") from e
        return cls(**raw)

    def resolved(self) -> dict:
        return redact(dataclasses.asdict(self))
