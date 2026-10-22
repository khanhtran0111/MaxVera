"""Immutable, versioned analyzer records; labels never belong to this schema."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from maxvera.contracts import safe_id
from maxvera.graph import relative_file


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(v) for v in value)
    return value


def _thaw(value):
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class Candidate:
    document: Mapping[str, Any]

    def __post_init__(self):
        d = self.document
        if d.get("schema_version") != "2.0":
            raise ValueError("candidate schema version requires explicit migration")
        if set(d) & {
            "true_cwe",
            "ground_truth_cwe",
            "cve_id",
            "patch",
            "fixed_locations",
            "target_cwe",
        }:
            raise ValueError("protected labels in analyzer schema")
        for key in ("case_id", "candidate_id", "run_id"):
            safe_id(d[key])
        if not d.get("snapshot_id"):
            raise ValueError("candidate snapshot provenance missing")
        if d.get("score_type") != "UN-CALIBRATED-RANKING":
            raise ValueError("candidate score must remain explicitly uncalibrated")
        if not isinstance(d.get("score"), (int, float)) or not math.isfinite(d["score"]):
            raise ValueError("finite ranking score required")
        rank = d.get("rank_pre_llm")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            raise ValueError("candidate rank must be positive")
        if d.get("verification_status") not in {
            "FLOW_FOUND",
            "NO_FLOW_FOUND",
            "QUERY_INVALID",
            "UNSUPPORTED_SPEC",
            "TIMEOUT",
            "NOT_ATTEMPTED",
        }:
            raise ValueError("unknown verification status")
        for loc in d.get("locations", []):
            relative_file(loc["file"])
            if not 1 <= loc["start_line"] <= loc["end_line"]:
                raise ValueError("invalid candidate location span")
        if not d.get("locations") or not d.get("origin_generators"):
            raise ValueError("candidate requires evidence locations and generator provenance")
        object.__setattr__(self, "document", _freeze(d))

    def to_dict(self):
        return _thaw(self.document)


@dataclass(frozen=True)
class Finding(Candidate):
    def __post_init__(self):
        super().__post_init__()
        safe_id(self.document["finding_id"])
        if self.document.get("decision") not in {
            "REVIEW",
            "SUPPORTED",
            "NOT_SUPPORTED",
            "UNRESOLVED",
        }:
            raise ValueError("unknown finding decision")
