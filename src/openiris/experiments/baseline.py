"""Shared result contract for Phase 0 baseline executions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from openiris.experiments.subprocess import ProcessResult, ProcessStatus


class BaselineStatus(StrEnum):
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


def baseline_status(result: ProcessResult) -> BaselineStatus:
    if result.status is ProcessStatus.COMPLETE:
        return BaselineStatus.COMPLETE
    if result.status is ProcessStatus.TIMEOUT:
        return BaselineStatus.TIMEOUT
    return BaselineStatus.FAILED


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    """One project/query observation used to build baseline JSONL results."""

    run_id: str
    baseline: str
    track: str
    project: str
    query: str
    status: BaselineStatus
    runtime_seconds: float
    cve: str | None = None
    cwe: str | None = None
    number_of_paths: int | None = None
    vulnerability_detected: bool | None = None
    exit_code: int | None = None
    command_record: str | None = None
    output_artifacts: tuple[str, ...] = ()
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.baseline not in {"codeql", "iris"}:
            raise ValueError("baseline must be 'codeql' or 'iris'")
        if self.track not in {"legacy", "v2"}:
            raise ValueError("track must be 'legacy' or 'v2'")
        if self.runtime_seconds < 0:
            raise ValueError("runtime cannot be negative")
        if self.number_of_paths is not None and self.number_of_paths < 0:
            raise ValueError("number_of_paths cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["output_artifacts"] = list(self.output_artifacts)
        return value


def count_sarif_paths(path: str | Path) -> int:
    """Count CodeQL paths/findings in SARIF without evaluation ground truth.

    Path-problem results may contain multiple ``codeFlows``.  A result without
    code-flow data is still one finding and therefore contributes one.
    """

    with Path(path).open("r", encoding="utf-8-sig") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("SARIF root must be an object")
    count = 0
    runs = document.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("SARIF runs must be an array")
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            flows = result.get("codeFlows")
            count += len(flows) if isinstance(flows, list) and flows else 1
    return count
