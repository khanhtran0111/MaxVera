"""Typed helpers for the mandatory usage and error JSONL streams."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from openiris.experiments.registry import RunHandle


@dataclass(frozen=True, slots=True)
class UsageRecord:
    """Cost and latency accounting for one model or external-tool call."""

    purpose: str
    model: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    estimated_cost_usd: float = 0.0
    hypothesis_id: str | None = None
    project: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.prompt_tokens < 0 or self.completion_tokens < 0:
            raise ValueError("token counts cannot be negative")
        if self.latency_ms < 0 or self.estimated_cost_usd < 0:
            raise ValueError("latency and cost cannot be negative")


@dataclass(frozen=True, slots=True)
class ErrorRecord:
    """Normalized failure record retained even when a run cannot complete."""

    code: str
    message: str
    stage: str
    details: dict[str, Any] = field(default_factory=dict)


class RunArtifactLogger:
    """Write typed records through a run handle's immutability guard."""

    def __init__(self, run: RunHandle) -> None:
        self.run = run

    def usage(self, record: UsageRecord) -> None:
        self.run.append_usage(asdict(record))

    def error(self, record: ErrorRecord) -> None:
        self.run.append_error(
            code=record.code,
            message=record.message,
            stage=record.stage,
            details=record.details,
        )
