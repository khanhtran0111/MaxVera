"""Append-only experiment run registry.

A run identifier owns exactly one directory for its lifetime.  The directory
may be populated while the run is active; once a terminal status is written,
the public API refuses every mutation.  Existing identifiers are never reused,
including failed and timed-out runs.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from openiris.config import config_sha256
from openiris.utils.io import append_jsonl, write_json, write_yaml

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FINALIZED_MARKER = "FINALIZED.json"


class RunStatus(StrEnum):
    """Lifecycle states shared by all Phase 0 baseline runners."""

    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"

    @property
    def terminal(self) -> bool:
        return self is not RunStatus.RUNNING


class RunRegistryError(RuntimeError):
    """Base registry error."""


class InvalidRunIdError(RunRegistryError, ValueError):
    """Raised for unsafe or non-portable run identifiers."""


class RunAlreadyExistsError(RunRegistryError, FileExistsError):
    """Raised when an identifier would replace an earlier run."""


class RunFinalizedError(RunRegistryError):
    """Raised when code attempts to mutate a terminal run."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _read_yaml(path: Path) -> dict[str, Any]:
    # Keep registry reads independent from the experiment config loader so a
    # corrupted manifest is reported as a registry error, not merged as config.
    import yaml

    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise RunRegistryError(f"invalid run manifest: {path}")
    return value


def _git_metadata(workspace: Path) -> tuple[str, bool]:
    try:
        commit = subprocess.run(  # noqa: S603,S607 - constant argv, shell disabled
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        dirty_output = subprocess.run(  # noqa: S603,S607
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        return commit, bool(dirty_output.strip())
    except (OSError, subprocess.SubprocessError):
        return "unknown", True


def capture_environment(extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Capture reproducibility metadata without copying secret environment values."""

    value: dict[str, Any] = {
        "captured_at": _now(),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "process": {"pid": os.getpid()},
    }
    if extra:
        value["declared"] = dict(extra)
    return value


@dataclass(slots=True)
class RunHandle:
    """The only supported writer for one run directory."""

    root: Path
    run_id: str

    @property
    def path(self) -> Path:
        return self.root / self.run_id

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.yaml"

    @property
    def status(self) -> RunStatus:
        return RunStatus(str(self.manifest()["status"]))

    @property
    def finalized(self) -> bool:
        return (self.path / _FINALIZED_MARKER).is_file()

    def manifest(self) -> dict[str, Any]:
        return _read_yaml(self.manifest_path)

    def _ensure_mutable(self) -> None:
        if self.finalized or self.status.terminal:
            raise RunFinalizedError(f"run {self.run_id!r} is finalized")

    def artifact_path(self, relative_path: str | Path) -> Path:
        """Resolve an artifact path while preventing traversal outside the run."""

        relative = Path(relative_path)
        if relative.is_absolute():
            raise ValueError("artifact path must be relative to the run directory")
        target = (self.path / relative).resolve()
        try:
            target.relative_to(self.path.resolve())
        except ValueError as exc:
            raise ValueError("artifact path escapes the run directory") from exc
        return target

    def reserve_directory(self, relative_path: str | Path) -> Path:
        self._ensure_mutable()
        target = self.artifact_path(relative_path)
        target.mkdir(parents=True, exist_ok=False)
        return target

    def write_json(self, relative_path: str | Path, value: Any) -> Path:
        self._ensure_mutable()
        target = self.artifact_path(relative_path)
        if target.exists():
            raise FileExistsError(f"refusing to overwrite run artifact: {target}")
        write_json(target, value)
        return target

    def write_yaml(self, relative_path: str | Path, value: Any) -> Path:
        self._ensure_mutable()
        target = self.artifact_path(relative_path)
        if target.exists():
            raise FileExistsError(f"refusing to overwrite run artifact: {target}")
        write_yaml(target, value)
        return target

    def append_usage(self, record: Mapping[str, Any]) -> None:
        self._ensure_mutable()
        value = {"recorded_at": _now(), **dict(record)}
        append_jsonl(self.path / "usage.jsonl", value)

    def append_jsonl(self, relative_path: str | Path, record: Mapping[str, Any]) -> Path:
        """Append one structured record to a run-local JSONL artifact."""

        self._ensure_mutable()
        target = self.artifact_path(relative_path)
        if target.suffix != ".jsonl":
            raise ValueError("append_jsonl only accepts .jsonl artifacts")
        if target.name in {"usage.jsonl", "errors.jsonl"}:
            raise ValueError("use append_usage/append_error for mandatory streams")
        append_jsonl(target, dict(record))
        return target

    def append_error(
        self,
        *,
        code: str,
        message: str,
        stage: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self._ensure_mutable()
        value: dict[str, Any] = {
            "recorded_at": _now(),
            "code": code,
            "message": message,
            "stage": stage,
        }
        if details:
            value["details"] = dict(details)
        append_jsonl(self.path / "errors.jsonl", value)

    def finalize(
        self,
        status: RunStatus | str,
        *,
        metrics: Mapping[str, Any] | None = None,
        summary: Mapping[str, Any] | None = None,
    ) -> None:
        """Atomically record a terminal status and lock the run through this API."""

        self._ensure_mutable()
        normalized = RunStatus(status)
        if not normalized.terminal:
            raise ValueError("final status must be terminal")

        metrics_path = self.path / "metrics.json"
        if metrics_path.exists():
            raise FileExistsError(f"metrics already exist: {metrics_path}")
        write_json(metrics_path, dict(metrics or {}))

        manifest = self.manifest()
        finished_at = _now()
        manifest["status"] = normalized.value
        manifest["finished_at"] = finished_at
        started = datetime.fromisoformat(str(manifest["started_at"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
        manifest["duration_seconds"] = max(0.0, (finished - started).total_seconds())
        if summary:
            manifest["summary"] = dict(summary)
        write_yaml(self.manifest_path, manifest)

        required = (
            "manifest.yaml",
            "config.resolved.yaml",
            "environment.json",
            "metrics.json",
            "usage.jsonl",
            "errors.jsonl",
        )
        missing = [name for name in required if not (self.path / name).is_file()]
        if missing:
            raise RunRegistryError(f"cannot finalize run; missing artifacts: {missing}")

        # The marker is created last.  Its exclusive creation makes terminal
        # state observable and protects against two finalizers.
        marker = self.path / _FINALIZED_MARKER
        with marker.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(
                {"run_id": self.run_id, "status": normalized.value, "finalized_at": finished_at},
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")

    def complete(
        self,
        metrics: Mapping[str, Any] | None = None,
        *,
        summary: Mapping[str, Any] | None = None,
    ) -> None:
        self.finalize(RunStatus.COMPLETE, metrics=metrics, summary=summary)


class RunRegistry:
    """Create and reopen append-only experiment runs."""

    def __init__(self, root: str | Path = "runs", *, workspace: str | Path | None = None) -> None:
        self.root = Path(root).resolve()
        self.workspace = Path(workspace or Path.cwd()).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def validate_run_id(run_id: str) -> str:
        if not _RUN_ID.fullmatch(run_id) or run_id in {".", ".."}:
            raise InvalidRunIdError(
                "run_id must be 1-128 portable characters: letters, digits, '.', '_', '-'"
            )
        return run_id

    def create_run(
        self,
        run_id: str,
        resolved_config: Mapping[str, Any],
        *,
        dataset: Mapping[str, Any] | None = None,
        toolchain: Mapping[str, Any] | None = None,
        model: Mapping[str, Any] | None = None,
        prompt_versions: Mapping[str, str] | None = None,
        environment: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> RunHandle:
        """Create one new RUNNING run; an existing id is always an error."""

        normalized_id = self.validate_run_id(run_id)
        run_path = self.root / normalized_id
        try:
            run_path.mkdir(parents=False, exist_ok=False)
        except FileExistsError as exc:
            raise RunAlreadyExistsError(f"run already exists: {normalized_id}") from exc

        try:
            (run_path / "logs").mkdir()
            (run_path / "commands").mkdir()
            # Empty append-only streams are part of the artifact contract even
            # for a baseline that performs no LLM call or encounters no error.
            (run_path / "usage.jsonl").touch(exist_ok=False)
            (run_path / "errors.jsonl").touch(exist_ok=False)
            resolved = dict(resolved_config)
            write_yaml(run_path / "config.resolved.yaml", resolved)
            write_json(run_path / "environment.json", capture_environment(environment))

            git_commit, dirty = _git_metadata(self.workspace)
            manifest: dict[str, Any] = {
                "schema_version": 1,
                "run_id": normalized_id,
                "status": RunStatus.RUNNING.value,
                "started_at": _now(),
                "finished_at": None,
                "git_commit": git_commit,
                "dirty_worktree": dirty,
                "dataset": dict(dataset or {}),
                "toolchain": dict(toolchain or {}),
                "model": dict(model) if model is not None else None,
                "prompt_versions": dict(prompt_versions or {}),
                "config_sha256": config_sha256(resolved),
            }
            if metadata:
                manifest["metadata"] = dict(metadata)
            write_yaml(run_path / "manifest.yaml", manifest)
            return RunHandle(self.root, normalized_id)
        except BaseException:
            # Never delete a partially initialized run: it is evidence that the
            # identifier was consumed.  A later retry must choose a new id.
            raise

    def open_run(self, run_id: str) -> RunHandle:
        normalized_id = self.validate_run_id(run_id)
        handle = RunHandle(self.root, normalized_id)
        if not handle.manifest_path.is_file():
            raise FileNotFoundError(f"unknown run: {normalized_id}")
        return handle

    def iter_runs(self) -> Iterator[RunHandle]:
        for child in sorted(self.root.iterdir(), key=lambda item: item.name):
            if child.is_dir() and (child / "manifest.yaml").is_file():
                yield RunHandle(self.root, child.name)

    @contextmanager
    def managed_run(
        self,
        run_id: str,
        resolved_config: Mapping[str, Any],
        **metadata: Any,
    ) -> Iterator[RunHandle]:
        """Finalize COMPLETE on success and retain failures for audit."""

        handle = self.create_run(run_id, resolved_config, **metadata)
        start = time.monotonic()
        try:
            yield handle
        except BaseException as exc:
            if not handle.finalized:
                handle.append_error(
                    code=type(exc).__name__,
                    message=str(exc),
                    stage="orchestration",
                )
                handle.finalize(
                    RunStatus.FAILED,
                    metrics={"wall_clock_seconds": time.monotonic() - start},
                )
            raise
        else:
            if not handle.finalized:
                handle.complete({"wall_clock_seconds": time.monotonic() - start})
