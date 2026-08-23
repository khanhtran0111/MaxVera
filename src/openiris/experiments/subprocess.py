"""Auditable, shell-free subprocess execution.

The executor deliberately accepts only an argument sequence.  stdout and
stderr are streamed directly to files so output produced before a timeout is
not lost and large CodeQL logs do not have to fit in memory.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import ExitStack, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class ProcessStatus(StrEnum):
    """Normalized outcome of one external command."""

    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SPAWN_ERROR = "SPAWN_ERROR"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_json_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Serializable result and retained-output locations for a command."""

    status: ProcessStatus
    argv: tuple[str, ...]
    cwd: str
    started_at: str
    finished_at: str
    duration_seconds: float
    exit_code: int | None
    timeout_seconds: float | None
    stdout_path: str
    stderr_path: str
    record_path: str
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status is ProcessStatus.COMPLETE

    @property
    def timed_out(self) -> bool:
        return self.status is ProcessStatus.TIMEOUT

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["argv"] = list(self.argv)
        return value


class ProcessExecutor:
    """Execute commands without a shell and preserve an immutable audit trail."""

    def __init__(self, default_timeout_seconds: float | None = None) -> None:
        if default_timeout_seconds is not None and default_timeout_seconds <= 0:
            raise ValueError("default timeout must be greater than zero")
        self.default_timeout_seconds = default_timeout_seconds

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        artifact_dir: str | Path,
        cwd: str | Path | None = None,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
        stdin_path: str | Path | None = None,
    ) -> ProcessResult:
        """Run ``argv`` and retain command metadata, stdout, and stderr.

        ``artifact_dir`` must not already contain command artifacts.  This
        prevents a retry from silently replacing evidence from an earlier
        process.  Environment overrides are intentionally not serialized,
        because API keys and access tokens commonly live there.
        """

        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise TypeError("argv must be a sequence of arguments, never a shell string")
        normalized_argv = tuple(os.fspath(argument) for argument in argv)
        if not normalized_argv or any(not argument for argument in normalized_argv):
            raise ValueError("argv must contain at least one non-empty argument")

        timeout = self.default_timeout_seconds if timeout_seconds is None else timeout_seconds
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        output_dir = Path(artifact_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = output_dir / "stdout.log"
        stderr_path = output_dir / "stderr.log"
        record_path = output_dir / "command.json"
        for target in (stdout_path, stderr_path, record_path):
            if target.exists():
                raise FileExistsError(f"refusing to overwrite command artifact: {target}")

        command_cwd = Path(cwd or Path.cwd()).resolve()
        if not command_cwd.is_dir():
            raise NotADirectoryError(command_cwd)

        child_env = None
        if env is not None:
            child_env = os.environ.copy()
            child_env.update({str(key): str(value) for key, value in env.items()})

        started_at = _utc_now()
        start = time.monotonic()
        status = ProcessStatus.SPAWN_ERROR
        exit_code: int | None = None
        error: str | None = None
        process: subprocess.Popen[bytes] | None = None

        try:
            with ExitStack() as stack:
                stdin_handle = (
                    stack.enter_context(Path(stdin_path).open("rb"))
                    if stdin_path is not None
                    else subprocess.DEVNULL
                )
                stdout_handle = stack.enter_context(stdout_path.open("xb"))
                stderr_handle = stack.enter_context(stderr_path.open("xb"))
                popen_options: dict[str, Any] = {}
                if os.name == "nt":
                    popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                else:
                    popen_options["start_new_session"] = True
                process = subprocess.Popen(  # noqa: S603 - argv is passed without a shell
                    normalized_argv,
                    cwd=command_cwd,
                    env=child_env,
                    stdin=stdin_handle,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    **popen_options,
                )
                try:
                    exit_code = process.wait(timeout=timeout)
                    status = ProcessStatus.COMPLETE if exit_code == 0 else ProcessStatus.FAILED
                except subprocess.TimeoutExpired:
                    status = ProcessStatus.TIMEOUT
                    error = f"command exceeded timeout of {timeout} seconds"
                    self._terminate(process)
                    exit_code = process.returncode
        except (OSError, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            # A failed spawn still produces both output files.  If failure
            # happened before either context manager opened, create the
            # missing file without replacing any partial evidence.
            stdout_path.touch(exist_ok=True)
            stderr_path.touch(exist_ok=True)

        duration = time.monotonic() - start
        result = ProcessResult(
            status=status,
            argv=normalized_argv,
            cwd=str(command_cwd),
            started_at=started_at,
            finished_at=_utc_now(),
            duration_seconds=duration,
            exit_code=exit_code,
            timeout_seconds=timeout,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            record_path=str(record_path),
            error=error,
        )
        _write_json_exclusive(record_path, result.to_dict())
        return result

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        """Best-effort termination of the command's process group."""

        try:
            if os.name == "nt":
                process.terminate()
            else:
                os.killpg(process.pid, signal.SIGTERM)  # type: ignore[attr-defined]
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
            except OSError:
                pass
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
