"""Bounded subprocesses: terminate descendants on timeout and persist safe diagnostics."""

from pathlib import Path

from maxvera.contracts import redact
from maxvera.orchestration import StageFailure
from src.graphs.program.runner import _run_command


def command(
    args: list[str],
    *,
    cwd: Path,
    log: Path,
    timeout: int,
    env: dict | None = None,
    failure: str = "ANALYSIS_FAILED",
) -> None:
    import os
    import subprocess

    active_env = os.environ if env is None else env
    if Path(args[0]).name == "codeql" and active_env.get("MAXVERA_DATA_ROLE") == "analysis":
        temp = active_env["TMPDIR"]
        cache = str(Path(active_env["HOME"]) / ".codeql")
        args = [*args, "-J=-Djava.io.tmpdir=" + temp, "--common-caches=" + cache]
        if args[1:3] in (["database", "analyze"], ["query", "run"]):
            args += [
                "--no-default-compilation-cache",
                "--compilation-cache=" + cache + "/compilation",
            ]

    try:
        result = _run_command(args, cwd=cwd, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        log.write_text(
            "TIMEOUT\n" + str(redact(e.stdout or "")) + "\n" + str(redact(e.stderr or ""))
        )
        raise StageFailure("TIMEOUT", "subprocess timed out; descendants terminated") from e
    log.write_text(str(redact(result.stdout)) + "\n" + str(redact(result.stderr)))
    if result.returncode:
        raise StageFailure(failure, f"command exited {result.returncode}; see {log.name}")
