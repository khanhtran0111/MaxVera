"""Bounded subprocesses: terminate descendants on timeout and persist safe diagnostics."""

import codecs
import contextlib
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path

from maxvera.contracts import redact
from maxvera.orchestration import StageFailure


class _SafeLog:
    """Bounded diagnostics, including tokens split across pipe-read boundaries."""

    def __init__(self, handle):
        self.handle = handle
        self.token = ""
        self.oversized = False
        self.bearer = False
        self.written = 0
        self.limited = False

    def _write(self, value):
        if self.limited:
            return
        encoded = value.encode("utf-8")
        remaining = 16 * 1024 * 1024 - self.written
        if len(encoded) > remaining:
            self.handle.write(encoded[:remaining].decode("utf-8", errors="ignore"))
            self.handle.write("\n[LOG_LIMIT_REACHED; FURTHER_DIAGNOSTICS_OMITTED]\n")
            self.limited = True
        else:
            self.handle.write(value)
            self.written += len(encoded)
        self.handle.flush()

    def _flush_token(self):
        if self.oversized:
            self._write("[OVERSIZED_TOKEN_OMITTED]")
            self.bearer = False
        elif self.token:
            if self.bearer:
                self._write("[REDACTED]")
                self.bearer = False
            elif self.token.lower().endswith("bearer"):
                self._write("[REDACTED]")
                self.bearer = True
            else:
                self._write(str(redact(self.token)))
        self.token = ""
        self.oversized = False

    def feed(self, value):
        for part in re.findall(r"\s+|\S+", value):
            if part[0].isspace():
                self._flush_token()
                self._write(part)
            elif not self.oversized:
                self.token += part
                if len(self.token) > 65536:
                    self.token = ""
                    self.oversized = True

    def finish(self):
        self._flush_token()


def _terminate(process):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)
    # The leader may exit before descendants which inherited its pipe/cache lock.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def command(
    args: list[str],
    *,
    cwd: Path,
    log: Path,
    timeout: int,
    env: dict | None = None,
    failure: str = "ANALYSIS_FAILED",
    min_free_gib: float | None = None,
) -> None:
    active_env = os.environ if env is None else env
    minimum = (
        float(active_env.get("MAXVERA_MIN_FREE_DISK_GIB", 0))
        if min_free_gib is None
        else min_free_gib
    )
    if isinstance(minimum, bool) or not math.isfinite(minimum) or minimum < 0:
        raise ValueError("minimum free disk space must be nonnegative and finite")
    if Path(args[0]).name == "codeql" and active_env.get("MAXVERA_DATA_ROLE") == "analysis":
        temp = active_env["TMPDIR"]
        cache = str(Path(active_env["HOME"]) / ".codeql")
        args = [*args, "-J=-Djava.io.tmpdir=" + temp, "--common-caches=" + cache]
        if args[1:3] in (["database", "analyze"], ["query", "run"]):
            args += [
                "--no-default-compilation-cache",
                "--compilation-cache=" + cache + "/compilation",
            ]

    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        output = _SafeLog(handle)
        if shutil.disk_usage(cwd).free < minimum * 1024**3:
            output.feed("RESOURCE_EXHAUSTED: disk reserve reached before command\n")
            raise StageFailure("RESOURCE_EXHAUSTED", "disk reserve reached before command")
        process = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        deadline = time.monotonic() + timeout
        next_disk_check = time.monotonic()
        try:
            while process.poll() is None or selector.get_map():
                now = time.monotonic()
                if now >= deadline:
                    raise StageFailure("TIMEOUT", "subprocess timed out; descendants terminated")
                if now >= next_disk_check:
                    if shutil.disk_usage(cwd).free < minimum * 1024**3:
                        raise StageFailure(
                            "RESOURCE_EXHAUSTED", "disk reserve reached during command"
                        )
                    next_disk_check = now + 1
                for key, _ in selector.select(timeout=min(0.2, deadline - now)):
                    block = os.read(key.fd, 8192)
                    if block:
                        output.feed(decoder.decode(block))
                    else:
                        selector.unregister(key.fileobj)
            output.feed(decoder.decode(b"", final=True))
            output.finish()
            if process.wait():
                raise StageFailure(failure, f"command exited {process.returncode}; see {log.name}")
        except BaseException as error:
            _terminate(process)
            output.finish()
            if isinstance(error, StageFailure):
                output.feed(f"\n{error.status}: {error}\n")
                output.finish()
            raise
        finally:
            selector.close()
            process.stdout.close()
