"""Durable per-case DAG execution with independent branches and immutable outputs."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from maxvera.contracts import SCHEMA_VERSION, digest, redact, safe_id
from src.common.provenance import sha256_file, utc_now
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums


class StageFailure(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Stage:
    name: str
    action: Callable
    dependencies: tuple[str, ...] = ()
    paid: bool = False
    checkpoint_validator: Callable | None = None


@dataclass
class Context:
    root: Path
    run_dir: Path
    stage_dir: Path
    case: dict
    config: dict
    results: dict
    deadline: float = float("inf")

    def remaining_seconds(self, cap: int) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise StageFailure("TIMEOUT", "case deadline exhausted before new work")
        return min(cap, max(1, int(remaining))) if remaining != float("inf") else cap

    def output(self, stage: str) -> dict:
        return self.results[stage].get("result", {})


def verify_checksums(path: Path) -> None:
    """Verify immutable file inventory with bounded RAM, including large DB trees.

    A disk-backed inventory avoids two Python sets proportional to every file in
    the run.  The temporary database lives outside the frozen output directory.
    Symlinks are never followed, including unindexed links to directories.
    """
    import re
    import sqlite3
    import tempfile

    index = path / "checksums.sha256"
    if path.is_symlink() or index.is_symlink():
        raise ValueError("unsafe checksum path: symlink")
    if not index.is_file():
        raise ValueError("missing frozen run checksum index")
    path = path.resolve()
    index = path / "checksums.sha256"
    with tempfile.TemporaryDirectory(prefix="maxvera-integrity-", dir="/tmp") as temp:
        connection = sqlite3.connect(str(Path(temp) / "inventory.sqlite"))
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute("CREATE TABLE inventory (path TEXT PRIMARY KEY, seen INTEGER)")
            with index.open(encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    # write_checksums represents an empty inventory as one blank line.
                    if line == "\n":
                        continue
                    fields = line.rstrip("\n").split("  ", 1)
                    if len(fields) != 2 or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None:
                        raise ValueError(f"malformed checksum index line {number}")
                    expected, rel = fields
                    relative = Path(rel)
                    if (
                        not rel
                        or relative.is_absolute()
                        or relative.as_posix() != rel
                        or ".." in relative.parts
                        or rel == "checksums.sha256"
                    ):
                        raise ValueError("unsafe checksum path")
                    target = path
                    for part in relative.parts:
                        target = target / part
                        if target.is_symlink():
                            raise ValueError("unsafe checksum path: symlink")
                    if not target.is_file() or sha256_file(target) != expected:
                        raise ValueError(f"checksum integrity mismatch: {rel}")
                    try:
                        connection.execute("INSERT INTO inventory VALUES (?, 0)", (rel,))
                    except sqlite3.IntegrityError as error:
                        raise ValueError(f"duplicate checksum path: {rel}") from error

            def scan(directory):
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            raise ValueError("unsafe checksum inventory symlink")
                        if entry.is_dir(follow_symlinks=False):
                            scan(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            target = Path(entry.path)
                            if target == index:
                                continue
                            rel = target.relative_to(path).as_posix()
                            cursor = connection.execute(
                                "UPDATE inventory SET seen=1 WHERE path=?", (rel,)
                            )
                            if cursor.rowcount != 1:
                                raise ValueError(f"checksum file inventory mismatch: {rel}")
                        else:
                            raise ValueError("unsafe checksum inventory non-regular entry")

            scan(path)
            if connection.execute("SELECT 1 FROM inventory WHERE seen=0 LIMIT 1").fetchone():
                raise ValueError("checksum file inventory mismatch")
        finally:
            connection.close()


class Orchestrator:
    def __init__(
        self,
        root: Path,
        pipeline: str,
        run_id: str,
        config: dict,
        cases: list[dict],
        stages: list[Stage],
        *,
        implementation_hash: str,
        resume: bool = False,
        mode: str = "full",
        finalizer: Callable | None = None,
        isolation: Callable | None = None,
    ):
        if pipeline not in {"reproduction", "research"} or mode not in {"full", "smoke"}:
            raise ValueError("invalid pipeline/mode")
        self.root = root.resolve()
        self.path = (
            self.root / "results" / "_smoke" / pipeline / safe_id(run_id)
            if mode == "smoke"
            else self.root / "results" / pipeline / safe_id(run_id)
        )
        if self.path.is_symlink() or not self.path.resolve().is_relative_to(self.root):
            raise ValueError("unsafe run path")
        ids = [safe_id(c["case_id"]) for c in cases]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("empty or duplicate case selection")
        names = []
        for stage in stages:
            safe_id(stage.name)
            if stage.name in names or not set(stage.dependencies) <= set(names):
                raise ValueError("DAG requires unique stages in dependency order")
            names.append(stage.name)
        self.config, self.cases, self.stages = config, cases, stages
        self.resume, self.finalizer = resume, finalizer
        self.isolation = isolation
        self.identity = {
            "schema_version": SCHEMA_VERSION,
            "pipeline": pipeline,
            "mode": mode,
            "run_id": run_id,
            "config_hash": digest(config),
            "input_hash": digest(cases),
            "implementation_hash": implementation_hash,
            "dag": [
                {"name": s.name, "dependencies": s.dependencies, "paid": s.paid} for s in stages
            ],
        }
        self.identity_hash = digest(self.identity)

    def _checkpoint_valid(self, folder: Path, record: dict) -> bool:
        for rel, expected in record.get("artifact_hashes", {}).items():
            p = folder / rel
            if not p.resolve().is_relative_to(folder.resolve()) or p.is_symlink():
                return False
            if not p.is_file() or sha256_file(p) != expected:
                return False
        return True

    def execute(self) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Locks live outside the immutable run; flock is released on process death.
        lock_dir = self.path.parent / ".locks"
        lock_dir.mkdir(exist_ok=True)
        with (lock_dir / self.path.name).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e:
                raise ValueError("run already locked by another process") from e
            return self._execute_locked()

    def _execute_locked(self) -> str:
        if self.path.exists():
            if not self.resume:
                raise ValueError("immutable run ID already exists; use --resume")
            manifest = json.loads((self.path / "manifest.json").read_text())
            if manifest["identity_hash"] != self.identity_hash:
                raise ValueError("resume config/code/schema/input mismatch; choose new run ID")
            state = (self.path / "STATUS").read_text().strip()
            if (self.path / "checksums.sha256").exists() or state == "COMPLETED":
                verify_checksums(self.path)
            if state == "COMPLETED":
                return state
            (self.path / "checksums.sha256").unlink(missing_ok=True)
        else:
            if self.resume:
                raise ValueError("cannot resume missing run")
            self.path.mkdir()
            os.chmod(self.path, 0o700)
            atomic_json(
                self.path / "manifest.json",
                {
                    **self.identity,
                    "identity_hash": self.identity_hash,
                    "created_at": utc_now(),
                    "case_ids": [c["case_id"] for c in self.cases],
                },
            )
            (self.path / "config.resolved.yaml").write_text(yaml.safe_dump(redact(self.config)))
        self._status("RUNNING")
        old_cases = {c["case_id"]: c for c in read_jsonl(self.path / "cases.jsonl")}
        statuses = [
            old_cases.get(
                c["case_id"], {"case_id": c["case_id"], "status": "PENDING", "stages": {}}
            )
            for c in self.cases
        ]
        atomic_jsonl(self.path / "cases.jsonl", statuses)
        errors = read_jsonl(self.path / "errors.jsonl")
        try:
            if self.isolation:
                self.isolation(self.path)
            for case_index, case in enumerate(self.cases):
                started = time.monotonic()
                case_budget = min(
                    self.config.get("budgets", {}).get("timeout_case_s", 7200),
                    self.config.get("runtime", {}).get("timeout_case_s", 7200),
                )
                case_deadline = started + case_budget
                records = {}
                failed = False
                for stage in self.stages:
                    folder = self.path / "stages" / case["case_id"] / stage.name
                    folder.mkdir(parents=True, exist_ok=True)
                    checkpoint = folder / "stage.json"
                    previous = json.loads(checkpoint.read_text()) if checkpoint.is_file() else {}
                    if previous.get("status") in {"SUCCESS", "SKIPPED_BY_VARIANT"}:
                        if not self._checkpoint_valid(folder, previous):
                            raise ValueError(f"stage checksum integrity mismatch: {stage.name}")
                        if stage.checkpoint_validator:
                            stage.checkpoint_validator(
                                Context(
                                    self.root,
                                    self.path,
                                    folder,
                                    case,
                                    self.config,
                                    records,
                                    deadline=case_deadline,
                                ),
                                previous,
                            )
                        records[stage.name] = previous
                        continue
                    base = {
                        "stage": stage.name,
                        "case_id": case["case_id"],
                        "updated_at": utc_now(),
                    }
                    stage_started = time.monotonic()
                    if stage.paid and previous.get("status") in {
                        "RUNNING",
                        "UNCERTAIN_REMOTE_CALL",
                    }:
                        record = {
                            **base,
                            "status": "UNCERTAIN_REMOTE_CALL",
                            "error": (
                                "Remote charge uncertain; inspect request journal before retry"
                            ),
                        }
                    elif any(
                        records[d]["status"] not in {"SUCCESS", "SKIPPED_BY_VARIANT"}
                        for d in stage.dependencies
                    ):
                        record = {**base, "status": "BLOCKED_BY_DEPENDENCY"}
                    elif time.monotonic() - started > self.config.get("budgets", {}).get(
                        "timeout_case_s", 7200
                    ):
                        record = {**base, "status": "TIMEOUT"}
                    else:
                        atomic_json(checkpoint, {**base, "status": "RUNNING"})
                        try:
                            reserve = self.config.get("runtime", {}).get("min_free_disk_gib", 0)
                            if shutil.disk_usage(self.path).free < reserve * 1024**3:
                                raise StageFailure(
                                    "RESOURCE_EXHAUSTED",
                                    f"less than {reserve:g} GiB disk space free; no stage started",
                                )
                            result = stage.action(
                                Context(
                                    self.root,
                                    self.path,
                                    folder,
                                    case,
                                    self.config,
                                    records,
                                    deadline=case_deadline,
                                )
                            )
                            if time.monotonic() > case_deadline:
                                raise StageFailure("TIMEOUT", "case deadline exceeded during stage")
                            hashes = {}
                            for rel in result.get("artifacts", []):
                                p = folder / rel
                                if (
                                    not p.resolve().is_relative_to(folder.resolve())
                                    or p.is_symlink()
                                ):
                                    raise ValueError("stage artifact outside stage directory")
                                hashes[rel] = sha256_file(p)
                            status = result.get("status", "SUCCESS")
                            if status not in {"SUCCESS", "SKIPPED_BY_VARIANT"}:
                                raise ValueError("stage returned invalid terminal status")
                            record = {
                                **base,
                                "status": status,
                                "result": result,
                                "artifact_hashes": hashes,
                            }
                        except Exception as e:
                            record = {
                                **base,
                                "status": getattr(e, "status", "ANALYSIS_FAILED"),
                                "error": redact(str(e)),
                            }
                    record["seconds"] = round(time.monotonic() - stage_started, 4)
                    atomic_json(checkpoint, record)
                    records[stage.name] = record
                    if record["status"] not in {"SUCCESS", "SKIPPED_BY_VARIANT"}:
                        failed = True
                        errors.append(record)
                        atomic_jsonl(self.path / "errors.jsonl", errors)
                # Include reused branch failures, including uncertain paid calls.
                failed |= any(
                    v["status"] not in {"SUCCESS", "SKIPPED_BY_VARIANT"} for v in records.values()
                )
                count = sum(len(v.get("result", {}).get("findings", [])) for v in records.values())
                failure_statuses = [
                    v["status"]
                    for v in records.values()
                    if v["status"] not in {"SUCCESS", "SKIPPED_BY_VARIANT", "BLOCKED_BY_DEPENDENCY"}
                ]
                statuses[case_index] = {
                    "case_id": case["case_id"],
                    "status": (failure_statuses[0] if failure_statuses else "ANALYSIS_FAILED")
                    if failed
                    else ("COMPLETED_WITH_FINDINGS" if count else "COMPLETED_NO_FINDINGS"),
                    "seconds": round(time.monotonic() - started, 4),
                    "stages": {k: v["status"] for k, v in records.items()},
                }
                atomic_jsonl(self.path / "cases.jsonl", statuses)
            if self.finalizer:
                self.finalizer(self.path, self.cases)
            for filename in ("errors.jsonl", "usage.jsonl", "llm_calls.jsonl", "findings.jsonl"):
                if not (self.path / filename).exists():
                    atomic_jsonl(self.path / filename, [])
            state = (
                "COMPLETED_WITH_CASE_FAILURES"
                if any(
                    c["status"] not in {"COMPLETED_WITH_FINDINGS", "COMPLETED_NO_FINDINGS"}
                    for c in statuses
                )
                else "COMPLETED"
            )
            self._status(state)
            write_checksums(self.path)
            return state
        except BaseException:
            self._status("FAILED")
            raise

    def _status(self, status: str) -> None:
        p = self.path / ".STATUS.tmp"
        p.write_text(status + "\n")
        os.replace(p, self.path / "STATUS")
