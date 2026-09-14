"""Build missing development-only CodeQL databases for Phase 7."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import utc_now
from src.data.build_projects import build_command_and_env
from src.reproduction.common import atomic_jsonl, read_csv, read_jsonl


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _codeql_binary(machine: Mapping[str, str]) -> Path:
    configured = machine.get("MAXVERA_CODEQL_HOME", "")
    if not configured:
        raise ValueError("MAXVERA_CODEQL_HOME is not configured")
    home = Path(configured).expanduser().resolve()
    candidates = (home, home / "codeql", home / "bin/codeql")
    binary = next((candidate for candidate in candidates if candidate.is_file()), None)
    if binary is None:
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return binary


def _preferred_attempt(row: Mapping[str, str]) -> dict[str, Any]:
    attempt: dict[str, Any] = {"jdk": row["jdk_version"]}
    if row.get("maven_version") not in {None, "", "n/a"}:
        attempt["maven"] = row["maven_version"]
    elif row.get("gradle_version") not in {None, "", "n/a"}:
        attempt["gradle"] = row["gradle_version"]
    elif row.get("use_gradlew", "").casefold() == "true":
        attempt["gradlew"] = True
    return attempt


def _attempts(row: Mapping[str, str], toolchain: Mapping[str, Any]) -> list[dict[str, Any]]:
    preferred = _preferred_attempt(row)
    candidates = [preferred, *cast(Sequence[Mapping[str, Any]], toolchain["build_attempts"])]
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(dict(item))
    return unique


def build_missing(
    repo_root: Path,
    *,
    limit: int | None,
    timeout: int,
) -> dict[str, int]:
    config = _mapping(repo_root / "configs/experiments/phase7_program_graph.yaml")
    dataset = cast(Mapping[str, Any], config["dataset"])
    rows = read_csv(repo_root / str(dataset["analysis_manifest"]))
    development = [
        row["project_id"] for row in read_csv(repo_root / str(dataset["development_split"]))
    ]
    by_id = {row["project_id"]: row for row in rows}
    selected = [by_id[project_id] for project_id in development]
    database_root = repo_root / str(dataset["database_root"])
    source_root = repo_root / str(dataset["source_root"])
    database_root.mkdir(parents=True, exist_ok=True)
    missing = [
        row
        for row in selected
        if not (database_root / row["project_id"] / "codeql-database.yml").is_file()
    ]
    if limit is not None:
        if limit < 1:
            raise ValueError("--limit must be positive")
        missing = missing[:limit]
    machine = effective_env(repo_root / ".env")
    codeql = _codeql_binary(machine)
    toolchain = _mapping(repo_root / "configs/toolchains/cwe_bench_java.yaml")
    status_path = repo_root / str(dataset["database_build_status"])
    records = read_jsonl(status_path)
    by_status_id = {str(record["project_id"]): record for record in records}
    successes = 0
    failures = 0
    for position, row in enumerate(missing, start=1):
        project_id = row["project_id"]
        destination = database_root / project_id
        source = source_root / project_id
        attempts: list[dict[str, Any]] = []
        started = time.monotonic()
        success = False
        reason = "all pinned build attempts failed or were unavailable"
        if not source.is_dir():
            reason = "opaque Phase 7 source tree is unavailable"
        else:
            for number, attempt in enumerate(_attempts(row, toolchain), start=1):
                try:
                    command, environment = build_command_and_env(
                        repo_root, source, attempt, toolchain, machine
                    )
                except ValueError as error:
                    attempts.append(
                        {
                            "number": number,
                            "toolchain": attempt,
                            "outcome": "UNAVAILABLE",
                            "reason": str(error),
                        }
                    )
                    continue
                attempt_started = time.monotonic()
                with tempfile.TemporaryDirectory(
                    prefix=f".{project_id}.attempt-{number}-", dir=database_root
                ) as temporary:
                    temporary_database = Path(temporary) / "database"
                    codeql_command = [
                        str(codeql),
                        "database",
                        "create",
                        str(temporary_database),
                        "--language=java",
                        "--threads=4",
                        "--ram=16384",
                        f"--source-root={source}",
                        f"--command={shlex.join(command)}",
                    ]
                    try:
                        process = subprocess.run(
                            codeql_command,
                            cwd=source,
                            env=environment,
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                        )
                        exit_code: int | None = process.returncode
                        output = (
                            f"command={shlex.join(codeql_command)}\n"
                            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
                        )
                    except subprocess.TimeoutExpired as error:
                        exit_code = None
                        output = (
                            f"command={shlex.join(codeql_command)}\ntimeout after {timeout}s\n"
                            f"stdout={error.stdout!r}\nstderr={error.stderr!r}"
                        )
                    log = repo_root / "data/interim/phase7_database_logs" / project_id
                    log.mkdir(parents=True, exist_ok=True)
                    (log / f"attempt_{number:02d}.log").write_text(
                        output, encoding="utf-8", newline="\n"
                    )
                    attempt_record: dict[str, Any] = {
                        "number": number,
                        "toolchain": attempt,
                        "outcome": "SUCCESS" if exit_code == 0 else "FAILED",
                        "exit_code": exit_code,
                        "seconds": round(time.monotonic() - attempt_started, 3),
                    }
                    attempts.append(attempt_record)
                    if exit_code == 0 and (temporary_database / "codeql-database.yml").is_file():
                        if destination.exists() or destination.is_symlink():
                            raise FileExistsError(
                                f"Phase 7 database destination appeared during build: {project_id}"
                            )
                        os.replace(temporary_database, destination)
                        success = True
                        reason = "missing Phase 7 database built successfully"
                        break
        record: dict[str, Any] = {
            "schema_version": 1,
            "project_id": project_id,
            "status": "SUCCESS" if success else "CODEQL_DB_FAILED",
            "reason": reason,
            "attempts": attempts,
            "seconds": round(time.monotonic() - started, 3),
            "updated_at": utc_now(),
        }
        by_status_id[project_id] = record
        atomic_jsonl(status_path, [by_status_id[key] for key in sorted(by_status_id)])
        successes += int(success)
        failures += int(not success)
        print(
            f"[{position}/{len(missing)}] {project_id}: {record['status']}",
            flush=True,
        )
    return {"selected_missing": len(missing), "successes": successes, "failures": failures}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    try:
        result = build_missing(
            args.repo_root.resolve(),
            limit=args.limit,
            timeout=args.timeout,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}")
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
