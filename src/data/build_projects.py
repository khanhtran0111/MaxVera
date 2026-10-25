"""Sequentially fetch, build, and create CodeQL databases for Phase 2 projects."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env, initialize_env_file
from src.common.provenance import utc_now

MAVEN_COMMAND = [
    "clean",
    "package",
    "-B",
    "-V",
    "-e",
    "-Dfindbugs.skip",
    "-Dcheckstyle.skip",
    "-Dpmd.skip=true",
    "-Dspotbugs.skip",
    "-Denforcer.skip",
    "-Dmaven.javadoc.skip",
    "-DskipTests",
    "-Dmaven.test.skip.exec",
    "-Dlicense.skip=true",
    "-Drat.skip=true",
    "-Dspotless.check.skip=true",
]


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"invalid YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _execute(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    log: Path,
    timeout: int,
) -> tuple[int, float]:
    started = time.monotonic()
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"command: {shlex.join(command)}\n")
        handle.flush()
        try:
            process = subprocess.run(
                command,
                cwd=cwd,
                env=dict(environment) if environment is not None else None,
                check=False,
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            return process.returncode, time.monotonic() - started
        except subprocess.TimeoutExpired:
            handle.write(f"TIMEOUT after {timeout} seconds\n")
            return 124, time.monotonic() - started


def _atomic_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _status_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("build status JSONL contains a non-object")
            records.append(cast(dict[str, Any], value))
    return records


def _fetch_source(
    row: Mapping[str, str], raw_root: Path, source_root: Path, log_root: Path, timeout: int
) -> tuple[bool, str, float]:
    project_id = row["project_id"]
    destination = source_root / project_id
    if destination.is_dir():
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=destination,
            check=False,
            capture_output=True,
            text=True,
        )
        if head.returncode == 0 and head.stdout.strip() == row["buggy_commit_id"]:
            return True, "source already verified", 0.0
        return False, "existing source directory has the wrong revision", 0.0
    temporary = source_root / f".{project_id}.fetching"
    if temporary.exists():
        shutil.rmtree(temporary)
    source_root.mkdir(parents=True, exist_ok=True)
    clone_log = log_root / project_id / "fetch.log"
    code, elapsed = _execute(
        ["git", "clone", "--filter=blob:none", "--no-checkout", row["github_url"], str(temporary)],
        cwd=source_root,
        log=clone_log,
        timeout=timeout,
    )
    if code != 0:
        shutil.rmtree(temporary, ignore_errors=True)
        return False, f"git clone failed with exit code {code}", elapsed
    commands = (
        ["git", "fetch", "--depth", "1", "origin", row["buggy_commit_id"]],
        ["git", "checkout", "--detach", row["buggy_commit_id"]],
    )
    for index, command in enumerate(commands, start=1):
        code, command_elapsed = _execute(
            command,
            cwd=temporary,
            log=log_root / project_id / f"fetch_{index}.log",
            timeout=timeout,
        )
        elapsed += command_elapsed
        if code != 0:
            shutil.rmtree(temporary, ignore_errors=True)
            return False, f"source checkout failed with exit code {code}", elapsed
    patch = raw_root / "patches" / f"{row['project_slug']}.patch"
    if patch.is_file():
        code, patch_elapsed = _execute(
            ["git", "apply", str(patch)],
            cwd=temporary,
            log=log_root / project_id / "patch.log",
            timeout=timeout,
        )
        elapsed += patch_elapsed
        if code != 0:
            shutil.rmtree(temporary, ignore_errors=True)
            return False, f"upstream build patch failed with exit code {code}", elapsed
    os.replace(temporary, destination)
    return True, "source fetched and verified", elapsed


def _tool_home(
    repo_root: Path,
    toolchain: Mapping[str, Any],
    family: str,
    version: str,
    machine: Mapping[str, str],
) -> Path:
    entry_untyped = cast(Mapping[str, Any], toolchain[family])[version]
    entry = cast(Mapping[str, Any], entry_untyped)
    if family == "jdk":
        variable = str(entry["env_home"])
        configured = machine.get(variable)
        if not configured:
            raise ValueError(f"missing {variable}")
        return Path(configured).expanduser().resolve()
    return (repo_root / str(toolchain["install_root"]) / str(entry["directory"])).resolve()


def build_command_and_env(
    repo_root: Path,
    source: Path,
    attempt: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    machine: Mapping[str, str],
) -> tuple[list[str], dict[str, str]]:
    """Resolve one upstream-compatible build attempt without shell interpolation."""
    jdk_version = str(attempt["jdk"])
    java_home = _tool_home(repo_root, toolchain, "jdk", jdk_version, machine)
    environment = dict(os.environ)
    environment["JAVA_HOME"] = str(java_home)
    if "maven" in attempt:
        home = _tool_home(repo_root, toolchain, "maven", str(attempt["maven"]), machine)
        executable = home / "bin" / "mvn"
        environment["PATH"] = f"{executable.parent}{os.pathsep}{environment.get('PATH', '')}"
        return [str(executable), *MAVEN_COMMAND], environment
    if "gradle" in attempt:
        home = _tool_home(repo_root, toolchain, "gradle", str(attempt["gradle"]), machine)
        executable = home / "bin" / "gradle"
        environment["PATH"] = f"{executable.parent}{os.pathsep}{environment.get('PATH', '')}"
        return [str(executable), "--no-daemon", "clean", "build", "-x", "test"], environment
    wrapper = source / "gradlew"
    if not wrapper.is_file():
        raise ValueError("project has no gradlew wrapper")
    wrapper.chmod(wrapper.stat().st_mode | 0o100)
    return [
        str(wrapper),
        "--no-daemon",
        "-Dorg.gradle.dependency.verification=off",
        "clean",
        "build",
        "-x",
        "test",
    ], environment


def _codeql_binary(machine: Mapping[str, str]) -> Path:
    configured = machine.get("MAXVERA_CODEQL_HOME")
    if not configured:
        raise ValueError("missing MAXVERA_CODEQL_HOME")
    candidate = Path(configured).expanduser().resolve()
    binary = candidate if candidate.is_file() else candidate / "codeql"
    if not binary.is_file():
        binary = candidate / "bin" / "codeql"
    if not binary.is_file():
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return binary


def run_project(
    repo_root: Path,
    row: Mapping[str, str],
    raw_root: Path,
    toolchain: Mapping[str, Any],
    machine: Mapping[str, str],
    *,
    timeout: int,
) -> dict[str, Any]:
    project_id = row["project_id"]
    source_root = repo_root / "data/interim/project_sources"
    logs = repo_root / "data/interim/build_info/logs"
    fetched, fetch_reason, fetch_seconds = _fetch_source(row, raw_root, source_root, logs, timeout)
    base: dict[str, Any] = {
        "schema_version": 1,
        "dataset_id": row["dataset_id"],
        "upstream_revision": row["upstream_revision"],
        "project_id": project_id,
        "updated_at": utc_now(),
        "fetch_seconds": round(fetch_seconds, 3),
        "attempts": [],
    }
    if not fetched:
        return {**base, "status": "BUILD_FAILED", "reason": fetch_reason}
    source = source_root / project_id
    attempts = cast(Sequence[Mapping[str, Any]], toolchain["build_attempts"])
    selected: tuple[Mapping[str, Any], list[str], dict[str, str]] | None = None
    for number, attempt in enumerate(attempts, start=1):
        try:
            command, environment = build_command_and_env(
                repo_root, source, attempt, toolchain, machine
            )
        except ValueError as error:
            cast(list[dict[str, Any]], base["attempts"]).append(
                {
                    "number": number,
                    "toolchain": dict(attempt),
                    "outcome": "UNAVAILABLE",
                    "reason": str(error),
                }
            )
            continue
        code, elapsed = _execute(
            command,
            cwd=source,
            environment=environment,
            log=logs / project_id / f"build_{number:02d}.log",
            timeout=timeout,
        )
        cast(list[dict[str, Any]], base["attempts"]).append(
            {
                "number": number,
                "toolchain": dict(attempt),
                "outcome": "SUCCESS" if code == 0 else "FAILED",
                "exit_code": code,
                "seconds": round(elapsed, 3),
            }
        )
        if code == 0:
            selected = (attempt, command, environment)
            break
    if selected is None:
        return {
            **base,
            "status": "BUILD_FAILED",
            "reason": "all pinned build attempts failed or were unavailable",
        }
    attempt, command, environment = selected
    try:
        codeql = _codeql_binary(machine)
    except ValueError as error:
        return {
            **base,
            "status": "CODEQL_DB_FAILED",
            "reason": str(error),
            "selected_toolchain": dict(attempt),
        }
    database = repo_root / "data/interim/codeql_databases" / project_id
    if database.exists():
        return {
            **base,
            "status": "CODEQL_DB_FAILED",
            "reason": "database target already exists; refusing overwrite",
        }
    database.parent.mkdir(parents=True, exist_ok=True)
    codeql_command = [
        str(codeql),
        "database",
        "create",
        str(database),
        "--language=java",
        "--threads=4",
        "--ram=16384",
        f"--source-root={source}",
        f"--command={shlex.join(command)}",
    ]
    code, elapsed = _execute(
        codeql_command,
        cwd=source,
        environment=environment,
        log=logs / project_id / "codeql_database.log",
        timeout=timeout,
    )
    if code != 0:
        return {
            **base,
            "status": "CODEQL_DB_FAILED",
            "reason": f"CodeQL database create failed with exit code {code}",
            "selected_toolchain": dict(attempt),
            "codeql_seconds": round(elapsed, 3),
        }
    return {
        **base,
        "status": "SUCCESS",
        "reason": "build and CodeQL database creation succeeded",
        "selected_toolchain": dict(attempt),
        "codeql_seconds": round(elapsed, 3),
        "codeql_database": f"data/interim/codeql_databases/{project_id}",
    }


def run_all(repo_root: Path, raw_root: Path, *, limit: int | None, timeout: int) -> int:
    manifest = _read_csv(repo_root / "data/processed/manifests/cwe_bench_v1.csv")
    toolchain = _load_yaml(repo_root / "configs/toolchains/cwe_bench_java.yaml")
    env_path = repo_root / ".env"
    initialize_env_file(env_path)
    machine = effective_env(env_path)
    status_path = repo_root / "data/interim/build_info/build_status.jsonl"
    records = _status_records(status_path)
    by_id = {str(record["project_id"]): record for record in records}
    pending = [
        row for row in manifest if by_id.get(row["project_id"], {}).get("status") == "PENDING"
    ]
    if limit is not None:
        pending = pending[:limit]
    for row in pending:
        result = run_project(repo_root, row, raw_root, toolchain, machine, timeout=timeout)
        by_id[row["project_id"]] = result
        ordered = [by_id[item["project_id"]] for item in manifest]
        _atomic_jsonl(status_path, ordered)
        print(f"{row['project_id']}: {result['status']}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--raw-root", type=Path, default=Path("data/raw/cwe_bench_java_v1"))
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=7200)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.repo_root.resolve()
    raw = args.raw_root if args.raw_root.is_absolute() else root / args.raw_root
    try:
        return run_all(root, raw.resolve(), limit=args.limit, timeout=args.timeout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
