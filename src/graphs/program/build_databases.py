"""Build missing development-only CodeQL databases for Phase 7."""

from __future__ import annotations

import argparse
import csv
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
from src.graphs.program.runner import _run_command
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
    elif row.get("use_gradlew", "").casefold() in {"true", "1"}:
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


def _seed_files(repo_root: Path, config: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    phase6 = cast(Mapping[str, Any], config["phase6_lock"])
    path = repo_root / str(phase6["run_root"]) / "hypotheses.jsonl"
    by_project: dict[str, set[str]] = {}
    for hypothesis in read_jsonl(path):
        project_id = str(hypothesis["project_id"])
        files = by_project.setdefault(project_id, set())
        for location in hypothesis.get("locations", []):
            if isinstance(location, dict) and isinstance(location.get("file"), str):
                files.add(str(location["file"]).replace("\\", "/").lstrip("./"))
    return {project_id: tuple(sorted(files)) for project_id, files in by_project.items()}


def _source_modules(source: Path, seed_files: Sequence[str], marker: str) -> tuple[str, ...]:
    modules: set[str] = set()
    for seed_file in seed_files:
        current = (source / seed_file).parent
        while current != source and source in current.parents:
            if (current / marker).is_file():
                modules.add(current.relative_to(source).as_posix())
                break
            current = current.parent
    return tuple(sorted(modules))


def _gradle_module(source: Path, seed_file: str) -> str | None:
    current = (source / seed_file).parent
    while current != source and source in current.parents:
        markers = (
            "build.gradle",
            "build.gradle.kts",
            f"{current.name}.gradle",
            f"{current.name}.gradle.kts",
        )
        if any((current / marker).is_file() for marker in markers):
            return current.relative_to(source).as_posix()
        current = current.parent
    return None


def _compatible_attempts(
    row: Mapping[str, str], toolchain: Mapping[str, Any], source: Path
) -> list[dict[str, Any]]:
    attempts = _attempts(row, toolchain)
    if (source / "pom.xml").is_file():
        return [attempt for attempt in attempts if "maven" in attempt]
    if any(
        (source / name).is_file()
        for name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")
    ):
        return [attempt for attempt in attempts if "gradle" in attempt or attempt.get("gradlew")]
    return attempts


def _build_command(
    command: Sequence[str], attempt: Mapping[str, Any], source: Path, seed_files: Sequence[str]
) -> list[str]:
    executable, *arguments = command
    if "maven" in attempt:
        modules = _source_modules(source, seed_files, "pom.xml")
        selection = ["-pl", ",".join(modules), "-am"] if modules else []
        options = [value for value in arguments if value not in {"clean", "package"}]
        goal = (
            "test-compile" if any("/src/test/" in f"/{file}" for file in seed_files) else "compile"
        )
        return [
            executable,
            *selection,
            goal,
            "-U",
            "-Dmaven.wagon.http.retryHandler.count=3",
            *options,
        ]
    tasks_set: set[str] = set()
    for seed_file in seed_files:
        module = _gradle_module(source, seed_file)
        if module is not None:
            task = "testClasses" if "/src/test/" in f"/{seed_file}" else "classes"
            tasks_set.add(f":{module.replace('/', ':')}:{task}")
    tasks = sorted(tasks_set)
    if not tasks:
        tasks = ["classes"]
    gradle_options: list[str] = []
    index = 0
    while index < len(arguments):
        if arguments[index : index + 2] == ["-x", "test"]:
            index += 2
            continue
        if arguments[index] not in {"clean", "build", "classes"}:
            gradle_options.append(arguments[index])
        index += 1
    return [executable, *gradle_options, *tasks]


def _build_environment(
    environment: Mapping[str, str], attempt: Mapping[str, Any]
) -> dict[str, str]:
    result = dict(environment)
    java_home = Path(result["JAVA_HOME"])
    result["PATH"] = f"{java_home / 'bin'}{os.pathsep}{result.get('PATH', '')}"
    if str(attempt.get("jdk")) == "17":
        option = "-XX:-UseContainerSupport"
        if option not in result.get("JAVA_TOOL_OPTIONS", ""):
            result["JAVA_TOOL_OPTIONS"] = " ".join(
                value for value in (result.get("JAVA_TOOL_OPTIONS", ""), option) if value
            )
    return result


def _output_path(repo_root: Path, override: Path | None, default: Path) -> Path:
    if override is None:
        return default
    return override if override.is_absolute() else repo_root / override


def _node_files(
    codeql: Path, database: Path, query: Path, timeout: int
) -> tuple[set[str], str | None]:
    with tempfile.TemporaryDirectory(prefix=".phase7-seed-check-") as temporary:
        bqrs = Path(temporary) / "nodes.bqrs"
        csv_path = Path(temporary) / "nodes.csv"
        commands = (
            [
                str(codeql),
                "query",
                "run",
                "--threads=2",
                "--ram=8192",
                f"--database={database}",
                f"--output={bqrs}",
                str(query),
            ],
            [str(codeql), "bqrs", "decode", "--format=csv", f"--output={csv_path}", str(bqrs)],
        )
        for command in commands:
            try:
                result = _run_command(command, timeout=timeout)
            except subprocess.TimeoutExpired:
                return set(), f"node query timed out after {timeout}s"
            if result.returncode:
                return set(), f"node query failed: {result.stderr[-2000:]}"
        files: set[str] = set()
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) > 2 and row[2].endswith(".java"):
                    files.add(row[2])
        return files, None


def _seed_node_coverage(
    codeql: Path, database: Path, query: Path, seed_files: Sequence[str], timeout: int
) -> tuple[int, str]:
    if not seed_files:
        return 0, "no Phase 6 seed files are available"
    files, error = _node_files(codeql, database, query, timeout)
    if error:
        return 0, error
    expected = set(seed_files)
    matched = len(files & expected)
    return matched, f"{matched}/{len(expected)} seed files have CodeQL nodes"


def build_missing(
    repo_root: Path,
    *,
    limit: int | None,
    timeout: int,
    project_id: str | None = None,
    database_root_override: Path | None = None,
    status_path_override: Path | None = None,
    log_root_override: Path | None = None,
    build_mode: str = "auto",
    config_path: Path | None = None,
) -> dict[str, int]:
    if build_mode not in {"auto", "manual", "none"}:
        raise ValueError("--build-mode must be auto, manual, or none")
    resolved_config = config_path or repo_root / "configs/experiments/phase7_program_graph.yaml"
    if not resolved_config.is_absolute():
        resolved_config = repo_root / resolved_config
    config = _mapping(resolved_config)
    dataset = cast(Mapping[str, Any], config["dataset"])
    rows = read_csv(repo_root / str(dataset["analysis_manifest"]))
    split_value = dataset.get("analysis_split", dataset.get("development_split"))
    if not isinstance(split_value, str):
        raise ValueError("Phase 7 database build requires an analysis split")
    development = [row["project_id"] for row in read_csv(repo_root / split_value)]
    by_id = {row["project_id"]: row for row in rows}
    selected = [by_id[project_id] for project_id in development]
    database_root = _output_path(
        repo_root, database_root_override, repo_root / str(dataset["database_root"])
    )
    source_root = repo_root / str(dataset["source_root"])
    database_root.mkdir(parents=True, exist_ok=True)
    missing = [
        row
        for row in selected
        if not (database_root / row["project_id"] / "codeql-database.yml").is_file()
    ]
    if project_id is not None:
        if project_id not in development:
            raise ValueError("--project-id is not in the development split")
        missing = [row for row in missing if row["project_id"] == project_id]
    if limit is not None:
        if limit < 1:
            raise ValueError("--limit must be positive")
        missing = missing[:limit]
    machine = effective_env(repo_root / ".env")
    codeql = _codeql_binary(machine)
    toolchain = _mapping(repo_root / "configs/toolchains/cwe_bench_java.yaml")
    status_path = _output_path(
        repo_root, status_path_override, repo_root / str(dataset["database_build_status"])
    )
    log_root = _output_path(
        repo_root, log_root_override, repo_root / "data/interim/phase7_database_logs"
    )
    seeds = _seed_files(repo_root, config)
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
            manual_attempts = _compatible_attempts(row, toolchain, source)
            modes = (
                [(attempt, "manual") for attempt in manual_attempts]
                if build_mode in {"auto", "manual"}
                else []
            )
            if build_mode in {"auto", "none"}:
                modes.append((_preferred_attempt(row), "none"))
            for number, (attempt, mode) in enumerate(modes, start=1):
                try:
                    command, environment = build_command_and_env(
                        repo_root, source, attempt, toolchain, machine
                    )
                    environment = _build_environment(environment, attempt)
                    if mode == "manual":
                        command = _build_command(
                            command, attempt, source, seeds.get(project_id, ())
                        )
                except ValueError as error:
                    if mode == "manual":
                        attempts.append(
                            {
                                "number": number,
                                "toolchain": attempt,
                                "build_mode": mode,
                                "outcome": "UNAVAILABLE",
                                "reason": str(error),
                            }
                        )
                        continue
                    environment = dict(os.environ)
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
                    ]
                    if mode == "manual":
                        codeql_command.append(f"--command={shlex.join(command)}")
                    else:
                        codeql_command.append("--build-mode=none")
                    try:
                        process = _run_command(
                            codeql_command, cwd=source, env=environment, timeout=timeout
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
                    log = log_root / project_id
                    log.mkdir(parents=True, exist_ok=True)
                    (log / f"attempt_{number:02d}.log").write_text(
                        output, encoding="utf-8", newline="\n"
                    )
                    attempt_record: dict[str, Any] = {
                        "number": number,
                        "toolchain": attempt,
                        "build_mode": mode,
                        "outcome": "SUCCESS" if exit_code == 0 else "FAILED",
                        "exit_code": exit_code,
                        "seconds": round(time.monotonic() - attempt_started, 3),
                    }
                    database_ready = (
                        exit_code == 0 and (temporary_database / "codeql-database.yml").is_file()
                    )
                    if exit_code == 0 and not database_ready:
                        attempt_record["outcome"] = "FAILED"
                        attempt_record["reason"] = "CodeQL exited successfully without a database"
                    if database_ready:
                        matched, coverage = _seed_node_coverage(
                            codeql,
                            temporary_database,
                            repo_root / str(config["extractor"]["node_query"]),
                            seeds.get(project_id, ()),
                            timeout,
                        )
                        attempt_record["seed_coverage"] = coverage
                        if not matched:
                            attempt_record["outcome"] = "NO_SEED_NODES"
                        with (log / f"attempt_{number:02d}.log").open(
                            "a", encoding="utf-8"
                        ) as handle:
                            handle.write(f"\nseed_coverage={coverage}\n")
                    attempts.append(attempt_record)
                    if attempt_record["outcome"] == "SUCCESS" and database_ready:
                        if destination.exists() or destination.is_symlink():
                            raise FileExistsError(
                                f"Phase 7 database destination appeared during build: {project_id}"
                            )
                        os.replace(temporary_database, destination)
                        success = True
                        reason = f"Phase 7 database built with {mode}; {coverage}"
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
    parser.add_argument("--project-id")
    parser.add_argument("--database-root", type=Path)
    parser.add_argument("--status-path", type=Path)
    parser.add_argument("--log-root", type=Path)
    parser.add_argument("--build-mode", choices=("auto", "manual", "none"), default="auto")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase7_program_graph.yaml")
    )
    args = parser.parse_args(argv)
    try:
        result = build_missing(
            args.repo_root.resolve(),
            limit=args.limit,
            timeout=args.timeout,
            project_id=args.project_id,
            database_root_override=args.database_root,
            status_path_override=args.status_path,
            log_root_override=args.log_root,
            build_mode=args.build_mode,
            config_path=args.config,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}")
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
