"""Build evaluator-only, opaque fixed-revision CodeQL databases for Phase 11."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file, utc_now
from src.data.build_projects import build_command_and_env
from src.graphs.program.build_databases import (
    _attempts,
    _codeql_binary,
    _node_files,
    _preferred_attempt,
)
from src.graphs.program.runner import _run_command
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl
from src.verification.runner import _dependency_status, _validate_config

PHASE10_STATUS = Path(
    "results/specifications/phase10/full_useg/p10_b9_dev_full_001/project_status.jsonl"
)


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run_command(command, cwd=cwd, env=env, timeout=timeout)


def _resolve_fixed_revision(source: Path, revision: str) -> str:
    """Resolve abbreviated evaluator revisions without persisting their identity.

    Git hosting providers generally reject fetching an abbreviated object ID even
    when that commit is reachable.  The vulnerable partial clone already has the
    upstream commit graph, so use it only to expand the evaluator-provided value
    before creating the isolated fixed checkout.
    """
    resolved = _run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=source,
    )
    return resolved.stdout.strip() if resolved.returncode == 0 else revision


def _target_source_files(
    root: Path,
    config: Mapping[str, Any],
    project_ids: set[str],
) -> dict[str, tuple[str, ...]]:
    """Resolve frozen Phase 10 endpoint nodes to their project source files."""
    dependencies = cast(Mapping[str, Any], config["development_dependencies"])
    phase10 = cast(Mapping[str, Any], dependencies["phase10"])
    phase9 = cast(Mapping[str, Any], dependencies["phase9"])
    phase10_root = root / str(phase10["run_root"])
    phase9_root = root / str(phase9["run_root"])
    node_projects: dict[str, str] = {}
    for spec in read_jsonl(phase10_root / "specifications.jsonl"):
        project_id = str(spec.get("project_id", ""))
        if project_id not in project_ids:
            continue
        for field in ("sources", "sinks", "sanitizers", "propagators"):
            values = spec.get(field, [])
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, dict) and value.get("node_id"):
                    node_projects[str(value["node_id"])] = project_id

    files: dict[str, set[str]] = {project_id: set() for project_id in project_ids}
    nodes_path = phase9_root / "useg/nodes.jsonl"
    with nodes_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            node = json.loads(line)
            node_project_id = node_projects.get(str(node.get("node_id", "")))
            if node_project_id is None:
                continue
            properties = node.get("properties", {})
            if not isinstance(properties, dict):
                continue
            location = properties.get("location", {})
            file_value = location.get("file") if isinstance(location, dict) else None
            if not isinstance(file_value, str):
                file_value = properties.get("file")
            if isinstance(file_value, str) and file_value.endswith(".java"):
                files[node_project_id].add(file_value)
    return {key: tuple(sorted(value)) for key, value in files.items()}


def _maven_modules(checkout: Path, source_files: Sequence[str]) -> tuple[str, ...]:
    """Find the nearest Maven module containing each frozen endpoint file."""
    modules: set[str] = set()
    for source_file in source_files:
        current = (checkout / source_file).parent
        while current != checkout and checkout in current.parents:
            if (current / "pom.xml").is_file():
                modules.add(current.relative_to(checkout).as_posix())
                break
            current = current.parent
    return tuple(sorted(modules))


def _compatible_attempts(
    row: Mapping[str, str],
    toolchain: Mapping[str, Any],
    checkout: Path,
) -> list[dict[str, Any]]:
    attempts = _attempts(row, toolchain)
    has_maven = (checkout / "pom.xml").is_file()
    has_gradle = any(
        (checkout / name).is_file()
        for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
    )
    if has_maven:
        return [attempt for attempt in attempts if "maven" in attempt]
    if has_gradle or (checkout / "gradlew").is_file():
        return [
            attempt for attempt in attempts if "gradle" in attempt or attempt.get("gradlew") is True
        ]
    return attempts


def _tailored_build_command(
    command: Sequence[str],
    attempt: Mapping[str, Any],
    modules: Sequence[str],
) -> list[str]:
    """Run only compilation tasks needed for CodeQL extraction."""
    executable, *arguments = command
    if "maven" in attempt:
        options = [value for value in arguments if value not in {"clean", "package"}]
        target = ["-pl", ",".join(modules), "-am"] if modules else []
        return [
            executable,
            *target,
            "compile",
            "-U",
            "-Dmaven.wagon.http.retryHandler.count=3",
            *options,
        ]
    options = [value for value in arguments if value not in {"clean", "build", "classes"}]
    return [executable, *options, "classes"]


def _stabilize_build_environment(
    environment: Mapping[str, str], attempt: Mapping[str, Any]
) -> dict[str, str]:
    """Make subprocess Java match the pinned JDK and avoid legacy cgroup crashes."""
    result = dict(environment)
    if java_home := result.get("JAVA_HOME"):
        result["PATH"] = f"{Path(java_home) / 'bin'}{os.pathsep}{result.get('PATH', '')}"
    option = "-XX:-UseContainerSupport"
    if str(attempt.get("jdk")) == "17" and option not in result.get("JAVA_TOOL_OPTIONS", ""):
        result["JAVA_TOOL_OPTIONS"] = " ".join(
            value for value in (result.get("JAVA_TOOL_OPTIONS", ""), option) if value
        )
    return result


def _checkout_fixed_revision(
    source: Path,
    checkout: Path,
    revision: str,
    upstream_url: str,
    *,
    timeout: int,
) -> tuple[bool, str]:
    """Create one isolated checkout, preferring already-fetched local objects."""
    candidates = [("local", str(source))]
    if upstream_url:
        candidates.append(("upstream", upstream_url))
    failures: list[str] = []
    for label, remote_url in candidates:
        shutil.rmtree(checkout, ignore_errors=True)
        checkout.mkdir()
        initialized = _run(["git", "init", "--quiet"], cwd=checkout)
        remote = (
            _run(["git", "remote", "add", "origin", remote_url], cwd=checkout)
            if initialized.returncode == 0
            else initialized
        )
        fetch = (
            _run(
                [
                    "git",
                    "fetch",
                    "--quiet",
                    "--filter=blob:none",
                    "--depth=1",
                    "origin",
                    revision,
                ],
                cwd=checkout,
                timeout=timeout,
            )
            if remote.returncode == 0
            else remote
        )
        switch = (
            _run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=checkout)
            if fetch.returncode == 0
            else fetch
        )
        if switch.returncode == 0:
            return True, label
        failures.append(f"{label} exit {switch.returncode}")
    return False, "; ".join(failures)


def _reset_checkout(checkout: Path) -> bool:
    reset = _run(["git", "reset", "--hard", "--quiet", "HEAD"], cwd=checkout)
    clean = _run(["git", "clean", "-ffdx", "--quiet"], cwd=checkout)
    return reset.returncode == 0 and clean.returncode == 0


def _selected_rows(
    root: Path, args: argparse.Namespace, config: Mapping[str, Any] | None = None,
) -> list[dict[str, str]]:
    development_path = root / "data/processed/splits/development.csv"
    test_path = root / "data/processed/splits/test_locked.csv"
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    analysis_path = root / "data/processed/analysis_input/D_extended_projects.csv"
    test = config is not None and config.get("analysis_scope") == "test_locked"
    phase10_status_path = root / PHASE10_STATUS
    if test:
        assert config is not None
        dependencies = cast(Mapping[str, Any], config["development_dependencies"])
        phase10 = cast(Mapping[str, Any], dependencies["phase10"])
        phase10_status_path = root / str(phase10["run_root"]) / "project_status.jsonl"
    development = [row["project_id"] for row in read_csv(development_path)]
    locked = {row["project_id"] for row in read_csv(test_path)}
    if set(development) & locked:
        raise ValueError("development and locked-test splits overlap")
    selected = sorted(locked) if test else development
    labels = {row["project_id"]: row for row in read_csv(labels_path)}
    analysis = {row["project_id"]: row for row in read_csv(analysis_path)}
    if set(selected) - labels.keys() or set(selected) - analysis.keys():
        raise ValueError("selected projects do not resolve to fixed labels/build metadata")
    phase10_successes = {
        str(row["project_id"])
        for row in read_jsonl(phase10_status_path)
        if row.get("status") == "SUCCESS"
    }
    rows = [
        {
            **analysis[project_id],
            "fix_commit_ids": labels[project_id]["fix_commit_ids"],
        }
        for project_id in selected
        if project_id in phase10_successes
    ]
    if args.project_id:
        rows = [row for row in rows if row["project_id"] == args.project_id]
        if not rows:
            raise ValueError("--project-id is not an analyzable Phase 10 development project")
    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("--limit must be positive")
        rows = rows[: args.limit]
    return rows


def _write_preparation_state(
    root: Path,
    fixed_root: Path,
    by_id: Mapping[str, Mapping[str, Any]],
    config: Mapping[str, Any] | None = None, config_path: Path | None = None,
) -> dict[str, Any]:
    """Atomically checkpoint statuses, then bind a fresh manifest to their hash."""
    status_path = fixed_root / "build_status.jsonl"
    atomic_jsonl(status_path, [by_id[key] for key in sorted(by_id)])
    counts = Counter(str(row["status"]) for row in by_id.values())
    test = config is not None and config.get("analysis_scope") == "test_locked"
    phase10_status = root / PHASE10_STATUS
    if test:
        assert config is not None
        dependencies = cast(Mapping[str, Any], config["development_dependencies"])
        phase10 = cast(Mapping[str, Any], dependencies["phase10"])
        phase10_status = root / str(phase10["run_root"]) / "project_status.jsonl"
    eligible_ids = {
        str(row["project_id"])
        for row in read_jsonl(phase10_status)
        if row.get("status") == "SUCCESS"
    }
    completed = sum(project_id in by_id for project_id in eligible_ids)
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "strategy": "evaluator_only_targeted_fixed_revision_to_opaque_project_database",
        "development_only": not test,
        "locked_test_prepared": test,
        "identity_mapping_persisted": False,
        "labels_sha256": sha256_file(root / "data/processed/evaluator_only/D_extended_labels.csv"),
        "development_split_sha256": sha256_file(root / "data/processed/splits/development.csv"),
        "phase10_project_status_sha256": sha256_file(phase10_status),
        "eligible_phase10_projects": len(eligible_ids),
        "accounted_projects": completed,
        "preparation_complete": completed == len(eligible_ids),
        "status_sha256": sha256_file(status_path),
        "phase11_config_sha256": sha256_file(
            config_path or root / "configs/experiments/phase11_static_verification.yaml"
        ),
        "implementation_sha256": sha256_file(root / "src/verification/prepare_fixed.py"),
        "successful_databases": counts["SUCCESS"],
        "failed_databases": counts["CODEQL_DB_FAILED"],
    }
    if test:
        assert config is not None
        manifest["analysis_scope"] = "test_locked"
        manifest["analyzer_snapshot_sha256"] = config["analyzer_snapshot_sha256"]
        manifest["test_split_sha256"] = sha256_file(root / "data/processed/splits/test_locked.csv")
    atomic_json(fixed_root / "preparation_manifest.json", manifest)
    return manifest


def prepare(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("fixed-revision preparation requires MAXVERA_DATA_ROLE=evaluator")
    config_path = root / getattr(
        args, "config", Path("configs/experiments/phase11_static_verification.yaml")
    )
    config = _mapping(config_path)
    _validate_config(config)
    if config.get("analysis_scope") == "test_locked":
        _dependency_status(root, config)
    rows = _selected_rows(root, args, config)
    databases = cast(Mapping[str, Any], config["databases"])
    source_root = root / "data/interim/phase6_project_sources"
    fixed_root = args.fixed_root or Path(str(databases["fixed_root"]))
    if not fixed_root.is_absolute():
        fixed_root = root / fixed_root
    fixed_root.mkdir(parents=True, exist_ok=True)
    status_path = fixed_root / "build_status.jsonl"
    records = read_jsonl(status_path)
    by_id = {str(row["project_id"]): row for row in records}
    selected_ids = {row["project_id"] for row in rows}
    target_files = _target_source_files(root, config, selected_ids)
    machine = effective_env(root / ".env")
    codeql = _codeql_binary(machine)
    toolchain = _mapping(root / "configs/toolchains/cwe_bench_java.yaml")
    manifest = _write_preparation_state(root, fixed_root, by_id, config, config_path)
    try:
        for position, row in enumerate(rows, start=1):
            project_id = row["project_id"]
            destination = fixed_root / project_id
            if (destination / "codeql-database.yml").is_file():
                if by_id.get(project_id, {}).get("status") != "SUCCESS":
                    by_id[project_id] = {
                        "schema_version": 1,
                        "project_id": project_id,
                        "status": "SUCCESS",
                        "reason": "existing opaque fixed database retained",
                        "attempts": [],
                        "updated_at": utc_now(),
                    }
                    manifest = _write_preparation_state(
                        root, fixed_root, by_id, config, config_path
                    )
                continue
            if destination.exists() or destination.is_symlink():
                raise ValueError(f"invalid fixed database destination: {project_id}")
            source = source_root / project_id
            fix_commits = [value for value in row["fix_commit_ids"].split(";") if value]
            started = time.monotonic()
            attempts: list[dict[str, Any]] = []
            success = False
            reason = "all compatible fixed-revision build attempts failed"
            checkout_method: str | None = None
            modules: tuple[str, ...] = ()
            if not source.is_dir() or not fix_commits:
                reason = "vulnerable source repository or fixed revision is unavailable"
            else:
                fixed_revision = _resolve_fixed_revision(source, fix_commits[-1])
                upstream = _run(["git", "remote", "get-url", "origin"], cwd=source)
                upstream_url = upstream.stdout.strip() if upstream.returncode == 0 else ""
                with tempfile.TemporaryDirectory(
                    prefix=f".{project_id}.fixed-", dir=fixed_root
                ) as temporary:
                    temporary_root = Path(temporary)
                    checkout = temporary_root / "source"
                    fetched, checkout_detail = _checkout_fixed_revision(
                        source,
                        checkout,
                        fixed_revision,
                        upstream_url,
                        timeout=args.fetch_timeout,
                    )
                    if not fetched:
                        reason = "fixed revision checkout failed: " + checkout_detail
                    else:
                        checkout_method = checkout_detail
                        modules = _maven_modules(checkout, target_files[project_id])
                        compatible = _compatible_attempts(row, toolchain, checkout)
                        if not compatible and args.build_mode == "manual":
                            reason = "no compatible pinned build toolchain is available"
                        modes = (
                            [(attempt, "manual") for attempt in compatible]
                            if args.build_mode in {"auto", "manual"}
                            else []
                        )
                        if args.build_mode in {"auto", "none"}:
                            modes.append((_preferred_attempt(row), "none"))
                        for number, (attempt, mode) in enumerate(modes, start=1):
                            attempt_started = time.monotonic()
                            if not _reset_checkout(checkout):
                                attempts.append(
                                    {
                                        "number": number,
                                        "toolchain": attempt,
                                        "build_mode": mode,
                                        "outcome": "UNAVAILABLE",
                                        "reason": "isolated fixed checkout could not be reset",
                                        "seconds": round(time.monotonic() - attempt_started, 3),
                                    }
                                )
                                break
                            try:
                                command, environment = build_command_and_env(
                                    root, checkout, attempt, toolchain, machine
                                )
                                environment = _stabilize_build_environment(environment, attempt)
                                if mode == "manual":
                                    command = _tailored_build_command(command, attempt, modules)
                            except ValueError as error:
                                if mode == "manual":
                                    attempts.append(
                                        {
                                            "number": number,
                                            "toolchain": attempt,
                                            "build_mode": mode,
                                            "outcome": "UNAVAILABLE",
                                            "reason": str(error),
                                            "seconds": round(time.monotonic() - attempt_started, 3),
                                        }
                                    )
                                    continue
                                environment = dict(os.environ)
                            database = temporary_root / f"database-{number:02d}"
                            codeql_command = [
                                str(codeql),
                                "database",
                                "create",
                                str(database),
                                "--language=java",
                                "--threads=4",
                                "--ram=16384",
                                f"--source-root={checkout}",
                            ]
                            if mode == "manual":
                                codeql_command.append(f"--command={shlex.join(command)}")
                            else:
                                codeql_command.append("--build-mode=none")
                            try:
                                process = _run(
                                    codeql_command,
                                    cwd=checkout,
                                    timeout=args.timeout,
                                    env=environment,
                                )
                                exit_code: int | None = process.returncode
                                log_text = (
                                    f"command={shlex.join(codeql_command)}\n"
                                    f"stdout:\n{process.stdout}\n"
                                    f"stderr:\n{process.stderr}"
                                )
                            except subprocess.TimeoutExpired as error:
                                exit_code = None
                                log_text = (
                                    f"timeout_seconds={args.timeout}\n"
                                    f"stdout={error.stdout!r}\n"
                                    f"stderr={error.stderr!r}"
                                )
                            log = fixed_root / "logs" / project_id
                            log.mkdir(parents=True, exist_ok=True)
                            (log / f"attempt_{number:02d}.log").write_text(
                                log_text, encoding="utf-8", newline="\n"
                            )
                            database_ready = (
                                exit_code == 0 and (database / "codeql-database.yml").is_file()
                            )
                            attempt_record: dict[str, Any] = {
                                "number": number,
                                "toolchain": attempt,
                                "build_mode": mode,
                                "outcome": "SUCCESS" if database_ready else "FAILED",
                                "exit_code": exit_code,
                                "seconds": round(time.monotonic() - attempt_started, 3),
                            }
                            if database_ready:
                                node_files, node_error = _node_files(
                                    codeql,
                                    database,
                                    root / "src/static_analysis/queries/phase7_nodes.ql",
                                    args.timeout,
                                )
                                attempt_record["java_node_files"] = len(node_files)
                                attempt_record["endpoint_files_matched"] = len(
                                    node_files & set(target_files[project_id])
                                )
                                if node_error or not node_files:
                                    attempt_record["outcome"] = "NO_JAVA_NODES"
                                    attempt_record["reason"] = (
                                        node_error or "no Java nodes extracted"
                                    )
                            attempts.append(attempt_record)
                            if attempt_record["outcome"] == "SUCCESS":
                                os.replace(database, destination)
                                success = True
                                reason = f"fixed-revision CodeQL database built with {mode}"
                                break
            by_id[project_id] = {
                "schema_version": 1,
                "project_id": project_id,
                "status": "SUCCESS" if success else "CODEQL_DB_FAILED",
                "reason": reason,
                "checkout_method": checkout_method,
                "target_module_count": len(modules),
                "attempts": attempts,
                "seconds": round(time.monotonic() - started, 3),
                "updated_at": utc_now(),
            }
            manifest = _write_preparation_state(root, fixed_root, by_id, config, config_path)
            print(
                f"[{position}/{len(rows)}] {project_id}: {by_id[project_id]['status']}",
                flush=True,
            )
    except KeyboardInterrupt:
        _write_preparation_state(root, fixed_root, by_id, config, config_path)
        raise
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 1 if any(by_id[row["project_id"]]["status"] != "SUCCESS" for row in rows) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase11_static_verification.yaml")
    )
    parser.add_argument("--project-id")
    parser.add_argument("--fixed-root", type=Path)
    parser.add_argument("--build-mode", choices=("auto", "manual", "none"), default="auto")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--fetch-timeout", type=int, default=300)
    return parser


def main() -> int:
    return prepare(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
