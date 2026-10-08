"""Prepare opaque fixed databases from the actual v2 synthesis cohort."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file
from src.data.build_projects import build_command_and_env
from src.graphs.program.build_databases import _node_files, _preferred_attempt
from src.graphs.program.runner import _run_command
from src.pipeline_v2.calibration import _development_rows
from src.pipeline_v2.recovery import database_environment
from src.pipeline_v2.runtime import Run, codeql, configuration, dependency, development_ids
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl
from src.verification.prepare_fixed import (
    _checkout_fixed_revision,
    _compatible_attempts,
    _maven_modules,
    _reset_checkout,
    _resolve_fixed_revision,
    _stabilize_build_environment,
    _tailored_build_command,
)


def target_files(specifications: Sequence[Mapping[str, Any]], project: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                entry["descriptor"]["file"]
                for specification in specifications
                if specification["project_id"] == project
                for entry in specification["frozen_endpoints"]
            }
        )
    )


def parent_databases(root: Path, config: Mapping[str, Any]) -> tuple[Path, dict[str, str]]:
    policy = config["fixed_preparation"]
    parent = root / policy["parent_root"]
    manifest_path, status_path = parent / "preparation_manifest.json", parent / "build_status.jsonl"
    lock = {
        "manifest_sha256": sha256_file(manifest_path),
        "status_sha256": sha256_file(status_path),
    }
    if any(lock[name] != policy["parent_" + name] for name in lock):
        raise ValueError("historical fixed preparation changed")
    manifest = json.loads(manifest_path.read_text())
    if (
        manifest.get("development_only") is not True
        or manifest.get("locked_test_prepared") is not False
        or manifest.get("identity_mapping_persisted") is not False
        or manifest.get("preparation_complete") is not True
        or manifest.get("labels_sha256") != config["dataset"]["labels_sha256"]
        or manifest.get("status_sha256") != lock["status_sha256"]
        or manifest.get("development_split_sha256") != config["dataset"]["development_split_sha256"]
    ):
        raise ValueError("fixed parent is not the registered development preparation")
    return parent, lock


def _build(
    root: Path,
    config: Mapping[str, Any],
    project: str,
    row: Mapping[str, str],
    files: Sequence[str],
    destination: Path,
    logs: Path,
) -> dict[str, Any]:
    policy = config["fixed_preparation"]
    source = root / policy["source_root"] / project
    revisions = [value for value in row["fix_commit_ids"].split(";") if value]
    if not source.is_dir() or not revisions:
        raise ValueError("source repository or fixed revision is unavailable")
    machine = effective_env(root / ".env")
    toolchain = yaml.safe_load((root / "configs/toolchains/cwe_bench_java.yaml").read_text())
    binary = codeql(root, config["codeql"])
    revision = _resolve_fixed_revision(source, revisions[-1])
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    with tempfile.TemporaryDirectory(prefix=f".{project}.", dir=destination.parent) as temporary:
        scratch = Path(temporary)
        checkout = scratch / "source"
        fetched, method = _checkout_fixed_revision(
            source,
            checkout,
            revision,
            remote.stdout.strip() if remote.returncode == 0 else "",
            timeout=int(policy["fetch_timeout_seconds"]),
        )
        if not fetched:
            raise RuntimeError("fixed revision checkout failed: " + method)
        modes = [(attempt, "manual") for attempt in _compatible_attempts(row, toolchain, checkout)]
        modes.append((_preferred_attempt(row), "none"))
        logs.mkdir(parents=True, exist_ok=True)
        attempts = []
        for number, (attempt, mode) in enumerate(modes, 1):
            database = scratch / f"database-{number}"
            try:
                if shutil.disk_usage(root).free < int(policy["minimum_free_disk_gib"]) * 1024**3:
                    raise RuntimeError("fixed extraction disk reserve exhausted")
                if not _reset_checkout(checkout):
                    raise RuntimeError("isolated fixed checkout could not be reset")
                if mode == "manual":
                    build_command, environment = build_command_and_env(
                        root,
                        checkout,
                        attempt,
                        toolchain,
                        machine,
                    )
                    environment = _stabilize_build_environment(environment, attempt)
                    build_command = _tailored_build_command(
                        build_command,
                        attempt,
                        _maven_modules(checkout, files),
                    )
                else:
                    # No minimal-JDK fallback: extraction must use the pinned toolchain.
                    environment, _ = database_environment(root, row, toolchain, machine)
                command = [
                    str(binary),
                    "database",
                    "create",
                    str(database),
                    "--language=java",
                    f"--threads={config['codeql']['threads']}",
                    f"--ram={config['codeql']['ram_mb']}",
                    f"--source-root={checkout}",
                    f"--command={shlex.join(build_command)}"
                    if mode == "manual"
                    else "--build-mode=none",
                ]
                result = _run_command(
                    command,
                    cwd=checkout,
                    env=environment,
                    timeout=int(policy["build_timeout_seconds"]),
                )
                (logs / f"attempt_{number}.log").write_text(
                    f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}",
                )
                if result.returncode or not (database / "src.zip").is_file():
                    raise RuntimeError("fixed extraction failed; see attempt log")
                java_files, error = _node_files(
                    binary,
                    database,
                    root / "src/static_analysis/queries/phase7_nodes.ql",
                    int(policy["build_timeout_seconds"]),
                )
                if error or not java_files:
                    raise RuntimeError(error or "fixed extraction contains no Java nodes")
                attempts.append({"build_mode": mode, "toolchain": attempt, "outcome": "SUCCESS"})
                shutil.move(str(database), str(destination))
                return {"checkout_method": method, "build_mode": mode, "attempts": attempts}
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                attempts.append(
                    {
                        "build_mode": mode,
                        "toolchain": attempt,
                        "outcome": "FAILED",
                        "reason": str(error),
                    }
                )
                atomic_json(logs / "attempts.json", {"attempts": attempts})
        raise RuntimeError("all pinned fixed extraction attempts failed; see attempts.json")


def prepare(
    root: Path,
    config: Mapping[str, Any],
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    phase10_relative: str,
    *,
    resume: bool = False,
    full: bool = False,
) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("fixed preparation requires a separate evaluator process")
    upstream, upstream_lock = dependency(root, phase10_relative, selected, 10)
    manifest = json.loads((upstream / "manifest.json").read_text())
    if (
        manifest["dependencies"].get("dry_run")
        or manifest["dependencies"].get("baseline_id") != "B9"
    ):
        raise ValueError("fixed preparation requires actual B9 v2 specifications")
    parent, parent_lock = parent_databases(root, config)
    dataset = config["dataset"]
    labels_path = root / dataset["labels"]
    if sha256_file(labels_path) != dataset["labels_sha256"]:
        raise ValueError("development fixed labels checksum mismatch")
    labels = _development_rows(labels_path, set(selected))
    metadata = {
        row["project_id"]: row
        for row in read_csv(
            root / "data/processed/analysis_input/D_extended_projects.csv",
        )
        if row["project_id"] in selected
    }
    run = Run(
        root,
        "results/pipeline_v2/fixed_preparation",
        run_id,
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=full,
        dependencies={
            "phase10": upstream_lock,
            "fixed_parent": parent_lock,
            "labels_sha256": dataset["labels_sha256"],
        },
    )
    run_manifest = json.loads((run.work / "manifest.json").read_text())
    atomic_json(
        run.work / "manifest.json",
        {
            **run_manifest,
            "data_access": "development evaluator-only fixed revisions and build metadata",
        },
    )
    database_root = root / dataset["fixed_database_root"] / run_id
    if not database_root.resolve().is_relative_to((root / "data/interim").resolve()):
        raise ValueError("fixed preparation destination is outside data/interim")
    database_root.mkdir(parents=True, exist_ok=True)
    specs = read_jsonl(upstream / "specifications.jsonl")
    statuses = {row["project_id"]: row for row in read_jsonl(upstream / "project_status.jsonl")}
    parent_success = {
        row["project_id"]
        for row in read_jsonl(parent / "build_status.jsonl")
        if row["status"] == "SUCCESS"
    }
    provenance = read_jsonl(run.work / "databases.jsonl")
    for project in run.pending():
        if statuses[project]["status"] != "SUCCESS" or not target_files(specs, project):
            run.status(
                project, "EXCLUDED_WITH_REASON", "no successful synthesis requiring fixed DB"
            )
            continue
        destination = database_root / project
        try:
            record = next((value for value in provenance if value["project_id"] == project), None)
            if destination.exists() or destination.is_symlink():
                if record is None:
                    raise ValueError("fixed destination exists without checkpoint provenance")
                if any(
                    sha256_file(destination / filename) != record[name]
                    for filename, name in (
                        ("src.zip", "source_archive_sha256"),
                        ("codeql-database.yml", "metadata_sha256"),
                    )
                ):
                    raise ValueError("fixed database checkpoint changed")
            else:
                extra: dict[str, Any]
                previous = parent / project
                if (
                    project in parent_success
                    and (previous / "src.zip").is_file()
                    and (previous / "codeql-database.yml").is_file()
                ):
                    destination.symlink_to(previous.resolve(), target_is_directory=True)
                    extra = {"build_mode": "historical", "parent": parent_lock}
                else:
                    if project not in labels or project not in metadata:
                        raise ValueError("development fixed target/build metadata is unavailable")
                    extra = _build(
                        root,
                        config,
                        project,
                        {**metadata[project], "fix_commit_ids": labels[project]["fix_commit_ids"]},
                        target_files(specs, project),
                        destination,
                        run.work / "logs" / project,
                    )
                record = {
                    "project_id": project,
                    "source_archive_sha256": sha256_file(destination / "src.zip"),
                    "metadata_sha256": sha256_file(destination / "codeql-database.yml"),
                    **extra,
                }
                provenance.append(record)
                atomic_jsonl(run.work / "databases.jsonl", provenance)
            run.status(
                project, "SUCCESS", "opaque fixed database prepared with recorded provenance"
            )
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            run.status(project, "CODEQL_DB_FAILED", str(error))
    atomic_jsonl(database_root / "build_status.jsonl", run.statuses)
    preparation = {
        "schema_version": 2,
        "development_only": True,
        "locked_test_prepared": False,
        "identity_mapping_persisted": False,
        "preparation_complete": not run.pending(),
        "development_split_sha256": dataset["development_split_sha256"],
        "labels_sha256": dataset["labels_sha256"],
        "phase10_manifest_sha256": upstream_lock["manifest_sha256"],
        "database_root": database_root.relative_to(root).as_posix(),
        "status_sha256": sha256_file(database_root / "build_status.jsonl"),
        "parent": parent_lock,
    }
    atomic_json(database_root / "preparation_manifest.json", preparation)
    atomic_json(run.work / "preparation_manifest.json", preparation)
    return run.finalize({"prepared_databases": len(provenance), "llm_calls": 0})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--phase10-run", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=["pilot", "full"], required=True)
    parser.add_argument("--project-id")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    if (args.mode == "pilot") != bool(args.project_id):
        parser.error("pilot requires one development project; full must cover all development")
    path = root / args.config
    output = prepare(
        root,
        configuration(root, path),
        path,
        development_ids(root, project_id=args.project_id),
        args.run_id,
        args.phase10_run,
        resume=args.resume,
        full=args.mode == "full",
    )
    print(output.relative_to(root), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
