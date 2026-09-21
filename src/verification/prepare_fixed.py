"""Build evaluator-only, opaque fixed-revision CodeQL databases for Phase 11."""

from __future__ import annotations

import argparse
import json
import os
import shlex
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
from src.graphs.program.build_databases import _attempts, _codeql_binary
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl

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
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


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


def _selected_rows(root: Path, args: argparse.Namespace) -> list[dict[str, str]]:
    development_path = root / "data/processed/splits/development.csv"
    test_path = root / "data/processed/splits/test_locked.csv"
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    analysis_path = root / "data/processed/analysis_input/D_extended_projects.csv"
    phase10_status_path = root / PHASE10_STATUS
    development = [row["project_id"] for row in read_csv(development_path)]
    locked = {row["project_id"] for row in read_csv(test_path)}
    if set(development) & locked:
        raise ValueError("development and locked-test splits overlap")
    labels = {row["project_id"]: row for row in read_csv(labels_path)}
    analysis = {row["project_id"]: row for row in read_csv(analysis_path)}
    if set(development) - labels.keys() or set(development) - analysis.keys():
        raise ValueError("development projects do not resolve to fixed labels/build metadata")
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
        for project_id in development
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


def prepare(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("fixed-revision preparation requires MAXVERA_DATA_ROLE=evaluator")
    rows = _selected_rows(root, args)
    config = _mapping(root / "configs/experiments/phase11_static_verification.yaml")
    databases = cast(Mapping[str, Any], config["databases"])
    source_root = root / "data/interim/phase6_project_sources"
    fixed_root = root / str(databases["fixed_root"])
    fixed_root.mkdir(parents=True, exist_ok=True)
    status_path = fixed_root / "build_status.jsonl"
    records = read_jsonl(status_path)
    by_id = {str(row["project_id"]): row for row in records}
    machine = effective_env(root / ".env")
    codeql = _codeql_binary(machine)
    toolchain = _mapping(root / "configs/toolchains/cwe_bench_java.yaml")
    for position, row in enumerate(rows, start=1):
        project_id = row["project_id"]
        destination = fixed_root / project_id
        if (destination / "codeql-database.yml").is_file():
            by_id[project_id] = {
                "schema_version": 1,
                "project_id": project_id,
                "status": "SUCCESS",
                "reason": "existing opaque fixed database retained",
                "attempts": [],
                "updated_at": utc_now(),
            }
            continue
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"invalid fixed database destination: {project_id}")
        source = source_root / project_id
        fix_commits = [value for value in row["fix_commit_ids"].split(";") if value]
        started = time.monotonic()
        attempts: list[dict[str, Any]] = []
        success = False
        reason = "all fixed-revision build attempts failed or were unavailable"
        if not source.is_dir() or not fix_commits:
            reason = "vulnerable source repository or fixed revision is unavailable"
        else:
            fixed_revision = _resolve_fixed_revision(source, fix_commits[-1])
            upstream = _run(["git", "remote", "get-url", "origin"], cwd=source)
            upstream_url = upstream.stdout.strip() if upstream.returncode == 0 else ""
            for number, attempt in enumerate(_attempts(row, toolchain), start=1):
                attempt_started = time.monotonic()
                with tempfile.TemporaryDirectory(
                    prefix=f".{project_id}.fixed-", dir=fixed_root
                ) as temporary:
                    temporary_root = Path(temporary)
                    checkout = temporary_root / "source"
                    checkout.mkdir()
                    initialized = _run(["git", "init", "--quiet"], cwd=checkout)
                    remote = (
                        _run(["git", "remote", "add", "origin", upstream_url], cwd=checkout)
                        if initialized.returncode == 0 and upstream_url
                        else initialized
                    )
                    if remote.returncode == 0:
                        fetch = _run(
                            [
                                "git",
                                "fetch",
                                "--quiet",
                                "--filter=blob:none",
                                "--depth=1",
                                "origin",
                                fixed_revision,
                            ],
                            cwd=checkout,
                            timeout=args.fetch_timeout,
                        )
                        switch = (
                            _run(
                                ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                                cwd=checkout,
                            )
                            if fetch.returncode == 0
                            else fetch
                        )
                    else:
                        switch = remote
                    if switch.returncode != 0:
                        attempts.append(
                            {
                                "number": number,
                                "toolchain": attempt,
                                "outcome": "UNAVAILABLE",
                                "reason": (
                                    "fixed revision could not be fetched into the opaque checkout"
                                ),
                                "seconds": round(time.monotonic() - attempt_started, 3),
                            }
                        )
                        break
                    try:
                        command, environment = build_command_and_env(
                            root, checkout, attempt, toolchain, machine
                        )
                    except ValueError as error:
                        attempts.append(
                            {
                                "number": number,
                                "toolchain": attempt,
                                "outcome": "UNAVAILABLE",
                                "reason": str(error),
                                "seconds": round(time.monotonic() - attempt_started, 3),
                            }
                        )
                        continue
                    database = temporary_root / "database"
                    codeql_command = [
                        str(codeql),
                        "database",
                        "create",
                        str(database),
                        "--language=java",
                        "--threads=4",
                        "--ram=16384",
                        f"--source-root={checkout}",
                        f"--command={shlex.join(command)}",
                    ]
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
                    attempts.append(
                        {
                            "number": number,
                            "toolchain": attempt,
                            "outcome": "SUCCESS" if exit_code == 0 else "FAILED",
                            "exit_code": exit_code,
                            "seconds": round(time.monotonic() - attempt_started, 3),
                        }
                    )
                    if exit_code == 0 and (database / "codeql-database.yml").is_file():
                        os.replace(database, destination)
                        success = True
                        reason = "opaque fixed-revision CodeQL database built"
                        break
        by_id[project_id] = {
            "schema_version": 1,
            "project_id": project_id,
            "status": "SUCCESS" if success else "CODEQL_DB_FAILED",
            "reason": reason,
            "attempts": attempts,
            "seconds": round(time.monotonic() - started, 3),
            "updated_at": utc_now(),
        }
        atomic_jsonl(status_path, [by_id[key] for key in sorted(by_id)])
        print(f"[{position}/{len(rows)}] {project_id}: {by_id[project_id]['status']}", flush=True)
    counts = Counter(str(row["status"]) for row in by_id.values())
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "strategy": "evaluator_only_last_fix_revision_to_opaque_project_database",
        "development_only": True,
        "locked_test_prepared": False,
        "identity_mapping_persisted": False,
        "labels_sha256": sha256_file(root / "data/processed/evaluator_only/D_extended_labels.csv"),
        "development_split_sha256": sha256_file(root / "data/processed/splits/development.csv"),
        "phase10_project_status_sha256": sha256_file(root / PHASE10_STATUS),
        "eligible_phase10_projects": sum(
            row.get("status") == "SUCCESS" for row in read_jsonl(root / PHASE10_STATUS)
        ),
        "status_sha256": sha256_file(status_path),
        "phase11_config_sha256": sha256_file(
            root / "configs/experiments/phase11_static_verification.yaml"
        ),
        "implementation_sha256": sha256_file(root / "src/verification/prepare_fixed.py"),
        "successful_databases": counts["SUCCESS"],
        "failed_databases": counts["CODEQL_DB_FAILED"],
    }
    atomic_json(fixed_root / "preparation_manifest.json", manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 1 if any(by_id[row["project_id"]]["status"] != "SUCCESS" for row in rows) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--project-id")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--fetch-timeout", type=int, default=300)
    return parser


def main() -> int:
    return prepare(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
