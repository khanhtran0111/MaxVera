"""Run the B0 CodeQL zero-hint baseline on the Phase 13 opaque test split."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from src.common.envfile import effective_env
from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums
from src.reproduction.runner import _codeql_binary, _codeql_version, _resolve_query

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FINAL = {"SUCCESS", "ANALYSIS_FAILED"}


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _save_statuses(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    atomic_jsonl(path / "project_status.jsonl", rows)
    counts = Counter(str(row["status"]) for row in rows)
    atomic_json(
        path / "status_summary.json",
        {"schema_version": 1, "total": len(rows), "counts": dict(sorted(counts.items()))},
    )


def _run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if os.environ.get("MAXVERA_DATA_ROLE") != "analyzer":
        raise ValueError("B0 locked-test analysis requires MAXVERA_DATA_ROLE=analyzer")
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("invalid B0 run ID")
    split = root / args.split
    database_root = root / args.database_root
    output_root = root / args.output_root
    final = output_root / args.run_id
    work = output_root / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable B0 result exists: {final}")
    selected = [row["project_id"] for row in read_csv(split)]
    if len(selected) != 24 or len(set(selected)) != 24:
        raise ValueError("B0 Phase 13 requires the frozen 24-project test split")
    machine = effective_env(root / ".env")
    codeql = _codeql_binary(machine.get("MAXVERA_CODEQL_HOME", ""))
    if not codeql.is_file():
        raise FileNotFoundError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    query = _resolve_query(root, "B0", "", codeql)
    if args.resume:
        if not work.is_dir():
            raise FileNotFoundError(f"no B0 in-progress run to resume: {work}")
        statuses = read_jsonl(work / "project_status.jsonl")
    else:
        if work.exists():
            raise FileExistsError(f"unfinished B0 run exists; use --resume: {work}")
        work.mkdir(parents=True)
        statuses = [
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": "PENDING",
                "reason": "selected locked-test project waiting for zero-hint CodeQL",
                "updated_at": utc_now(),
            }
            for project_id in selected
        ]
        _write(work / "STATUS", "RUNNING\n")
        _write(work / "command.txt", shlex.join(sys.argv) + "\n")
        atomic_json(work / "environment.json", collect_environment(root))
        atomic_json(
            work / "manifest.json",
            {
                "schema_version": 1,
                "phase": 13,
                "baseline_id": "B0",
                "run_id": args.run_id,
                "mode": "full",
                "analysis_scope": "test_locked",
                "created_at": utc_now(),
                "git": collect_git(root),
                "selected_project_ids": selected,
                "selected_project_count": len(selected),
                "data_access": "opaque test IDs and CodeQL databases only; no labels",
                "split": args.split.as_posix(),
                "split_sha256": sha256_file(split),
                "database_root": args.database_root.as_posix(),
                "codeql": {
                    "version": _codeql_version(codeql),
                    "query_suite": "java-security-extended",
                },
                "implementation_sha256": sha256_file(
                    root / "src/experiments/phase13_b0.py"
                ),
            },
        )
        _save_statuses(work, statuses)
    by_id = {str(row["project_id"]): row for row in statuses}
    resources = read_jsonl(work / "resource_usage.jsonl")
    for position, project_id in enumerate(selected, start=1):
        status = by_id[project_id]
        if status.get("status") in FINAL:
            continue
        started = time.monotonic()
        database = database_root / project_id
        sarif = work / "projects" / project_id / "results.sarif"
        log = work / "projects" / project_id / "analysis.log"
        try:
            if not (database / "codeql-database.yml").is_file():
                raise FileNotFoundError("opaque CodeQL database is unavailable")
            sarif.parent.mkdir(parents=True, exist_ok=True)
            command = [
                str(codeql),
                "database",
                "analyze",
                "--rerun",
                "--threads=2",
                "--ram=8192",
                "--format=sarif-latest",
                f"--output={sarif}",
                str(database),
                query,
            ]
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
            _write(
                log,
                f"command={shlex.join(command)}\nexit_code={process.returncode}\n"
                f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}",
            )
            if process.returncode or not sarif.is_file():
                raise RuntimeError(f"CodeQL analysis failed with status {process.returncode}")
            loaded = json.loads(sarif.read_text(encoding="utf-8"))
            runs = cast(list[dict[str, Any]], loaded.get("runs", []))
            alerts = sum(len(cast(list[Any], run.get("results", []))) for run in runs)
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "CodeQL zero-hint suite completed",
                    "alerts": alerts,
                    "sarif": sarif.relative_to(work).as_posix(),
                    "updated_at": utc_now(),
                }
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": f"{type(error).__name__}: {str(error)[:500]}",
                    "updated_at": utc_now(),
                }
            )
        resources = [row for row in resources if row.get("project_id") != project_id]
        resources.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "wall_seconds": round(time.monotonic() - started, 3),
            }
        )
        atomic_jsonl(work / "resource_usage.jsonl", resources)
        _save_statuses(work, statuses)
        print(f"[{position}/{len(selected)}] {project_id}: {status['status']}", flush=True)
    failures = [row for row in statuses if row.get("status") != "SUCCESS"]
    _write(work / "STATUS", "FAILED\n" if failures else "SUCCESS\n")
    write_checksums(work)
    os.replace(work, final)
    print(
        f"Phase 13 B0 completed: {final} "
        f"({len(selected) - len(failures)}/{len(selected)} successful)"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--split", type=Path, default=Path("data/processed/splits/test_locked.csv"))
    parser.add_argument("--database-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
