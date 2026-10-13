"""Inspect all registered inputs and optionally repair extraction, without LLM calls.

Fixed revisions are inspected only in this evaluator process. Its report/cache must
not be used as an analyzer prompt or a discovery input.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file, utc_now
from src.pipeline_v2.coverage import require_coverage, source_coverage
from src.pipeline_v2.extraction import create_complete_database
from src.pipeline_v2.recovery import database_environment
from src.pipeline_v2.runtime import codeql, configuration, selection_ids
from src.reproduction.common import atomic_json, read_csv
from src.verification.prepare_fixed import _checkout_fixed_revision, _resolve_fixed_revision


def extract(
    root: Path,
    config: dict[str, Any],
    project: str,
    metadata: dict[str, str],
    revision: str,
    destination: Path,
    logs: Path,
    cancelled: threading.Event | None = None,
) -> None:
    """Extract a clean isolated revision; install only a coverage-checked database."""
    if destination.exists() or destination.is_symlink():
        raise ValueError("repair destination already exists")
    if shutil.disk_usage(root).free < config["benchmark"]["minimum_free_disk_gib"] * 1024**3:
        raise RuntimeError("extraction disk reserve exhausted")
    source = root / config["fixed_preparation"]["source_root"] / project
    toolchain = yaml.safe_load((root / "configs/toolchains/cwe_bench_java.yaml").read_text())
    environment, _ = database_environment(root, metadata, toolchain, effective_env(root / ".env"))
    binary = codeql(root, config["codeql"])
    logs.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    with tempfile.TemporaryDirectory(prefix=f".{project}.", dir=destination.parent) as scratch:
        checkout, database = Path(scratch) / "source", Path(scratch) / "database"
        fetched, method = _checkout_fixed_revision(
            source,
            checkout,
            revision,
            remote.stdout.strip() if remote.returncode == 0 else "",
            timeout=config["fixed_preparation"]["fetch_timeout_seconds"],
        )
        if not fetched:
            raise RuntimeError("isolated checkout failed: " + method)
        policy = {**config["codeql"], **config["fixed_preparation"].get("extraction_resources", {})}
        try:
            create_complete_database(
                binary, checkout, database, logs, policy, environment, cancelled=cancelled
            )
            coverage = source_coverage(
                database,
                source,
                config["execution"]["minimum_application_source_coverage"],
                revision,
            )
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            if database.exists():
                rejected = destination.parent / "rejected" / destination.name
                rejected.mkdir(parents=True, exist_ok=True)
                retained = rejected / Path(scratch).name.lstrip(".")
                shutil.move(str(database), str(retained))
            raise
        atomic_json(logs / "source_coverage.json", coverage)
        if not coverage["ready"]:
            # Retain the failed extraction for diagnosis/re-evaluation. It never
            # receives SUCCESS merely because CodeQL creation returned zero.
            rejected = destination.parent / "rejected" / destination.name
            rejected.mkdir(parents=True, exist_ok=True)
            retained = rejected / Path(scratch).name.lstrip(".")
            shutil.move(str(database), str(retained))
            atomic_json(retained / "coverage_failure.json", coverage)
            raise ValueError(
                "APPLICATION_COVERAGE_FAILED: "
                f"{coverage['covered_application_files']}/{coverage['expected_application_files']} "
                f"tracked application Java files extracted; retained at {retained}"
            )
        shutil.move(str(database), str(destination))


def inspect(
    root: Path, config_path: Path, output: Path, *, repair: bool = False, workers: int = 1
) -> dict[str, Any]:
    """Serialize cache access and leave a durable lifecycle record on every exit."""
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("readiness requires an evaluator process for fixed revision inspection")
    output = output.resolve()
    if not output.is_relative_to((root / "results/diagnostics").resolve()):
        raise ValueError("readiness output must be inside results/diagnostics")
    config = configuration(root, config_path)
    cache = root / config["fixed_preparation"]["coverage_cache_root"]
    if not cache.resolve().is_relative_to((root / "data/interim").resolve()):
        raise ValueError("coverage cache must be inside data/interim")
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / ".readiness.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another readiness process owns this cache") from error
        output.mkdir(parents=True, exist_ok=True)
        lifecycle = {"pid": os.getpid(), "started_at": utc_now(), "repair": repair}
        atomic_json(output / "lifecycle.json", {**lifecycle, "status": "RUNNING"})
        try:
            report = _inspect(root, config_path, output, repair=repair, workers=workers)
        except BaseException as error:
            atomic_json(
                output / "lifecycle.json",
                {
                    **lifecycle,
                    "status": "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "FAILED",
                    "finished_at": utc_now(),
                    "error": f"{type(error).__name__}: {error}",
                },
            )
            raise
        atomic_json(
            output / "lifecycle.json",
            {**lifecycle, "status": report["status"], "finished_at": utc_now()},
        )
        return report


def _inspect(
    root: Path, config_path: Path, output: Path, *, repair: bool = False, workers: int = 1
) -> dict[str, Any]:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("readiness requires an evaluator process for fixed revision inspection")
    config = configuration(root, config_path)
    selected = selection_ids(root, config)
    output = output.resolve()
    if not output.is_relative_to((root / "results/diagnostics").resolve()):
        raise ValueError("readiness output must be inside results/diagnostics")
    output.mkdir(parents=True, exist_ok=True)
    metadata = {r["project_id"]: r for r in read_csv(root / config["dataset"]["population"])}
    labels = {r["project_id"]: r for r in read_csv(root / config["dataset"]["labels"])}
    if sha256_file(root / config["dataset"]["labels"]) != config["dataset"]["labels_sha256"]:
        raise ValueError("fixed labels checksum mismatch")
    signature = {
        "config_sha256": sha256_file(config_path),
        "selected_project_ids": selected,
        "coverage_policy_sha256": sha256_file(root / "src/pipeline_v2/coverage.py"),
        "extraction_policy_sha256": sha256_file(Path(__file__).with_name("extraction.py")),
    }
    signature_path = output / "inputs.json"
    if signature_path.exists() and json.loads(signature_path.read_text()) != signature:
        raise ValueError("readiness inputs changed; choose a new output directory")
    atomic_json(signature_path, signature)
    cache = root / config["fixed_preparation"]["coverage_cache_root"]
    if not cache.resolve().is_relative_to((root / "data/interim").resolve()):
        raise ValueError("coverage cache must be inside data/interim")
    minimum = config["execution"]["minimum_application_source_coverage"]
    if not 1 <= workers <= 3:
        raise ValueError("readiness workers must be between 1 and 3")
    rows: list[dict[str, Any]] = []
    progress: dict[str, dict[str, Any]] = {
        project: {"project_id": project, "status": "PENDING"} for project in selected
    }
    atomic_json(output / "projects.json", {"projects": list(progress.values())})
    cancelled = threading.Event()
    pool_lock = threading.Lock()
    database_pool: dict[tuple[str, ...], Path] = {}

    def inspect_project(project: str, do_repair: bool = False) -> dict[str, Any]:
        source = root / config["fixed_preparation"]["source_root"] / project
        row: dict[str, Any] = {"project_id": project, "status": "BLOCKED"}
        for side in ("vulnerable", "fixed"):
            if cancelled.is_set():
                raise RuntimeError("readiness interrupted")
            destination = cache / side / project
            try:
                revision = (
                    subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=source, text=True
                    ).strip()
                    if side == "vulnerable"
                    else (
                        _resolve_fixed_revision(
                            source, labels[project]["fix_commit_ids"].split(";")[-1]
                        )
                    )
                )
                rejected_root = destination.parent / "rejected" / project
                candidates = [destination, *sorted(rejected_root.glob("*"))]
                reuse_key = (
                    side,
                    revision,
                    *(
                        metadata[project].get(key, "")
                        for key in ("jdk_version", "maven_version", "gradle_version")
                    ),
                )
                shared = None
                if config["fixed_preparation"].get("reuse_exact_revision_databases"):
                    with pool_lock:
                        shared = database_pool.get(reuse_key)
                    if shared is not None:
                        candidates.insert(0, shared)
                if side == "vulnerable":
                    candidates += [
                        root / rel / project
                        for rel in [
                            config["dataset"]["vulnerable_database_root"],
                            *config["benchmark"]["vulnerable_parent_roots"],
                        ]
                    ]
                else:
                    candidates += [
                        root / config["fixed_preparation"]["parent_root"] / project,
                        root / config["fixed_preparation"]["diagnostic_parent"]["root"] / project,
                    ]
                    candidates += [
                        root / rel / project
                        for rel in config["fixed_preparation"].get("coverage_parent_roots", [])
                    ]
                rejected = []
                chosen = None
                for candidate in candidates:
                    if not (candidate / "codeql-database.yml").is_file():
                        continue
                    try:
                        coverage = source_coverage(candidate, source, minimum, revision)
                    except (OSError, ValueError, subprocess.SubprocessError) as error:
                        rejected.append(
                            {
                                "database": candidate.relative_to(root).as_posix(),
                                "error": str(error),
                            }
                        )
                        continue
                    if coverage["ready"]:
                        chosen = candidate
                        break
                    rejected.append(
                        {"database": candidate.relative_to(root).as_posix(), "coverage": coverage}
                    )
                if chosen is None and do_repair:
                    if destination.exists() or destination.is_symlink():
                        # Only our repair cache is mutable. Never rebuild in a
                        # historical parent or follow a symlink into one.
                        rejected_root.mkdir(parents=True, exist_ok=True)
                        retained = rejected_root / f"previous-{os.getpid()}"
                        destination.rename(retained)
                    print(f"{utc_now()} EXTRACT {project} {side}", flush=True)
                    extract(
                        root,
                        config,
                        project,
                        metadata[project],
                        revision,
                        destination,
                        output / "logs" / project / side,
                        cancelled=cancelled,
                    )
                    chosen = destination
                if (
                    repair
                    and chosen is not None
                    and shared is not None
                    and chosen.resolve() == shared.resolve()
                    and destination.resolve() != chosen.resolve()
                ):
                    # Persist checked peer reuse so a fresh process does not
                    # depend on which worker happens to populate the pool first.
                    try:
                        local_ready = source_coverage(
                            destination, source, minimum, revision
                        )["ready"]
                    except (OSError, ValueError, subprocess.SubprocessError):
                        local_ready = False
                    if not local_ready:
                        target = chosen.resolve(strict=True)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        if destination.exists() or destination.is_symlink():
                            rejected_root.mkdir(parents=True, exist_ok=True)
                            retained = rejected_root / f"peer-alias-{os.getpid()}"
                            destination.rename(retained)
                            rejected.append(
                                {
                                    "database": retained.relative_to(root).as_posix(),
                                    "reason": "superseded by checked same-revision peer",
                                }
                            )
                        temporary = destination.with_name(f".{project}.peer-{os.getpid()}")
                        temporary.symlink_to(target, target_is_directory=True)
                        temporary.replace(destination)
                    # Never move a valid DB that another worker may be using.
                    chosen = destination
                if chosen is None:
                    row[side] = {"ready": False, "rejected": rejected}
                else:
                    row[side] = {
                        "ready": True,
                        "database": chosen.relative_to(root).as_posix(),
                        "source_archive_sha256": sha256_file(chosen / "src.zip"),
                        "metadata_sha256": sha256_file(chosen / "codeql-database.yml"),
                        "coverage": require_coverage(chosen, source, minimum, revision),
                        "rejected": rejected,
                    }
                    if config["fixed_preparation"].get("reuse_exact_revision_databases"):
                        with pool_lock:
                            database_pool[reuse_key] = chosen
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                row[side] = {"ready": False, "error": f"{type(error).__name__}: {error}"}
        if row["vulnerable"]["ready"] and row["fixed"]["ready"]:
            row["status"] = "READY"
        return row

    def write_progress() -> None:
        atomic_json(output / "projects.json", {"projects": list(progress.values())})
        complete = [row for row in progress.values() if row["status"] != "PENDING"]
        atomic_json(
            output / "summary.json",
            {
                **signature,
                "status": "IN_PROGRESS",
                "projects": len(selected),
                "completed": len(complete),
                "pending": len(selected) - len(complete),
                "ready": sum(r["status"] == "READY" for r in complete),
                "blocked": sum(r["status"] == "BLOCKED" for r in complete),
                "api_calls": 0,
            },
        )

    write_progress()
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = []
    try:
        futures = [executor.submit(inspect_project, project) for project in selected]
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            progress[row["project_id"]] = row
            write_progress()
            print(
                f"{utc_now()} {len(rows)}/{len(selected)} {row['project_id']}: {row['status']}",
                flush=True,
            )
        if repair:
            # Inspect every case before starting lengthy builds. A stopped
            # repair then still leaves an observed result for all 120 cases.
            blocked = [project for project in selected if progress[project]["status"] == "BLOCKED"]

            def extraction_size(project: str) -> int:
                sizes = [
                    candidate.get("coverage", {}).get("expected_application_files", 0)
                    for side in ("vulnerable", "fixed")
                    for candidate in progress[project][side].get("rejected", [])
                ]
                return max(sizes, default=0)

            # Large repositories do not prevent smaller repairs from completing.
            # This changes input-maintenance order only, never the cohort/order
            # used by discovery, LLM synthesis or benchmark evaluation.
            blocked.sort(key=extraction_size)
            futures = [executor.submit(inspect_project, project, True) for project in blocked]
            for number, future in enumerate(as_completed(futures), 1):
                row = future.result()
                progress[row["project_id"]] = row
                write_progress()
                print(
                    f"{utc_now()} REPAIR {number}/{len(blocked)} "
                    f"{row['project_id']}: {row['status']}",
                    flush=True,
                )
            rows = list(progress.values())
    except BaseException:
        cancelled.set()
        for future in futures:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    positions = {project: index for index, project in enumerate(selected)}
    rows.sort(key=lambda row: positions[row["project_id"]])
    atomic_json(output / "projects.json", {"projects": rows})
    ready = sum(r["status"] == "READY" for r in rows)
    summary = {
        **signature,
        "status": "PASS" if ready == len(selected) else "BLOCKED",
        "projects": len(selected),
        "ready": ready,
        "blocked": len(selected) - ready,
        "api_calls": 0,
        "queries_validated": False,
        "scope": "tracked application Java source archive coverage and pinned input population",
    }
    atomic_json(output / "summary.json", summary)
    cache.mkdir(parents=True, exist_ok=True)
    atomic_json(cache / "coverage_manifest.json", {**summary, "records": rows})
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repair", action="store_true")
    parser.add_argument("--workers", type=int, default=1, choices=[1, 2, 3])
    args = parser.parse_args()

    def interrupted(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt("readiness received SIGTERM")

    signal.signal(signal.SIGTERM, interrupted)
    root = Path(__file__).resolve().parents[2]
    report = inspect(
        root, root / args.config, root / args.output, repair=args.repair, workers=args.workers
    )
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "selected_project_ids"},
            ensure_ascii=False,
        ),
        flush=True,
    )
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
