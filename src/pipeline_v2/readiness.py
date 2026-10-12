"""Inspect all registered inputs and optionally repair extraction, without LLM calls.

Fixed revisions are inspected only in this evaluator process. Its report/cache must
not be used as an analyzer prompt or a discovery input.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file, utc_now
from src.graphs.program.runner import _run_command
from src.pipeline_v2.coverage import require_coverage, source_coverage
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
        result = _run_command(
            [
                str(binary),
                "database",
                "create",
                str(database),
                "--language=java",
                "--build-mode=none",
                f"--threads={policy['threads']}",
                f"--ram={policy['ram_mb']}",
                f"--source-root={checkout}",
            ],
            cwd=checkout,
            env=environment,
            timeout=policy["timeout_seconds"],
            cancelled=cancelled,
        )
        (logs / "extraction.log").write_text(
            f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        if result.returncode:
            raise RuntimeError("CodeQL no-build extraction failed; see extraction.log")
        coverage = source_coverage(
            database, source, config["execution"]["minimum_application_source_coverage"], revision
        )
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
    progress = {project: {"project_id": project, "status": "PENDING"} for project in selected}
    atomic_json(output / "projects.json", {"projects": list(progress.values())})
    cancelled = threading.Event()

    def inspect_project(project: str) -> dict[str, Any]:
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
                if chosen is None and repair:
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
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                row[side] = {"ready": False, "error": f"{type(error).__name__}: {error}"}
        if row["vulnerable"]["ready"] and row["fixed"]["ready"]:
            row["status"] = "READY"
        return row

    executor = ThreadPoolExecutor(max_workers=workers)
    futures = []
    try:
        futures = [executor.submit(inspect_project, project) for project in selected]
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            progress[row["project_id"]] = row
            atomic_json(output / "projects.json", {"projects": list(progress.values())})
            atomic_json(
                output / "summary.json",
                {
                    **signature,
                    "status": "IN_PROGRESS",
                    "projects": len(selected),
                    "completed": len(rows),
                    "pending": len(selected) - len(rows),
                    "ready": sum(r["status"] == "READY" for r in rows),
                    "blocked": sum(r["status"] == "BLOCKED" for r in rows),
                    "api_calls": 0,
                },
            )
            print(
                f"{utc_now()} {len(rows)}/{len(selected)} {row['project_id']}: {row['status']}",
                flush=True,
            )
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
    root = Path(__file__).resolve().parents[2]
    report = inspect(
        root, root / args.config, root / args.output, repair=args.repair, workers=args.workers
    )
    print(json.dumps(report, ensure_ascii=False), flush=True)
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
