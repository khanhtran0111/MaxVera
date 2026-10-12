"""Register all 120 opaque cases and reuse unchanged development discovery."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file
from src.graphs.program.runner import _run_command
from src.pipeline_v2.b9 import upstream_runs
from src.pipeline_v2.coverage import require_coverage, source_coverage
from src.pipeline_v2.recovery import database_environment
from src.pipeline_v2.runtime import Run, codeql, configuration, development_ids, selection_ids
from src.reproduction.common import atomic_json, read_csv, read_jsonl
from src.verification.prepare_fixed import _checkout_fixed_revision


def inherit_discovery(run: Run) -> None:
    policy = run.config["benchmark"]
    if policy.get("fresh_discovery"):
        return
    dev = [p for p in run.selected if p in set(development_ids(run.root))]
    if not dev:
        return
    base = configuration(run.root, run.root / policy["seed_config_path"])
    locks = upstream_runs(run.root, base, dev)
    upstream = locks["phase6"]["path"]
    registered = policy["phase6_seed"]
    if any(
        locks["phase6"]["lock"][key] != registered[key]
        for key in ("run_root", "manifest_sha256", "checksums_sha256")
    ):
        raise ValueError("benchmark discovery seed changed")
    if any(
        run.config[key] != base[key]
        for key in (
            "top_k",
            "codeql",
            "budget",
            "model_config",
            "phase8",
            "verification",
            "calibration",
        )
    ):
        raise ValueError("benchmark scientific policy differs from the development seed")
    statuses = {r["project_id"]: r for r in read_jsonl(upstream / "project_status.jsonl")}
    for project in run.pending():
        if project not in statuses or statuses[project]["status"] != "SUCCESS":
            continue
        source = upstream / "projects" / project
        provenance = json.loads((source / "database_provenance.json").read_text())
        database = run.root / run.config["dataset"]["vulnerable_database_root"] / project
        if (
            sha256_file(database / "src.zip") != provenance["source_archive_sha256"]
            or sha256_file(database / "codeql-database.yml")
            != provenance["database_metadata_sha256"]
        ):
            raise ValueError("benchmark inherited vulnerable database changed")
        destination = run.work / "projects" / project
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
        fields = {
            k: v
            for k, v in statuses[project].items()
            if k not in {"project_id", "status", "reason", "updated_at", "inherited_from"}
        }
        run.status(
            project,
            "SUCCESS",
            "inherited unchanged typed development discovery",
            **fields,
            inherited_from=locks["phase6"]["lock"],
        )


def prepare(root: Path, config_path: Path, run_id: str, *, resume: bool = False) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") == "evaluator":
        raise ValueError("vulnerable preparation must run at the analyzer boundary")
    config = configuration(root, config_path)
    selected = selection_ids(root, config)
    policy = config["benchmark"]
    metadata_path = root / config["dataset"]["population"]
    metadata = {r["project_id"]: r for r in read_csv(metadata_path)}
    run = Run(
        root,
        "results/pipeline_v2/benchmark_inputs",
        run_id,
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=True,
        dependencies={"population_sha256": sha256_file(metadata_path)},
    )
    destination = root / config["dataset"]["vulnerable_database_root"]
    if not destination.resolve().is_relative_to((root / "data/interim").resolve()):
        raise ValueError("benchmark database root is outside data/interim")
    destination.mkdir(parents=True, exist_ok=True)
    binary = codeql(root, config["codeql"])
    minimum_coverage = config.get("execution", {}).get("minimum_application_source_coverage")
    toolchain = yaml.safe_load((root / "configs/toolchains/cwe_bench_java.yaml").read_text())
    for project in run.pending():
        target = destination / project
        provenance_path = run.work / "projects" / project / "database.json"
        try:
            if provenance_path.exists():
                record = json.loads(provenance_path.read_text())
                candidate = (
                    target if target.exists() else run.work / "builds" / project / "database"
                )
                if any(
                    sha256_file(candidate / file) != record[key]
                    for file, key in [
                        ("src.zip", "source_archive_sha256"),
                        ("codeql-database.yml", "metadata_sha256"),
                    ]
                ):
                    raise ValueError("benchmark database checkpoint changed")
                if candidate != target:
                    shutil.move(str(candidate), str(target))
            else:
                parent = None
                for relative in policy["vulnerable_parent_roots"]:
                    candidate = root / relative / project
                    if not (candidate / "codeql-database.yml").is_file():
                        continue
                    if minimum_coverage is not None:
                        try:
                            coverage = source_coverage(
                                candidate,
                                root / config["fixed_preparation"]["source_root"] / project,
                                float(minimum_coverage),
                            )
                        except (OSError, ValueError, subprocess.SubprocessError):
                            continue
                        if not coverage["ready"]:
                            continue
                    parent = candidate
                    break
                if parent is not None:
                    if not target.exists():
                        target.symlink_to(parent.resolve(), target_is_directory=True)
                    if target.resolve() != parent.resolve():
                        raise ValueError("benchmark database parent changed")
                    extra: dict[str, Any] = {
                        "build_mode": "historical",
                        "parent": parent.relative_to(root).as_posix(),
                    }
                else:
                    source = root / config["fixed_preparation"]["source_root"] / project
                    revision = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=source, text=True
                    ).strip()
                    if shutil.disk_usage(root).free < policy["minimum_free_disk_gib"] * 1024**3:
                        raise RuntimeError("benchmark extraction disk reserve exhausted")
                    environment, toolchain_record = database_environment(
                        root, metadata[project], toolchain, effective_env(root / ".env")
                    )
                    scratch = run.work / "builds" / project
                    scratch.mkdir(parents=True, exist_ok=True)
                    checkout = scratch / "source"
                    remote = subprocess.run(
                        ["git", "remote", "get-url", "origin"],
                        cwd=source,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    fetched, method = _checkout_fixed_revision(
                        source,
                        checkout,
                        revision,
                        remote.stdout.strip() if remote.returncode == 0 else "",
                        timeout=int(config["fixed_preparation"]["fetch_timeout_seconds"]),
                    )
                    if not fetched:
                        raise RuntimeError("isolated vulnerable checkout failed: " + method)
                    database = scratch / "database"
                    if database.exists():
                        shutil.rmtree(database)
                    result = _run_command(
                        [
                            str(binary),
                            "database",
                            "create",
                            str(database),
                            "--language=java",
                            "--build-mode=none",
                            f"--threads={config['codeql']['threads']}",
                            f"--ram={config['codeql']['ram_mb']}",
                            f"--source-root={checkout}",
                        ],
                        cwd=checkout,
                        env=environment,
                        timeout=config["codeql"]["timeout_seconds"],
                    )
                    (scratch / "build.log").write_text(
                        f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}"
                    )
                    if result.returncode or not (database / "src.zip").is_file():
                        raise RuntimeError("benchmark no-build extraction failed")
                    if minimum_coverage is not None:
                        require_coverage(database, source, float(minimum_coverage), revision)
                    if target.exists():
                        raise ValueError("unregistered benchmark database destination")
                    extra = {
                        "build_mode": "none",
                        "source_git_commit": revision,
                        "checkout_method": method,
                        "toolchain": toolchain_record,
                    }
                    atomic_json(
                        provenance_path,
                        {
                            "project_id": project,
                            "source_archive_sha256": sha256_file(database / "src.zip"),
                            "metadata_sha256": sha256_file(database / "codeql-database.yml"),
                            **extra,
                        },
                    )
                    shutil.move(str(database), str(target))
                record = {
                    "project_id": project,
                    "source_archive_sha256": sha256_file(target / "src.zip"),
                    "metadata_sha256": sha256_file(target / "codeql-database.yml"),
                    **extra,
                }
                atomic_json(provenance_path, record)
            if minimum_coverage is not None:
                record["application_source_coverage"] = require_coverage(
                    target,
                    root / config["fixed_preparation"]["source_root"] / project,
                    float(minimum_coverage),
                )
                atomic_json(provenance_path, record)
            run.status(
                project,
                "SUCCESS",
                "opaque vulnerable database ready for typed discovery",
                **record_without_id(record),
            )
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            run.status(project, "CODEQL_DB_FAILED", str(error))
    return run.finalize({"llm_calls": 0})


def record_without_id(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "project_id"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=["full"], required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(
        prepare(root, (root / args.config).resolve(), args.run_id, resume=args.resume), flush=True
    )


if __name__ == "__main__":
    main()
