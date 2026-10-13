"""Expose checked vulnerable databases to the analyzer through opaque cache paths.

Run only after a complete successful readiness report. No database contents or
historical inputs are modified; evaluator reports never enter analyzer prompts.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file, utc_now
from src.pipeline_v2.coverage import require_coverage
from src.pipeline_v2.runtime import configuration, selection_ids
from src.reproduction.common import atomic_json


def promote(root: Path, config_path: Path, readiness: Path, output: Path) -> dict[str, Any]:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("promotion requires evaluator role")
    if not readiness.resolve().is_relative_to((root / "results/diagnostics").resolve()):
        raise ValueError("readiness must be inside results/diagnostics")
    if not output.resolve().is_relative_to((root / "results/diagnostics").resolve()):
        raise ValueError("output must be inside results/diagnostics")
    if output.exists():
        raise ValueError("promotion output already exists")
    config = configuration(root, config_path)
    selected = selection_ids(root, config)
    summary = json.loads((readiness / "summary.json").read_text())
    rows = json.loads((readiness / "projects.json").read_text())["projects"]
    if (
        summary["status"] != "PASS"
        or summary["ready"] != len(selected)
        or summary["blocked"] != 0
        or summary["selected_project_ids"] != selected
        or [row["project_id"] for row in rows] != selected
        or any(row["status"] != "READY" for row in rows)
        or summary["config_sha256"] != sha256_file(config_path)
        or summary["coverage_policy_sha256"] != sha256_file(root / "src/pipeline_v2/coverage.py")
        or summary["extraction_policy_sha256"]
        != sha256_file(root / "src/pipeline_v2/extraction.py")
    ):
        raise ValueError("promotion requires complete current input readiness PASS")
    cache = root / config["fixed_preparation"]["coverage_cache_root"]
    if not cache.resolve().is_relative_to((root / "data/interim").resolve()):
        raise ValueError("cache must be inside data/interim")
    records: list[dict[str, Any]] = []
    with (cache / ".readiness.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(parents=True)
        for row in rows:
            project = row["project_id"]
            checked = row["vulnerable"]
            target = (root / checked["database"]).resolve()
            if not target.is_relative_to((root / "data/interim").resolve()):
                raise ValueError("checked database must be inside data/interim")
            if (
                sha256_file(target / "src.zip") != checked["source_archive_sha256"]
                or sha256_file(target / "codeql-database.yml") != checked["metadata_sha256"]
            ):
                raise ValueError("checked database changed before promotion")
            coverage = require_coverage(
                target,
                root / config["fixed_preparation"]["source_root"] / project,
                config["execution"]["minimum_application_source_coverage"],
            )
            if coverage.get("supplement_model_check_sha256") != checked["coverage"].get(
                "supplement_model_check_sha256"
            ):
                raise ValueError("checked model validation changed before promotion")
            destination = cache / "vulnerable" / project
            changed = destination.resolve() != target
            if changed:
                if destination.exists() or destination.is_symlink():
                    retained = cache / "vulnerable/rejected" / project / f"promotion-{os.getpid()}"
                    retained.parent.mkdir(parents=True, exist_ok=True)
                    destination.rename(retained)
                temporary = destination.with_name(f".{project}.promotion-{os.getpid()}")
                temporary.symlink_to(target, target_is_directory=True)
                temporary.replace(destination)
            records.append(
                {
                    "project_id": project,
                    "database": destination.relative_to(root).as_posix(),
                    "target": target.relative_to(root).as_posix(),
                    "changed": changed,
                    "source_archive_sha256": checked["source_archive_sha256"],
                    "metadata_sha256": checked["metadata_sha256"],
                    "supplement_model_check_sha256": coverage.get("supplement_model_check_sha256"),
                }
            )
            atomic_json(output / "projects.json", {"projects": records})
        result = {
            "status": "PASS",
            "projects": len(records),
            "api_calls": 0,
            "promoted": sum(record["changed"] for record in records),
            "created_at": utc_now(),
            "readiness_summary_sha256": sha256_file(readiness / "summary.json"),
            "readiness_projects_sha256": sha256_file(readiness / "projects.json"),
        }
        atomic_json(output / "summary.json", result)
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/b9_benchmark_120_complete.yaml")
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(promote(root, root / args.config, root / args.readiness, root / args.output)))


if __name__ == "__main__":
    main()
