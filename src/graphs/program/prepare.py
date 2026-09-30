"""Prepare opaque Phase 7 aliases to reusable Phase 2 CodeQL databases."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from src.common.provenance import sha256_file, utc_now
from src.reproduction.common import atomic_json, read_csv, read_jsonl


def prepare_databases(
    repo_root: Path,
    *,
    source_manifest: Path,
    target_manifest: Path,
    development_split: Path,
    source_database_root: Path,
    target_database_root: Path,
    phase2_status_path: Path,
    preparation_manifest: Path,
    analysis_scope: str = "development",
) -> dict[str, object]:
    source_rows = read_csv(source_manifest)
    target_rows = read_csv(target_manifest)
    development_ids = {row["project_id"] for row in read_csv(development_split)}
    source_by_revision = {
        (row["project_slug"], row["buggy_commit_id"]): row["project_id"] for row in source_rows
    }
    phase2_status = {
        str(row["project_id"]): str(row["status"]) for row in read_jsonl(phase2_status_path)
    }
    selected = [row for row in target_rows if row["project_id"] in development_ids]
    if len(selected) != len(development_ids):
        raise ValueError("Phase 7 development split does not resolve to the target manifest")
    target_database_root.mkdir(parents=True, exist_ok=True)
    outcomes: dict[str, str] = {}
    for row in selected:
        project_id = row["project_id"]
        destination = target_database_root / project_id
        if destination.is_dir() and not destination.is_symlink():
            if not (destination / "codeql-database.yml").is_file():
                raise ValueError(f"invalid locally built Phase 7 database: {project_id}")
            outcomes[project_id] = "LOCAL_DATABASE"
            continue
        source_id = source_by_revision.get((row["project_slug"], row["buggy_commit_id"]))
        if source_id is None:
            outcomes[project_id] = "DATABASE_MISSING"
            continue
        source = source_database_root / source_id
        if (
            phase2_status.get(source_id) != "SUCCESS"
            or not (source / "codeql-database.yml").is_file()
        ):
            outcomes[project_id] = "DATABASE_MISSING"
            continue
        relative_target = Path(os.path.relpath(source, start=target_database_root))
        if destination.is_symlink():
            if Path(os.readlink(destination)) != relative_target:
                raise ValueError(f"Phase 7 database alias has unexpected target: {project_id}")
        elif destination.exists():
            raise ValueError(
                f"Phase 7 database target is neither a valid directory nor alias: {project_id}"
            )
        else:
            destination.symlink_to(relative_target, target_is_directory=True)
        outcomes[project_id] = "ALIASED_DATABASE"
    unexpected = sorted(
        path.name for path in target_database_root.iterdir() if path.name not in outcomes
    )
    if unexpected:
        raise ValueError(f"unexpected Phase 7 database entries: {unexpected[:5]}")
    counts = Counter(outcomes.values())
    result: dict[str, object] = {
        "schema_version": 1,
        "created_at": utc_now(),
        "strategy": "opaque_alias_of_identical_revision_else_explicit_missing",
        "selected_projects": len(selected),
        "available_databases": counts["ALIASED_DATABASE"] + counts["LOCAL_DATABASE"],
        "aliased_databases": counts["ALIASED_DATABASE"],
        "locally_built_databases": counts["LOCAL_DATABASE"],
        "missing_databases": counts["DATABASE_MISSING"],
        "available_project_ids": sorted(
            project_id for project_id, status in outcomes.items() if status != "DATABASE_MISSING"
        ),
        "missing_project_ids": sorted(
            project_id for project_id, status in outcomes.items() if status == "DATABASE_MISSING"
        ),
        "source_manifest_sha256": sha256_file(source_manifest),
        "target_manifest_sha256": sha256_file(target_manifest),
        "analysis_scope": analysis_scope,
        "analysis_split_sha256": sha256_file(development_split),
        "development_split_sha256": (
            sha256_file(development_split) if analysis_scope == "development" else None
        ),
        "phase2_status_sha256": sha256_file(phase2_status_path),
        "target_root": target_database_root.relative_to(repo_root).as_posix(),
        "identity_fields_used_by_preparation_only": ["project_slug", "buggy_commit_id"],
        "identity_mapping_persisted": False,
        "locked_test_prepared": analysis_scope == "test_locked",
    }
    atomic_json(preparation_manifest, result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--analysis-split", type=Path)
    parser.add_argument("--target-database-root", type=Path)
    parser.add_argument("--preparation-manifest", type=Path)
    parser.add_argument(
        "--analysis-scope", choices=("development", "test_locked"), default="development"
    )
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    result = prepare_databases(
        root,
        source_manifest=root / "data/processed/manifests/cwe_bench_v1.csv",
        target_manifest=root / "data/processed/manifests/cwe_bench_extended.csv",
        development_split=(
            args.analysis_split
            if args.analysis_split and args.analysis_split.is_absolute()
            else root / (args.analysis_split or "data/processed/splits/development.csv")
        ),
        source_database_root=root / "data/interim/codeql_databases",
        target_database_root=(
            args.target_database_root
            if args.target_database_root and args.target_database_root.is_absolute()
            else root / (args.target_database_root or "data/interim/phase7_codeql_databases")
        ),
        phase2_status_path=root / "data/interim/build_info/build_status.jsonl",
        preparation_manifest=(
            args.preparation_manifest
            if args.preparation_manifest and args.preparation_manifest.is_absolute()
            else root
            / (args.preparation_manifest or "data/interim/phase7_database_preparation.json")
        ),
        analysis_scope=args.analysis_scope,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
