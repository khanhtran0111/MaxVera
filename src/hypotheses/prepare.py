"""Prepare opaque D_extended source aliases without exposing repository labels."""

from __future__ import annotations

import argparse
import csv
import os
from collections.abc import Sequence
from pathlib import Path

from src.common.provenance import sha256_file, utc_now
from src.data.build_projects import _fetch_source
from src.reproduction.common import atomic_json


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def prepare_sources(
    repo_root: Path,
    *,
    source_manifest: Path,
    target_manifest: Path,
    existing_source_root: Path,
    target_source_root: Path,
    preparation_manifest: Path,
    target_raw_root: Path | None = None,
    log_root: Path | None = None,
    fetch_timeout: int = 1800,
) -> dict[str, object]:
    """Alias equivalent revisions and fetch corrected D_extended revisions."""
    source_rows = _rows(source_manifest)
    target_rows = _rows(target_manifest)
    source_by_revision = {
        (row["project_slug"], row["buggy_commit_id"]): row["project_id"] for row in source_rows
    }
    target_source_root.mkdir(parents=True, exist_ok=True)
    aliased = 0
    fetched = 0
    for row in target_rows:
        identity = (row["project_slug"], row["buggy_commit_id"])
        source_id = source_by_revision.get(identity)
        if source_id is None:
            if target_raw_root is None or log_root is None:
                raise ValueError("D_extended row needs a corrected-revision source fetch")
            destination = target_source_root / row["project_id"]
            if destination.is_symlink():
                raise ValueError(f"corrected source target cannot be a symlink: {destination}")
            ok, reason, _ = _fetch_source(
                row,
                target_raw_root,
                target_source_root,
                log_root,
                fetch_timeout,
            )
            if not ok:
                raise RuntimeError(f"D_extended source preparation failed: {reason}")
            fetched += 1
            continue
        source = existing_source_root / source_id
        if not source.is_dir():
            raise FileNotFoundError(f"prepared vulnerable source is missing for {source_id}")
        destination = target_source_root / row["project_id"]
        relative_target = Path(os.path.relpath(source, start=target_source_root))
        if destination.is_symlink():
            if Path(os.readlink(destination)) != relative_target:
                raise ValueError(f"source alias points to an unexpected target: {destination}")
        elif destination.exists():
            raise ValueError(
                f"source alias target already exists and is not a symlink: {destination}"
            )
        else:
            destination.symlink_to(relative_target, target_is_directory=True)
        aliased += 1
    unexpected = [
        path.name
        for path in target_source_root.iterdir()
        if path.name not in {row["project_id"] for row in target_rows}
    ]
    if unexpected:
        raise ValueError(f"unexpected Phase 6 source aliases: {sorted(unexpected)[:5]}")
    manifest: dict[str, object] = {
        "schema_version": 1,
        "created_at": utc_now(),
        "strategy": "opaque_alias_when_revision_matches_else_verified_fetch",
        "prepared_projects": aliased + fetched,
        "aliased_projects": aliased,
        "fetched_corrected_revision_projects": fetched,
        "source_manifest_sha256": sha256_file(source_manifest),
        "target_manifest_sha256": sha256_file(target_manifest),
        "source_root": existing_source_root.relative_to(repo_root).as_posix(),
        "target_root": target_source_root.relative_to(repo_root).as_posix(),
        "identity_fields_used_by_preparation_only": ["project_slug", "buggy_commit_id"],
        "identity_mapping_persisted": False,
    }
    atomic_json(preparation_manifest, manifest)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    result = prepare_sources(
        root,
        source_manifest=root / "data/processed/manifests/cwe_bench_v1.csv",
        target_manifest=root / "data/processed/manifests/cwe_bench_extended.csv",
        existing_source_root=root / "data/interim/project_sources",
        target_source_root=root / "data/interim/phase6_project_sources",
        preparation_manifest=root / "data/interim/phase6_source_preparation.json",
        target_raw_root=root / "data/raw/cwe_bench_java_extended",
        log_root=root / "data/interim/phase6_source_logs",
    )
    print(
        "Prepared "
        f"{result['prepared_projects']} opaque Phase 6 sources "
        f"({result['aliased_projects']} aliases, "
        f"{result['fetched_corrected_revision_projects']} corrected checkouts)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
