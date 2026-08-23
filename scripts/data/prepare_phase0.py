#!/usr/bin/env python3
"""Prepare all frozen dataset artifacts required by Phase 0."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from openiris.config import load_yaml
from openiris.data import (
    create_repository_split_from_manifest,
    freeze_snapshot,
    generate_inventory_reports,
    load_cwe_bench,
    materialize_dataset_views,
)

DEFAULT_CONFIGS = (
    Path("configs/datasets/legacy_paper.yaml"),
    Path("configs/datasets/v2_snapshot.yaml"),
)


def prepare(config_path: Path, workspace: Path) -> dict[str, Any]:
    config = load_yaml(config_path)
    source_root = workspace / Path(str(config["source_path"]))
    bundle = load_cwe_bench(source_root, str(config["track"]))
    snapshot_id = str(config["snapshot_id"])
    manifest_path = workspace / "data" / "manifests" / "datasets" / f"{snapshot_id}.yaml"
    manifest = freeze_snapshot(
        bundle,
        manifest_path,
        snapshot_id=snapshot_id,
        source_url=str(config["source_url"]),
        git_commit=str(config["git_commit"]),
        downloaded_at=str(config["downloaded_at"]),
    )

    views = materialize_dataset_views(
        bundle,
        snapshot_id,
        workspace / "data" / "runtime_views",
        workspace / "data" / "ground_truth",
    )
    report_root = workspace / "reports" / "datasets" / snapshot_id
    generate_inventory_reports(
        bundle,
        manifest,
        report_root,
        runtime_manifest=views.runtime_manifest,
    )

    split_path = workspace / "data" / "manifests" / "splits" / f"{snapshot_id}_repo_v1.yaml"
    split = create_repository_split_from_manifest(
        views.runtime_manifest,
        split_path,
        dataset_snapshot_id=snapshot_id,
        dataset_manifest_sha256=str(manifest["sha256_manifest"]),
        seed="maxvera-phase0-repo-split-v1",
        ratios={"train": 0.70, "dev": 0.15, "test": 0.15},
        split_id=f"{snapshot_id}_repo_v1",
    )
    return {
        "snapshot_id": snapshot_id,
        "manifest": manifest_path.relative_to(workspace).as_posix(),
        "runtime_manifest": views.runtime_manifest.relative_to(workspace).as_posix(),
        "ground_truth": views.ground_truth.relative_to(workspace).as_posix(),
        "report_root": report_root.relative_to(workspace).as_posix(),
        "split": split_path.relative_to(workspace).as_posix(),
        "num_instances": manifest["num_instances"],
        "split_counts": split["counts"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configs", nargs="*", type=Path, default=list(DEFAULT_CONFIGS))
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    results = [prepare(config, workspace) for config in args.configs]
    print(json.dumps({"schema_version": 1, "snapshots": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
