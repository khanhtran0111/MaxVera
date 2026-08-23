from __future__ import annotations

from pathlib import Path

import pytest

from openiris.data import (
    BuildInfo,
    DatasetBundle,
    DatasetIntegrityError,
    ProjectRecord,
    freeze_snapshot,
    verify_snapshot_manifest,
)


def _bundle(root: Path) -> DatasetBundle:
    (root / "data").mkdir(parents=True)
    (root / "data" / "project_info.csv").write_text("stable bytes\n", encoding="utf-8")
    record = ProjectRecord(
        upstream_id="1",
        project_slug="private-evaluation-slug",
        cve_id="private-evaluation-id",
        cwe_id="CWE-22",
        cwe_name="private weakness",
        repository_owner="acme",
        repository_name="widget",
        repository_tag="1.0",
        repository_url="https://github.com/acme/widget",
        advisory_id="private advisory",
        revision="a" * 40,
        fix_commit_ids=("b" * 40,),
        build=BuildInfo(status="success", jdk_version="17"),
    )
    return DatasetBundle(root, "legacy", (record,), {}, {})


def test_snapshot_manifest_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "dataset")
    output = bundle.root / "snapshot.yaml"
    options = {
        "snapshot_id": "legacy_fixture",
        "source_url": "https://example.invalid/cwe-bench.git",
        "git_commit": "c" * 40,
        "downloaded_at": "2026-08-23T00:00:00Z",
    }

    first = freeze_snapshot(bundle, output, **options)
    first_bytes = output.read_bytes()
    second = freeze_snapshot(bundle, output, **options)

    assert first == second
    assert output.read_bytes() == first_bytes
    assert first["num_instances"] == 1
    assert first["num_unique_repositories"] == 1
    assert first["file_hashes"]["data/project_info.csv"]["sha256"]
    verify_snapshot_manifest(output, bundle.root)


def test_snapshot_verification_detects_file_drift(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "dataset")
    output = tmp_path / "manifest.yaml"
    freeze_snapshot(
        bundle,
        output,
        snapshot_id="legacy_fixture",
        source_url="https://example.invalid/cwe-bench.git",
        git_commit="c" * 40,
    )
    (bundle.root / "data" / "project_info.csv").write_text("changed\n", encoding="utf-8")

    with pytest.raises(DatasetIntegrityError, match="drifted"):
        verify_snapshot_manifest(output, bundle.root)
