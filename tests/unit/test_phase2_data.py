from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.data.phase2 import (
    DatasetConfig,
    assert_analysis_rows_safe,
    assign_group_splits,
    build_canonical_rows,
    initialize_build_status,
    normalize_cwe,
    opaque_project_id,
    validate_phase2,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _config(expected: int | None = 2) -> DatasetConfig:
    return DatasetConfig(
        dataset_id="D_fixture",
        upstream_url="https://example.test/fixture.git",
        revision="a" * 40,
        expected_cves=expected,
        split_seed=1234,
        development_ratio=0.8,
    )


def _raw_fixture(root: Path) -> None:
    project_fields = [
        "id",
        "project_slug",
        "cve_id",
        "cwe_id",
        "cwe_name",
        "github_username",
        "github_repository_name",
        "github_tag",
        "github_url",
        "advisory_id",
        "buggy_commit_id",
        "fix_commit_ids",
    ]
    projects = [
        {
            "id": str(index),
            "project_slug": f"owner__repo_CVE-2024-000{index}_v{index}",
            "cve_id": f"CVE-2024-000{index}",
            "cwe_id": "CWE-022" if index == 1 else "CWE-079",
            "cwe_name": "fixture weakness",
            "github_username": "owner",
            "github_repository_name": "repo" if index == 1 else "repo-two",
            "github_tag": f"v{index}",
            "github_url": f"https://example.test/owner/repo-{index}",
            "advisory_id": f"GHSA-fixture-{index}",
            "buggy_commit_id": str(index) * 40,
            "fix_commit_ids": str(index + 1) * 40,
        }
        for index in (1, 2)
    ]
    _write_csv(root / "data/project_info.csv", project_fields, projects)
    _write_csv(
        root / "data/build_info.csv",
        [
            "project_slug",
            "status",
            "jdk_version",
            "mvn_version",
            "gradle_version",
            "use_gradlew",
        ],
        [
            {
                "project_slug": project["project_slug"],
                "status": "success",
                "jdk_version": "8u202",
                "mvn_version": "3.5.0",
                "gradle_version": "n/a",
                "use_gradlew": "n/a",
            }
            for project in projects
        ],
    )
    _write_csv(
        root / "data/fix_info.csv",
        ["project_slug", "file", "method", "method_start", "method_end"],
        [
            {
                "project_slug": project["project_slug"],
                "file": "src/Main.java",
                "method": "run",
                "method_start": "1",
                "method_end": "2",
            }
            for project in projects
        ]
        + [
            {
                "project_slug": "historical_row_not_in_project_info",
                "file": "src/Old.java",
                "method": "old",
                "method_start": "1",
                "method_end": "2",
            }
        ],
    )
    advisory = root / "advisory"
    advisory.mkdir()
    for project in projects:
        (advisory / f"{project['project_slug']}.json").write_text(
            '{"summary":"protected"}\n', encoding="utf-8"
        )


def test_canonical_manifest_has_one_stable_opaque_id_per_project(tmp_path: Path) -> None:
    _raw_fixture(tmp_path)
    rows = build_canonical_rows(tmp_path, _config())
    assert len(rows) == 2
    assert rows[0]["ground_truth_cwe"] == "CWE-22"
    assert rows[0]["project_id"].startswith("proj_")
    assert "CVE" not in rows[0]["project_id"]
    assert rows[0]["project_id"] == opaque_project_id(
        "D_fixture", "a" * 40, rows[0]["project_slug"]
    )
    assert rows[0]["fix_location_count"] == "1"


def test_canonical_manifest_rejects_missing_status(tmp_path: Path) -> None:
    _raw_fixture(tmp_path)
    build_path = tmp_path / "data/build_info.csv"
    rows = list(csv.DictReader(build_path.read_text(encoding="utf-8").splitlines()))[:1]
    _write_csv(build_path, list(rows[0]), rows)
    with pytest.raises(ValueError, match="missing upstream build metadata"):
        build_canonical_rows(tmp_path, _config())


def test_group_split_is_deterministic_and_has_no_repository_overlap() -> None:
    rows: list[dict[str, str]] = []
    for group in range(12):
        for version in range(1 + (group % 3 == 0)):
            rows.append(
                {
                    "project_id": f"proj_{group}_{version}",
                    "github_username": f"owner-{group // 2}",
                    "github_repository_name": f"repo-{group}",
                }
            )
    first = assign_group_splits(rows, seed=1234, development_ratio=0.8)
    second = assign_group_splits(list(reversed(rows)), seed=1234, development_ratio=0.8)
    assert first == second
    groups: dict[str, set[str]] = {}
    for row in rows:
        key = f"{row['github_username']}/{row['github_repository_name']}"
        groups.setdefault(key, set()).add(first[row["project_id"]])
    assert all(len(splits) == 1 for splits in groups.values())
    assert set(first.values()) == {"development", "test_locked"}


def test_analysis_firewall_rejects_fields_and_label_like_values() -> None:
    assert_analysis_rows_safe([{"project_id": "proj_123", "source_dir": "projects/proj_123"}])
    with pytest.raises(ValueError, match="forbidden fields"):
        assert_analysis_rows_safe([{"project_id": "proj_123", "cve_id": "hidden"}])
    with pytest.raises(ValueError, match="label-like"):
        assert_analysis_rows_safe([{"project_id": "proj_CWE-22"}])


def test_pending_status_is_complete_but_does_not_pass_phase_gate(tmp_path: Path) -> None:
    rows = [
        {
            "project_id": f"proj_{index}",
            "dataset_id": "D_fixture",
            "upstream_revision": "a" * 40,
        }
        for index in range(2)
    ]
    path = initialize_build_status(tmp_path, rows, _config())
    statuses = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(statuses) == 2
    assert {item["status"] for item in statuses} == {"PENDING"}
    statuses[0]["status"] = "BUILD_FAILED"
    path.write_text("\n".join(json.dumps(item) for item in statuses) + "\n", encoding="utf-8")
    initialize_build_status(tmp_path, rows, _config())
    preserved = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert preserved[0]["status"] == "BUILD_FAILED"


@pytest.mark.parametrize(
    ("source", "expected"),
    [("CWE-022", "CWE-22"), ("cwe-078", "CWE-78"), ("CWE-0", "CWE-0")],
)
def test_normalize_cwe(source: str, expected: str) -> None:
    assert normalize_cwe(source) == expected


def test_validate_phase2_reports_missing_manifest(tmp_path: Path) -> None:
    assert validate_phase2(tmp_path) == ["canonical v1 manifest is missing"]


def test_materialized_release_has_120_rows_and_groupwise_split() -> None:
    processed = REPO_ROOT / "data/processed"
    v1 = list(csv.DictReader((processed / "manifests/cwe_bench_v1.csv").open()))
    extended = list(csv.DictReader((processed / "manifests/cwe_bench_extended.csv").open()))
    development = list(csv.DictReader((processed / "splits/development.csv").open()))
    test_locked = list(csv.DictReader((processed / "splits/test_locked.csv").open()))
    assert len(v1) == len(extended) == 120
    assert len(development) == 96
    assert len(test_locked) == 24
    development_ids = {row["project_id"] for row in development}
    test_ids = {row["project_id"] for row in test_locked}
    assert development_ids.isdisjoint(test_ids)
    assert development_ids | test_ids == {row["project_id"] for row in extended}
    split_by_id = {project_id: "development" for project_id in development_ids}
    split_by_id.update({project_id: "test_locked" for project_id in test_ids})
    repository_splits: dict[tuple[str, str], set[str]] = {}
    for row in extended:
        key = (row["github_username"].casefold(), row["github_repository_name"].casefold())
        repository_splits.setdefault(key, set()).add(split_by_id[row["project_id"]])
    assert all(len(splits) == 1 for splits in repository_splits.values())


def test_materialized_analysis_view_has_no_protected_columns() -> None:
    analysis_root = REPO_ROOT / "data/processed/analysis_input"
    manifests = sorted(analysis_root.glob("*.csv"))
    assert {path.name for path in manifests} == {
        "D_extended_projects.csv",
        "D_repro_v1_projects.csv",
    }
    for manifest in manifests:
        rows = list(csv.DictReader(manifest.open()))
        assert len(rows) == 120
        assert_analysis_rows_safe(rows)
