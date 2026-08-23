from __future__ import annotations

from pathlib import Path

from openiris.data import (
    REQUIRED_REPORT_FILES,
    BuildInfo,
    DatasetBundle,
    ProjectRecord,
    generate_inventory_reports,
    materialize_dataset_views,
)


def _record(number: int, tag: str) -> ProjectRecord:
    return ProjectRecord(
        upstream_id=str(number),
        project_slug=f"evaluation-record-{number}",
        cve_id=f"private-{number}",
        cwe_id="CWE-22" if number == 1 else "CWE-79",
        cwe_name="private",
        repository_owner="acme",
        repository_name="widget",
        repository_tag=tag,
        repository_url="https://github.com/acme/widget",
        advisory_id="private",
        revision=str(number) * 40,
        fix_commit_ids=(),
        build=BuildInfo(status="success" if number == 1 else "failure"),
    )


def test_generates_complete_deterministic_inventory(tmp_path: Path) -> None:
    bundle = DatasetBundle(
        tmp_path / "source", "legacy", (_record(1, "1.0"), _record(2, "2.0")), {}, {}
    )
    views = materialize_dataset_views(bundle, "fixture", tmp_path / "runtime", tmp_path / "truth")
    manifest = {
        "snapshot_id": "fixture",
        "sha256_manifest": "d" * 64,
    }
    output = tmp_path / "reports"

    paths = generate_inventory_reports(
        bundle, manifest, output, runtime_manifest=views.runtime_manifest
    )
    first = {name: path.read_bytes() for name, path in paths.items()}
    paths = generate_inventory_reports(
        bundle, manifest, output, runtime_manifest=views.runtime_manifest
    )

    assert set(paths) == REQUIRED_REPORT_FILES
    assert {name: path.read_bytes() for name, path in paths.items()} == first
    assert "Runtime leakage audit | PASS" in paths["summary.md"].read_text(encoding="utf-8")
    assert '"records_checked": 2' in paths["leakage_audit.json"].read_text(encoding="utf-8")
