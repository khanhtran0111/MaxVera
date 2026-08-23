from __future__ import annotations

from pathlib import Path

import pytest

from openiris.data import BuildInfo, DatasetBundle, ProjectRecord, materialize_dataset_views


@pytest.fixture
def separated_views(tmp_path: Path):
    record = ProjectRecord(
        upstream_id="7",
        project_slug="acme__widget_CVE-2025-1234_1.0",
        cve_id="CVE-2025-1234",
        cwe_id="CWE-79",
        cwe_name="Cross-site scripting",
        repository_owner="acme",
        repository_name="widget",
        repository_tag="1.0",
        repository_url="https://github.com/acme/widget",
        advisory_id="GHSA-aaaa-bbbb-cccc",
        revision="a" * 40,
        fix_commit_ids=("b" * 40,),
        build=BuildInfo(status="success", jdk_version="17"),
    )
    bundle = DatasetBundle(tmp_path / "source", "v2", (record,), {}, {})
    return materialize_dataset_views(
        bundle, "fixture", tmp_path / "runtime", tmp_path / "ground_truth"
    )
