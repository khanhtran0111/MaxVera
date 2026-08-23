from __future__ import annotations

from pathlib import Path

import pytest

from openiris.data import DatasetFormatError, load_cwe_bench, normalize_cwe_id

PROJECT_HEADER = (
    "id,project_slug,cve_id,cwe_id,cwe_name,github_username,"
    "github_repository_name,github_tag,github_url,advisory_id,"
    "buggy_commit_id,fix_commit_ids\n"
)


def _write_v2_fixture(root: Path) -> Path:
    data = root / "data"
    data.mkdir(parents=True)
    (data / "project_info.csv").write_text(
        PROJECT_HEADER + "1,acme__widget_CVE-2025-1000_1.0,CVE-2025-1000,CWE-022,Path traversal,"
        "acme,widget,1.0,https://github.com/acme/widget,GHSA-aaaa-bbbb-cccc,"
        + "a" * 40
        + ","
        + "b" * 40
        + "\n",
        encoding="utf-8",
    )
    # Upstream v2 schema drift: recent build rows use one underscore before CVE.
    (data / "build_info.csv").write_text(
        "project_slug,status,jdk_version,mvn_version,gradle_version,use_gradlew\n"
        "acme_widget_CVE-2025-1000_1.0,success (Kotlin),17,3.9.9,,False\n",
        encoding="utf-8",
    )
    # The real v2 fix CSV has one empty trailing header/field.
    (data / "fix_info.csv").write_text(
        "project_slug,cve_id,github_username,github_repository_name,commit,file,class,"
        "class_start,class_end,method,method_start,method_end,signature,\n"
        "acme_widget_CVE-2025-1000_1.0,CVE-2025-1000,acme,widget,"
        + "b" * 40
        + ",src/Widget.java,Widget,1,20,open,4,8,void open(),\n",
        encoding="utf-8",
    )
    (data / "fix_info_source_sink.csv").write_text(
        "project_slug,cve_id,Source,Sink\nacme_widget_CVE-2025-1000_1.0,CVE-2025-1000,input,open\n",
        encoding="utf-8",
    )
    return root


def test_loads_v2_csv_and_resolves_auxiliary_slug_drift(tmp_path: Path) -> None:
    bundle = load_cwe_bench(_write_v2_fixture(tmp_path / "dataset"), "v2")

    assert len(bundle.instances) == 1
    instance = bundle.instances[0]
    assert instance.cwe_id == "CWE-22"
    assert instance.build.succeeded
    assert instance.build.maven_version == "3.9.9"
    assert len(bundle.fix_locations[instance.project_slug]) == 1
    assert len(bundle.source_sink_annotations[instance.project_slug]) == 1


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [("CWE-022", "CWE-22"), ("cwe_00079", "CWE-79"), ("CWE 94", "CWE-94")],
)
def test_normalizes_cwe_aliases(raw: str, normalized: str) -> None:
    assert normalize_cwe_id(raw) == normalized


def test_rejects_missing_required_project_column(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "project_info.csv").write_text("id,project_slug\n1,p\n", encoding="utf-8")
    (data / "build_info.csv").write_text(
        "project_slug,status,jdk_version,mvn_version,gradle_version,use_gradlew\n",
        encoding="utf-8",
    )

    with pytest.raises(DatasetFormatError, match="Missing columns"):
        load_cwe_bench(tmp_path, "legacy")
