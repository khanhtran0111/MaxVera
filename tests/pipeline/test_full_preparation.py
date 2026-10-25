"""Source preparation exercises real pinned Git objects without network or builds."""

import csv
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from maxvera.dataset import validate_snapshot_manifest, write_snapshot_manifest
from src.common.provenance import write_checksums


def git(directory, *args):
    return subprocess.run(
        ["git", *args], cwd=directory, check=True, capture_output=True, text=True
    ).stdout.strip()


def repository(path, files):
    path.mkdir(parents=True)
    git(path, "init", "--quiet")
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    git(path, "add", ".")
    git(
        path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "input",
    )
    return git(path, "rev-parse", "HEAD")


def fixture(tmp_path, *, count=2, patch=False):
    remote = tmp_path / "remote"
    commit = repository(remote, {"App.java": "class App {}\n", "pom.xml": "<project/>\n"})
    raw = tmp_path / "data/raw/cwe_bench_java_extended"
    revision = repository(
        raw,
        {
            "data/project_info.csv": "frozen metadata\n",
            "data/build_info.csv": "build metadata\n",
            "data/fix_info.csv": "fix metadata\n",
        },
    )
    git(raw, "remote", "add", "origin", "https://github.com/example/dataset")
    if patch:
        patch_path = raw / "patches/project-1.patch"
        patch_path.parent.mkdir()
        patch_path.write_text(
            "diff --git a/pom.xml b/pom.xml\n--- a/pom.xml\n+++ b/pom.xml\n"
            "@@ -1 +1 @@\n-<project/>\n+<project>patched</project>\n"
        )
        git(raw, "add", ".")
        git(
            raw,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "patch",
        )
        revision = git(raw, "rev-parse", "HEAD")
    config = tmp_path / "dataset.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "dataset_id": "D_extended",
                "revision": revision,
                "upstream_url": "https://github.com/example/dataset",
            }
        )
    )
    manifests = tmp_path / "data/processed/manifests"
    manifests.mkdir(parents=True)
    rows = [
        {
            "dataset_id": "D_extended",
            "upstream_revision": revision,
            "project_id": f"opaque-{n}",
            "project_slug": f"project-{n}",
            "github_url": remote.as_uri(),
            "buggy_commit_id": commit,
            "jdk_version": "17",
            "maven_version": "3.9.8",
            "gradle_version": "n/a",
            "use_gradlew": "n/a",
        }
        for n in range(1, count + 1)
    ]
    canonical = manifests / "cwe_bench_extended.csv"
    with canonical.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    source_index = manifests / "D_extended_source_checksums.sha256"
    write_checksums(
        [p for p in raw.rglob("*") if p.is_file() and ".git" not in p.parts], source_index, raw
    )
    write_checksums([canonical, source_index], manifests / "D_extended_checksums.sha256", tmp_path)
    java = tmp_path / "jdk/bin/java"
    java.parent.mkdir(parents=True)
    java.write_text("#!/bin/sh\nexit 0\n")
    java.chmod(0o755)
    mvn = tmp_path / ".cache/toolchains/maven/bin/mvn"
    mvn.parent.mkdir(parents=True)
    mvn.write_text("#!/bin/sh\nexit 99\n")
    mvn.chmod(0o755)
    toolchains = tmp_path / "configs/toolchains/cwe_bench_java.yaml"
    toolchains.parent.mkdir(parents=True)
    toolchains.write_text(
        yaml.safe_dump(
            {
                "install_root": ".cache/toolchains",
                "jdk": {"17": {"env_home": "MAXVERA_JAVA_17_HOME"}},
                "maven": {"3.9.8": {"directory": "maven"}},
                "build_attempts": [{"jdk": "17", "maven": "3.9.8"}],
            }
        )
    )
    (tmp_path / ".env").write_text(f"MAXVERA_JAVA_17_HOME={java.parent.parent}\n")
    return config, rows, canonical, raw, remote


def test_new_view_pins_sources_applies_patch_and_preserves_release(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, raw, remote = fixture(tmp_path, patch=True)
    # Real snapshots are nested inside the MaxVera Git working tree. git apply
    # must not silently resolve against that outer repository and skip the patch.
    git(tmp_path, "init", "--quiet")
    preserved = {str(p): p.read_bytes() for p in (canonical, *raw.glob("patches/*"))}
    # Uncommitted checkout bytes must never enter a source archive.
    (remote / "App.java").write_text("class Dirty {}\n")
    report = prepare_sources(tmp_path, config, view_name="full-prepared", min_free_gib=0)
    assert report["ready"] is True
    assert (report["prepared"], report["reused"], report["failed"]) == (2, 0, 0)
    view = tmp_path / "data/processed/analysis_input/full-prepared"
    assert (view / "projects/opaque-1/App.java").read_text() == "class App {}\n"
    assert (view / "projects/opaque-1/pom.xml").read_text() == "<project>patched</project>\n"
    record = validate_snapshot_manifest(view / "projects/opaque-1", "opaque-1")
    assert record["provenance"]["source_commit"] == rows[0]["buggy_commit_id"]
    assert record["provenance"]["build_patch_sha256"] is not None
    assert preserved == {str(p): p.read_bytes() for p in (canonical, *raw.glob("patches/*"))}
    assert not list(view.rglob(".git"))
    # A valid input recipe is availability evidence; the exit-99 build must not run.
    recipe = json.loads((view / "projects/opaque-1/build.runtime.json").read_text())
    assert "package" in recipe["attempts"][0]["command"]
    before = {str(p): p.read_bytes() for p in view.rglob("*") if p.is_file()}
    again = prepare_sources(
        tmp_path, config, view_name="full-prepared", offline=True, min_free_gib=0
    )
    assert (again["prepared"], again["reused"], again["ready"]) == (0, 2, True)
    assert before == {str(p): p.read_bytes() for p in view.rglob("*") if p.is_file()}


def test_new_view_does_not_silently_reuse_legacy_policy(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, _, _, _ = fixture(tmp_path)
    source = tmp_path / "data/processed/analysis_input/previous/projects/opaque-1"
    source.mkdir(parents=True)
    (source / "App.java").write_text("class PreviouslyAudited {}\n")
    (source / "build.runtime.json").write_text(
        json.dumps({"attempts": [{"command": ["/bin/true"], "environment": {}}]})
    )
    write_snapshot_manifest(
        source,
        "opaque-1",
        {
            "dataset_id": "D_extended",
            "dataset_revision": rows[0]["upstream_revision"],
            "source_commit": rows[0]["buggy_commit_id"],
            "build_patch_sha256": None,
            "preparation_policy": "audited-snapshot-copy-v1",
            "verification": {"kind": "pinned-source-inventory", "artifact_sha256": "a" * 64},
        },
    )
    reuse = source.parents[1] / "D_extended_projects.csv"
    reuse.write_text(
        "project_id,source_dir,source_required\nopaque-1,previous/projects/opaque-1,true\n"
    )
    preserved = {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    report = prepare_sources(
        tmp_path,
        config,
        view_name="next",
        reuse_manifest=reuse,
        selected_ids=["opaque-1"],
        offline=True,
        min_free_gib=0,
    )
    assert (report["reused"], report["requested"], report["failed"]) == (0, 1, 1)
    assert not report["ready"]
    with Path(report["manifest"]).open() as stream:
        output = list(csv.DictReader(stream))
    assert len(output) == 2
    assert output[0]["source_dir"] == "next/projects/opaque-1"
    assert not (tmp_path / "data/processed/analysis_input/next/projects/opaque-1").exists()
    assert preserved == {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}


def test_new_view_reuses_only_exact_v2_snapshot_by_reference(tmp_path):
    from maxvera.preparation import prepare_sources

    config, _, _, _, _ = fixture(tmp_path)
    first = prepare_sources(tmp_path, config, view_name="first", min_free_gib=0)
    source = tmp_path / "data/processed/analysis_input/first/projects/opaque-1"
    preserved = {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    second = prepare_sources(
        tmp_path,
        config,
        view_name="second",
        reuse_manifest=Path(first["manifest"]),
        offline=True,
        min_free_gib=0,
    )
    assert (second["reused"], second["prepared"], second["ready"]) == (2, 0, True)
    with Path(second["manifest"]).open() as stream:
        assert next(csv.DictReader(stream))["source_dir"] == "first/projects/opaque-1"
    assert preserved == {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}


def test_offline_missing_cases_remain_visible_and_resume_from_cache(tmp_path):
    from maxvera.preparation import prepare_sources

    config, _, _, _, _ = fixture(tmp_path)
    missing = prepare_sources(tmp_path, config, view_name="offline", offline=True, min_free_gib=0)
    assert (missing["requested"], missing["failed"], missing["ready"]) == (2, 2, False)
    assert all(c["status"] == "FAILED" for c in missing["cases"])
    with Path(missing["manifest"]).open() as stream:
        assert len(list(csv.DictReader(stream))) == 2
    first = prepare_sources(
        tmp_path, config, view_name="first", selected_ids=["opaque-1"], min_free_gib=0
    )
    assert first["ready"]
    cached = prepare_sources(tmp_path, config, view_name="offline", offline=True, min_free_gib=0)
    assert (cached["prepared"], cached["ready"]) == (2, True)


def test_changed_source_and_immutable_view_are_never_resealed(tmp_path):
    from maxvera.preparation import prepare_sources

    config, _, _, _, _ = fixture(tmp_path)
    prepare_sources(tmp_path, config, view_name="sealed", min_free_gib=0)
    source = tmp_path / "data/processed/analysis_input/sealed/projects/opaque-1"
    original = (source / "snapshot.files.json").read_bytes()
    (source / "App.java").write_text("class Corrupt {}\n")
    report = prepare_sources(tmp_path, config, view_name="sealed", min_free_gib=0)
    assert (report["failed"], report["reused"]) == (1, 1)
    assert (source / "snapshot.files.json").read_bytes() == original
    assert (source / "App.java").read_text() == "class Corrupt {}\n"


def test_manifest_source_reference_edit_requires_new_view(tmp_path):
    from maxvera.preparation import prepare_sources

    config, _, _, _, _ = fixture(tmp_path)
    first = prepare_sources(tmp_path, config, view_name="immutable", min_free_gib=0)
    manifest = Path(first["manifest"])
    manifest.write_text(
        manifest.read_text().replace("immutable/projects/opaque-1", "other/projects/opaque-1")
    )
    with pytest.raises(ValueError, match="immutable"):
        prepare_sources(tmp_path, config, view_name="immutable", min_free_gib=0)


def test_rejects_mutated_release_and_low_space_before_fetch(tmp_path):
    from maxvera.preparation import prepare_sources

    config, _, canonical, _, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="space"):
        prepare_sources(tmp_path, config, view_name="space", min_free_gib=10**12)
    assert not (tmp_path / "data/processed/analysis_input/space").exists()
    canonical.write_text(canonical.read_text().replace("opaque-1", "tampered-1"))
    with pytest.raises(ValueError, match="checksum"):
        prepare_sources(tmp_path, config, view_name="changed", min_free_gib=0)


def test_symlink_archive_is_explicit_failure_without_partial_snapshot(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    (remote / "Alias.java").symlink_to("App.java")
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "symlink",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="unsafe", min_free_gib=0)
    assert report["failed"] == 1 and "symlink" in report["cases"][0]["error"]
    view = tmp_path / "data/processed/analysis_input/unsafe"
    assert not (view / "projects/opaque-1").exists()
    assert not list(view.glob("projects/.*.preparing-*"))


def test_internal_documentation_symlink_is_materialized_with_pinned_proof(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    docs = remote / "docs"
    docs.mkdir()
    (docs / "guide.adoc").write_text("Pinned documentation.\n")
    (docs / "index.adoc").symlink_to("guide.adoc")
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "documentation alias",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="docs-proof", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/docs-proof/projects/opaque-1"
    assert not (source / "docs/index.adoc").is_symlink()
    assert (source / "docs/index.adoc").read_bytes() == (source / "docs/guide.adoc").read_bytes()
    record = validate_snapshot_manifest(source, "opaque-1")
    proof = json.loads((source / "archive.materialization.json").read_text())
    assert proof["materialized_symlinks"]["count"] == 1
    receipt = tmp_path / "logs/source_preparation/docs-proof/transformations/opaque-1.json"
    assert json.loads(receipt.read_text())["materialized_symlinks"][0]["path"] == "docs/index.adoc"
    assert (
        record["provenance"]["materialization_sha256"]
        == record["files"]["archive.materialization.json"]
    )


def test_test_resource_symlink_is_recorded_and_never_followed(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    resources = remote / "module/src/test/resources"
    resources.mkdir(parents=True)
    (resources / "escape-fixture").symlink_to("../../../../../../private-file")
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "test resource alias",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="test-resource-proof", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/test-resource-proof/projects/opaque-1"
    assert not (source / "module/src/test/resources/escape-fixture").exists()
    proof = json.loads((source / "archive.materialization.json").read_text())
    assert proof["omitted_test_resource_symlinks"]["count"] == 1
    receipt = tmp_path / "logs/source_preparation/test-resource-proof/transformations/opaque-1.json"
    assert json.loads(receipt.read_text())["omitted_test_resource_symlinks"] == [
        {
            "path": "module/src/test/resources/escape-fixture",
            "target": "../../../../../../private-file",
        }
    ]
    validate_snapshot_manifest(source, "opaque-1")


def test_internal_resource_directory_alias_copies_exact_files(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    resources = remote / "examples/common/mdb"
    resources.mkdir(parents=True)
    (resources / "settings.yaml").write_text("enabled: true\n")
    (remote / "examples/alias").symlink_to("common/mdb", target_is_directory=True)
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "resource directory alias",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="directory-proof", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/directory-proof/projects/opaque-1"
    assert (source / "examples/alias/settings.yaml").read_text() == "enabled: true\n"
    assert not (source / "examples/alias").is_symlink()
    validate_snapshot_manifest(source, "opaque-1")


def test_advisory_documents_are_excluded_with_trusted_only_receipt(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    advisory = remote / "security/CVE-2020-1234.html"
    advisory.parent.mkdir()
    advisory.write_text("Vulnerability advisory: CVE-2020-1234\n")
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "advisory document",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="no-advisories", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/no-advisories/projects/opaque-1"
    assert not (source / "security/CVE-2020-1234.html").exists()
    assert "CVE-2020-1234" not in "".join(p.read_text() for p in source.rglob("*") if p.is_file())
    receipt = tmp_path / "logs/source_preparation/no-advisories/transformations/opaque-1.json"
    assert "CVE-2020-1234" in receipt.read_text()
    validate_snapshot_manifest(source, "opaque-1")


def test_tracked_build_directories_survive_archive_inventory_and_private_copy(tmp_path):
    from types import SimpleNamespace

    from maxvera.orchestration import StageFailure
    from maxvera.preparation import prepare_sources
    from maxvera.research import static_extract
    from maxvera.snapshots import source_inventory

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    tracked = {
        "src/main/java/example/build/BuildHelper.java": "class BuildHelper {}\n",
        "src/main/java/example/target/TargetHelper.java": "class TargetHelper {}\n",
        "src/main/java/example/classes/ClassHelper.java": "class ClassHelper {}\n",
        "tools/build/config.xml": "<build configuration='pinned'/>\n",
    }
    for name, content in tracked.items():
        path = remote / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "tracked build sources",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="tracked", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/tracked/projects/opaque-1"
    for name, content in tracked.items():
        assert (source / name).is_file(), name
        assert (source / name).read_text() == content
    record = validate_snapshot_manifest(source, "opaque-1")
    assert set(tracked) <= set(record["files"])
    assert set(tracked) <= set(source_inventory(source))
    assert record["provenance"]["preparation_policy"] == "pinned-git-archive-normalized-v2"
    ledger = json.loads((source / "archive.materialization.json").read_text())
    assert ledger["inventory_policy"] == "tracked-archive-v2"
    stage = tmp_path / "private-stage"
    stage.mkdir()
    ctx = SimpleNamespace(
        root=tmp_path,
        case={"case_id": "opaque-1", "source_dir": "tracked/projects/opaque-1"},
        stage_dir=stage,
        run_dir=tmp_path / "private-run",
        config={"codeql": {"research_binary": "missing-codeql"}},
        output=lambda _: {"files": source_inventory(source)},
    )
    with pytest.raises(StageFailure, match="CodeQL binary missing"):
        static_extract(ctx)
    for name, content in tracked.items():
        assert (stage / "workspace" / name).read_text() == content


def test_omitted_symlink_oracle_target_stays_in_trusted_receipt_only(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    path = remote / "module/src/test/resources/escape-fixture"
    path.parent.mkdir(parents=True)
    raw_target = "../../../../CVE-2020-1234/ground_truth_cwe.json"
    path.symlink_to(raw_target)
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "oracle test resource target",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="omission-firewall", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/omission-firewall/projects/opaque-1"
    analyzer_bytes = b"".join(p.read_bytes() for p in source.rglob("*") if p.is_file())
    assert b"CVE-2020-1234" not in analyzer_bytes
    assert b"ground_truth_cwe" not in analyzer_bytes
    receipt = tmp_path / "logs/source_preparation/omission-firewall/transformations/opaque-1.json"
    assert raw_target in receipt.read_text()


def test_legacy_inventory_retains_original_build_directory_policy(tmp_path):
    from maxvera.snapshots import source_inventory

    old = tmp_path / "legacy"
    (old / "src/build").mkdir(parents=True)
    (old / "src/build/Legacy.java").write_text("class Legacy {}\n")
    (old / "Kept.java").write_text("class Kept {}\n")
    assert set(source_inventory(old)) == {"Kept.java"}


def test_v2_snapshot_rejects_unsummarized_materialization_ledger(tmp_path):
    from src.common.provenance import sha256_file

    source = tmp_path / "unsealed"
    source.mkdir()
    (source / "App.java").write_text("class App {}\n")
    (source / "build.runtime.json").write_text(
        json.dumps({"attempts": [{"command": ["/bin/true"], "environment": {}}]})
    )
    ledger = source / "archive.materialization.json"
    ledger.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "inventory_policy": "tracked-archive-v2",
                "omitted_test_resource_symlinks": [
                    {"target": "CVE-2020-1234/ground_truth_cwe.json"}
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="ledger"):
        write_snapshot_manifest(
            source,
            "opaque-1",
            {
                "dataset_id": "D_extended",
                "dataset_revision": "a" * 40,
                "source_commit": "b" * 40,
                "build_patch_sha256": None,
                "preparation_policy": "pinned-git-archive-normalized-v2",
                "materialization_sha256": sha256_file(ledger),
            },
        )
    assert not (source / "snapshot.files.json").exists()


def test_patch_resource_omission_has_trusted_exact_receipt(tmp_path):
    from maxvera.preparation import prepare_sources

    config, rows, canonical, _, remote = fixture(tmp_path, count=1)
    patch = remote / "fixtures/change.patch"
    patch.parent.mkdir()
    patch.write_text("tracked fixture patch\n")
    git(remote, "add", ".")
    git(
        remote,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "patch resource",
    )
    commit = git(remote, "rev-parse", "HEAD")
    canonical.write_text(canonical.read_text().replace(rows[0]["buggy_commit_id"], commit))
    index = canonical.parent / "D_extended_source_checksums.sha256"
    write_checksums([canonical, index], canonical.parent / "D_extended_checksums.sha256", tmp_path)
    report = prepare_sources(tmp_path, config, view_name="policy-omission", min_free_gib=0)
    assert report["ready"]
    source = tmp_path / "data/processed/analysis_input/policy-omission/projects/opaque-1"
    assert not (source / "fixtures/change.patch").exists()
    ledger = json.loads((source / "archive.materialization.json").read_text())
    assert ledger["omitted_policy_files"]["count"] == 1
    receipt = tmp_path / "logs/source_preparation/policy-omission/transformations/opaque-1.json"
    assert (
        json.loads(receipt.read_text())["omitted_policy_files"][0]["path"]
        == "fixtures/change.patch"
    )
