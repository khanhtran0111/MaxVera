from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from src.pipeline_v2.coverage import application_java, require_coverage, source_coverage


def test_coverage_keeps_production_package_names_and_excludes_build_templates() -> None:
    assert application_java("app/src/main/java/org/example/resources/Controller.java")
    assert application_java("app/src/main/java/org/example/tests/TestSupport.java")
    assert not application_java("app/src/test/java/org/example/ControllerTest.java")
    assert not application_java("gradle/spotless.license.java")
    assert not application_java("archetype/src/main/resources/src/main/java/Template.java")
    assert not application_java("app/src/testFixtures/java/org/example/Foo.java")
    assert not application_java("app/src/test-swiftmq/java/org/example/Foo.java")
    assert not application_java("plugin/src/it/nested/src/main/java/org/example/Foo.java")
    assert application_java("app/src/main/java/org/example/it/Foo.java")
    assert application_java("app/src/main/java/org/example/testFixtures/Foo.java")


def test_database_must_contain_application_not_only_buildsrc_and_templates(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    for name in (
        "app/src/main/java/App.java",
        "optional/src/main/java/Other.java",
        "buildSrc/src/main/java/Plugin.java",
        "app/src/test/java/Test.java",
        "archetype/src/main/resources/archetype-resources/Template.java",
    ):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("class Fixture {}")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=source,
        check=True,
    )
    database = tmp_path / "database"
    database.mkdir()
    with zipfile.ZipFile(database / "src.zip", "w") as archive:
        archive.writestr("temporary/checkout/buildSrc/src/main/java/Plugin.java", "class Plugin {}")
    result = source_coverage(database, source)
    assert result["covered_application_files"] == 0
    assert result["expected_application_files"] == 2
    assert not result["ready"]
    with pytest.raises(ValueError, match="APPLICATION_COVERAGE_FAILED"):
        require_coverage(database, source)
    with zipfile.ZipFile(database / "src.zip", "a") as archive:
        archive.writestr("temporary/checkout/app/src/main/java/App.java", "class App {}")
    assert not source_coverage(database, source)["ready"]
    with zipfile.ZipFile(database / "src.zip", "a") as archive:
        archive.writestr("temporary/checkout/optional/src/main/java/Other.java", "class Other {}")
    assert require_coverage(database, source)["coverage_ratio"] == 1
    (database / "codeql-database.yml").write_text("creationMetadata:\n  sha: wrong-revision\n")
    with pytest.raises(ValueError, match="revision mismatch"):
        source_coverage(database, source)
    (database / "codeql-database.yml").write_text("inProgress:\n  primaryLanguage: java\n")
    with pytest.raises(ValueError, match="not finalized"):
        source_coverage(database, source)


def test_comment_only_exemption_uses_pinned_revision_and_keeps_real_code(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    files = {
        "App.java": "class App {}",
        "Empty.java": "",
        "Comments.java": "\ufeff/* class Old {} */\n// class Other {}\n",
        "Real.java": 'class Real { String url = "https://example.org/*code*/"; }',
    }
    for name, text in files.items():
        (source / name).write_text(text)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    commit = [
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    ]
    subprocess.run(commit, cwd=source, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    database = tmp_path / "database"
    database.mkdir()
    with zipfile.ZipFile(database / "src.zip", "w") as archive:
        archive.writestr("App.java", files["App.java"])
    coverage = source_coverage(database, source, revision=revision)
    assert not coverage["ready"]
    assert coverage["unextracted_non_executable_files"] == ["Comments.java", "Empty.java"]
    assert coverage["missing_application_files"] == ["Real.java"]
    with zipfile.ZipFile(database / "src.zip", "a") as archive:
        archive.writestr("Real.java", files["Real.java"])
    assert require_coverage(database, source, revision=revision)["coverage_ratio"] == 1
    (source / "Empty.java").write_text("class Empty { void active() {} }")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(commit, cwd=source, check=True)
    assert require_coverage(database, source, revision=revision)["ready"]
    assert not source_coverage(database, source)["ready"]


@pytest.mark.parametrize(
    "record",
    [
        {"status": "PENDING"},
        {"status": "BLOCKED", "unmodeled_files": ["App.java"]},
        {"status": "PASS", "unmodeled_files": ["App.java"]},
        {"status": "PASS", "unmodeled_files": [], "compiler_driver_pinned": False},
        {
            "status": "PASS",
            "unmodeled_files": [],
            "compiler_driver_pinned": True,
            "extraction_policy_sha256": "stale-policy",
        },
        [],
    ],
)
def test_unvalidated_supplement_cannot_be_reused_as_complete(
    tmp_path: Path,
    record: object,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        cwd=source,
        check=True,
    )
    database = tmp_path / "database"
    database.mkdir()
    (database / "supplement_model_check.json").write_text(json.dumps(record))
    with pytest.raises(ValueError, match="supplemental model check not passed"):
        source_coverage(database, source)
