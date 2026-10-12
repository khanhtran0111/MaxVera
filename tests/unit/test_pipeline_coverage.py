from __future__ import annotations

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
