"""Analyzer-side application source coverage, without evaluator labels or fixes."""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Any

NON_APPLICATION = frozenset(
    {
        "test",
        "tests",
        "testsuite",
        "example",
        "examples",
        "sample",
        "samples",
        "benchmark",
        "benchmarks",
        "buildSrc",
        ".mvn",
        "resources",
        "archetype-resources",
        "java-templates",
        "integration-tests",
        "e2e",
    }
)


def application_java(name: str) -> bool:
    path = Path(name)
    # Inspect source-root/module directories, not Java package names. Production
    # code can legitimately live in a package called "resources" or "tests".
    source_indices = [index for index, part in enumerate(path.parts) if part == "src"]
    prefix = path.parts[: source_indices[-1] + 3] if source_indices else path.parts[:-1]
    return (
        path.suffix == ".java"
        and not NON_APPLICATION.intersection(prefix)
        and not (path.parts and path.parts[0] == "gradle")
        and path.name not in {"package-info.java", "module-info.java"}
    )


def source_coverage(
    database: Path, source: Path, minimum_ratio: float = 1.0, revision: str = "HEAD"
) -> dict[str, Any]:
    if not 0 < minimum_ratio <= 1:
        raise ValueError("application coverage ratio must be in (0, 1]")
    revision = subprocess.check_output(
        ["git", "rev-parse", revision], cwd=source, text=True
    ).strip()
    tracked = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", revision], cwd=source, text=True
    ).splitlines()
    expected = sorted(name for name in tracked if application_java(name))
    try:
        with zipfile.ZipFile(database / "src.zip") as archive:
            names = archive.namelist()
    except zipfile.BadZipFile as error:
        raise ValueError("APPLICATION_COVERAGE_FAILED: corrupt source archive") from error
    # Index suffixes once: large repositories otherwise require quadratic matching.
    suffixes: set[str] = set()
    application_files = []
    for name in names:
        if not name.endswith(".java"):
            continue
        parts = name.split("/")
        suffixes.update("/".join(parts[i:]) for i in range(len(parts)))
        if application_java(name):
            application_files.append(name)
    missing = sorted(set(expected) - suffixes)
    ratio = (len(expected) - len(missing)) / len(expected) if expected else 0.0
    ready = bool(expected and application_files and ratio >= minimum_ratio)
    return {
        "ready": ready,
        "source_git_commit": revision,
        "expected_application_files": len(expected),
        "archive_application_files": len(application_files),
        "covered_application_files": len(expected) - len(missing),
        "coverage_ratio": ratio,
        "minimum_ratio": minimum_ratio,
        "missing_application_files": missing,
    }


def require_coverage(
    database: Path, source: Path, minimum_ratio: float = 1.0, revision: str = "HEAD"
) -> dict[str, Any]:
    result = source_coverage(database, source, minimum_ratio, revision)
    if not result["ready"]:
        raise ValueError(
            "APPLICATION_COVERAGE_FAILED: "
            f"{result['covered_application_files']}/{result['expected_application_files']} "
            "tracked application Java files extracted"
        )
    return result
