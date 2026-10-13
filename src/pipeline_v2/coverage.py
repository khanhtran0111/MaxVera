"""Analyzer-side application source coverage, without evaluator labels or fixes."""

from __future__ import annotations

import json
import re
import subprocess
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from src.common.provenance import sha256_file

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
        "demo",
        "demos",
        "testFixtures",
    }
)


def application_java(name: str) -> bool:
    path = Path(name)
    # Inspect source-root/module directories, not Java package names. Production
    # code can legitimately live in a package called "resources" or "tests".
    source_indices = [index for index, part in enumerate(path.parts) if part == "src"]
    prefix = path.parts[: source_indices[-1] + 3] if source_indices else path.parts[:-1]
    test_source = any(
        index + 1 < len(path.parts)
        and (path.parts[index + 1] == "it" or path.parts[index + 1].startswith("test-"))
        for index in source_indices
    )
    return (
        path.suffix == ".java"
        and not NON_APPLICATION.intersection(prefix)
        and not (path.parts and path.parts[0] == "gradle")
        and path.name not in {"package-info.java", "module-info.java"}
        and not test_source
    )


def extraction_options() -> list[str]:
    """Keep test duplicates from shadowing production classes during no-build.

    Apply only to the new, coverage-gated repair profile. Java package names
    called tests/resources remain analyzable below src/main/java.
    """
    return ["-Ojava.exclude=**/src/{test,testFixtures,test-*,it}/**"]


@lru_cache(maxsize=8192)
def non_executable_source(source: Path, revision: str, name: str) -> bool:
    """Exempt only empty/comment-only blobs at the requested revision.

    Keep strings intact (including URLs and text blocks), and fail closed on
    unavailable Git objects. Never inspect vulnerability labels or changed lines.
    """
    result = subprocess.run(
        ["git", "--no-lazy-fetch", "show", f"{revision}:{name}"],
        cwd=source,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if result.returncode:
        return False
    text = result.stdout.decode("utf-8", errors="replace").lstrip("\ufeff")
    tokens = re.compile(
        r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\r\n]*'
    )
    text = tokens.sub(lambda match: "" if match[0].startswith(("/*", "//")) else match[0], text)
    return not text.strip()


def executable_missing(
    source: Path, revision: str, missing: list[str]
) -> tuple[list[str], list[str]]:
    # Bound blob reads for badly truncated giant SDK databases. Uninspected
    # files remain missing; the bound can never turn an incomplete DB into READY.
    excluded = [name for name in missing[:512] if non_executable_source(source, revision, name)]
    excluded_set = set(excluded)
    return [name for name in missing if name not in excluded_set], excluded


def source_coverage(
    database: Path, source: Path, minimum_ratio: float = 1.0, revision: str = "HEAD"
) -> dict[str, Any]:
    if not 0 < minimum_ratio <= 1:
        raise ValueError("application coverage ratio must be in (0, 1]")
    revision = subprocess.check_output(
        ["git", "rev-parse", revision], cwd=source, text=True
    ).strip()
    metadata_path = database / "codeql-database.yml"
    model_path = database / "supplement_model_check.json"
    if model_path.exists():
        model_check = json.loads(model_path.read_text())
        if (
            not isinstance(model_check, dict)
            or model_check.get("status") != "PASS"
            or model_check.get("unmodeled_files")
            or model_check.get("compiler_driver_pinned") is not True
            or model_check.get("extraction_policy_sha256")
            != sha256_file(Path(__file__).with_name("extraction.py"))
        ):
            raise ValueError("APPLICATION_COVERAGE_FAILED: supplemental model check not passed")
    if metadata_path.exists():
        try:
            metadata = yaml.safe_load(metadata_path.read_text())
        except yaml.YAMLError as error:
            raise ValueError("APPLICATION_COVERAGE_FAILED: malformed database metadata") from error
        if (
            not isinstance(metadata, dict)
            or metadata.get("inProgress")
            or metadata.get("finalised") is False
        ):
            raise ValueError("APPLICATION_COVERAGE_FAILED: database is not finalized")
        creation = metadata.get("creationMetadata")
        database_revision = creation.get("sha") if isinstance(creation, dict) else None
        if database_revision != revision:
            raise ValueError("APPLICATION_COVERAGE_FAILED: database revision mismatch")
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
    missing, non_executable = executable_missing(source, revision, sorted(set(expected) - suffixes))
    excluded_set = set(non_executable)
    expected = [name for name in expected if name not in excluded_set]
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
        "unextracted_non_executable_files": non_executable,
        "non_executable_exclusion_reason": "pinned Git blob is empty or comment-only",
        "supplement_model_check_sha256": sha256_file(model_path) if model_path.exists() else None,
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
