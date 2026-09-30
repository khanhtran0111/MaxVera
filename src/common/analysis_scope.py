"""Shared split handling for development and locked-test analysis runs."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from src.reproduction.common import read_csv

SCOPES = {"development", "test_locked"}


def analysis_scope(config: Mapping[str, Any]) -> str:
    """Return the explicit scope, preserving development-config compatibility."""
    scope = str(config.get("analysis_scope", "development"))
    if scope not in SCOPES:
        raise ValueError(f"unsupported analysis scope: {scope}")
    return scope


def split_paths(config: Mapping[str, Any]) -> tuple[str, str]:
    """Return (selected split, disjoint holdout split) from an experiment config."""
    dataset = cast(Mapping[str, Any], config["dataset"])
    scope = analysis_scope(config)
    if scope == "development":
        selected = dataset.get("analysis_split", dataset.get("development_split"))
        holdout = dataset.get("holdout_split", dataset.get("forbidden_test_split"))
    else:
        selected = dataset.get("analysis_split")
        holdout = dataset.get("holdout_split")
    if not isinstance(selected, str) or not isinstance(holdout, str):
        raise ValueError(f"{scope} analysis requires explicit selected and holdout split paths")
    return selected, holdout


def selected_rows(
    repo_root: Path, config: Mapping[str, Any]
) -> tuple[list[dict[str, str]], str, str]:
    """Resolve opaque analysis rows and enforce split disjointness."""
    dataset = cast(Mapping[str, Any], config["dataset"])
    projects = read_csv(repo_root / str(dataset["analysis_manifest"]))
    allowed_columns = {
        "project_id",
        "source_dir",
        "source_required",
        "jdk_version",
        "maven_version",
        "gradle_version",
        "use_gradlew",
    }
    if any(set(row) - allowed_columns for row in projects):
        raise ValueError("analysis manifest contains protected columns")
    selected_path, holdout_path = split_paths(config)
    selected_ids = [row["project_id"] for row in read_csv(repo_root / selected_path)]
    holdout_ids = {row["project_id"] for row in read_csv(repo_root / holdout_path)}
    if set(selected_ids) & holdout_ids:
        raise ValueError("analysis and holdout splits overlap")
    by_id = {row["project_id"]: row for row in projects}
    missing = set(selected_ids) - set(by_id)
    if missing:
        raise ValueError(f"analysis split contains {len(missing)} unknown projects")
    return [by_id[project_id] for project_id in selected_ids], selected_path, holdout_path


def validate_manifest_selection(
    repo_root: Path, manifest: Mapping[str, Any]
) -> tuple[set[str], str]:
    """Validate a manifest selection against its recorded split without label access."""
    dataset = cast(Mapping[str, Any], manifest["dataset"])
    scope = str(manifest.get("analysis_scope", "development"))
    if scope not in SCOPES:
        raise ValueError("manifest analysis scope is invalid")
    split = dataset.get("split")
    holdout = dataset.get("holdout_split")
    if not isinstance(split, str) or not isinstance(holdout, str):
        # Legacy development manifests predate the explicit holdout path.
        if scope != "development":
            raise ValueError("locked-test manifest lacks explicit split provenance")
        split = "data/processed/splits/development.csv"
        holdout = "data/processed/splits/test_locked.csv"
    expected = {row["project_id"] for row in read_csv(repo_root / split)}
    held_out = {row["project_id"] for row in read_csv(repo_root / holdout)}
    selected = {str(value) for value in manifest.get("selected_project_ids", [])}
    if not selected or not selected <= expected or selected & held_out:
        raise ValueError(f"selection violates the {scope} split contract")
    if manifest.get("mode") == "full" and selected != expected:
        raise ValueError(f"full run does not cover the complete {scope} split")
    return selected, scope
