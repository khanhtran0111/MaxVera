from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.smoke.harness import (
    candidate_from_text,
    parse_sarif,
    validate_candidate,
    validate_smoke_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def smoke_root(tmp_path: Path) -> Path:
    """Unit validation uses fixture directories, never downloaded benchmark databases."""
    import shutil

    manifest = tmp_path / "data/processed/manifests/smoke.csv"
    manifest.parent.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / "data/processed/manifests/smoke.csv", manifest)
    rows = list(csv.DictReader(manifest.open()))
    for row in rows:
        for field in ("source_dir", "codeql_database"):
            (tmp_path / row[field]).mkdir(parents=True)
    return tmp_path


def test_smoke_manifest_is_opaque_and_covers_each_available_cwe(smoke_root: Path) -> None:
    rows = validate_smoke_manifest(smoke_root)
    with (REPO_ROOT / "data/processed/evaluator_only/D_repro_v1_labels.csv").open(
        "r", encoding="utf-8", newline=""
    ) as handle:
        labels = {row["project_id"]: row for row in csv.DictReader(handle)}
    assert {labels[row["project_id"]]["ground_truth_cwe"] for row in rows} == {
        "CWE-22",
        "CWE-78",
        "CWE-79",
        "CWE-94",
    }
    assert all("cwe" not in field.lower() and "cve" not in field.lower() for field in rows[0])


def test_smoke_validation_rejects_missing_database(smoke_root: Path) -> None:
    rows = validate_smoke_manifest(smoke_root)
    (smoke_root / rows[0]["codeql_database"]).rmdir()
    with pytest.raises(ValueError, match="smoke input is missing"):
        validate_smoke_manifest(smoke_root)


def test_candidate_schema_is_strict() -> None:
    candidate = {
        "candidate_type": "command_injection",
        "source": "method parameter",
        "sink": "Runtime.exec",
        "confidence": 0.9,
        "abstain": False,
    }
    assert validate_candidate(candidate) == candidate
    with pytest.raises(ValueError, match="fields"):
        validate_candidate({**candidate, "extra": "forbidden"})
    with pytest.raises(ValueError, match="between"):
        validate_candidate({**candidate, "confidence": 1.1})
    wrapped = "```json\n" + json.dumps(candidate) + "\n```"
    assert candidate_from_text(wrapped) == candidate


def test_parse_sarif_accepts_empty_valid_result_set(tmp_path: Path) -> None:
    sarif = tmp_path / "findings.sarif"
    sarif.write_text('{"version":"2.1.0","runs":[{"results":[]}]}', encoding="utf-8")
    assert parse_sarif(sarif) == 0
