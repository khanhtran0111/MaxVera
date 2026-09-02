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


def test_smoke_manifest_is_opaque_and_covers_each_available_cwe() -> None:
    rows = validate_smoke_manifest(REPO_ROOT)
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


def test_smoke_selection_reproduces_fastest_success_per_cwe() -> None:
    rows = validate_smoke_manifest(REPO_ROOT)
    with (REPO_ROOT / "data/processed/manifests/cwe_bench_v1.csv").open(
        "r", encoding="utf-8", newline=""
    ) as handle:
        canonical = list(csv.DictReader(handle))
    statuses = {
        item["project_id"]: item
        for item in (
            json.loads(line)
            for line in (
                REPO_ROOT / "data/interim/build_info/build_status.jsonl"
            ).read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    }
    candidates: dict[str, list[tuple[float, str]]] = {}
    for item in canonical:
        status = statuses[item["project_id"]]
        if status["status"] == "SUCCESS":
            candidates.setdefault(item["ground_truth_cwe"], []).append(
                (float(status["codeql_seconds"]), item["project_id"])
            )
    expected = {min(items)[1] for items in candidates.values()}
    assert {row["project_id"] for row in rows} == expected


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
