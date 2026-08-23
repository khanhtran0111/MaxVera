from __future__ import annotations

import csv
from pathlib import Path

from openiris.baselines.reference import import_reference_csv


def test_reference_import_uses_project_and_cwe_as_case_key(tmp_path: Path) -> None:
    source = tmp_path / "reference.csv"
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "CWE ID",
                "CVE",
                "Author",
                "Package ",
                "Tag",
                "Recall",
                "Alerts",
                "Paths",
                "TP Alerts",
                "TP Paths",
                "Precision",
                "F1",
            ]
        )
        writer.writerow(["CWE-078", "CVE-1", "a", "p", "1", "0", "0", "0", "0", "0", "N/A", "0"])
        writer.writerow(["CWE-094", "CVE-1", "a", "p", "1", "1", "2", "3", "1", "1", "0.5", "0.66"])

    summary = import_reference_csv(
        source,
        tmp_path / "out.jsonl",
        source_name="test",
        source_commit="a" * 40,
    )

    assert summary["num_records"] == 2
    assert summary["num_detected"] == 1
