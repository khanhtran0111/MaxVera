"""Import the published IRIS v1 tables as immutable comparison references."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _nullable_number(value: str) -> int | float | None:
    normalized = value.strip()
    if not normalized or normalized.lower() in {"none", "n/a", "nan"} or normalized.startswith("#"):
        return None
    number = float(normalized)
    return int(number) if number.is_integer() else number


def _normalized_row(row: dict[str, str], source_name: str, source_commit: str) -> dict[str, Any]:
    clean = {key.strip(): value.strip() for key, value in row.items() if key is not None}
    project_slug = "_".join([clean["Author"], clean["Package"], clean["CVE"], clean["Tag"]])
    cwe_id = clean["CWE ID"]
    return {
        "schema_version": 1,
        "record_kind": "published_reference",
        "source_name": source_name,
        "source_commit": source_commit,
        "case_id": f"{project_slug}::{cwe_id}",
        "project_slug": project_slug,
        "cve_id": clean["CVE"],
        "cwe_id": cwe_id,
        "detected": bool(_nullable_number(clean["Recall"])),
        "num_alerts": _nullable_number(clean["Alerts"]),
        "num_paths": _nullable_number(clean["Paths"]),
        "num_tp_alerts": _nullable_number(clean["TP Alerts"]),
        "num_tp_paths": _nullable_number(clean["TP Paths"]),
        "precision": _nullable_number(clean["Precision"]),
        "f1": _nullable_number(clean["F1"]),
    }


def import_reference_csv(
    source: str | Path,
    output: str | Path,
    *,
    source_name: str,
    source_commit: str,
) -> dict[str, Any]:
    source_path = Path(source)
    output_path = Path(output)
    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        records = [
            _normalized_row(row, source_name, source_commit) for row in csv.DictReader(handle)
        ]

    case_ids = [record["case_id"] for record in records]
    duplicate_ids = sorted(case_id for case_id, count in Counter(case_ids).items() if count > 1)
    if duplicate_ids:
        raise ValueError(f"reference contains duplicate case IDs: {duplicate_ids}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    if output_path.exists():
        if output_path.read_text(encoding="utf-8") != rendered:
            raise FileExistsError(f"refusing to overwrite a different reference: {output_path}")
    else:
        output_path.write_text(rendered, encoding="utf-8", newline="\n")

    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    return {
        "schema_version": 1,
        "source": str(source_path.as_posix()),
        "source_sha256": digest,
        "source_commit": source_commit,
        "source_name": source_name,
        "output": str(output_path.as_posix()),
        "num_records": len(records),
        "num_detected": sum(record["detected"] for record in records),
        "cwe_distribution": dict(sorted(Counter(record["cwe_id"] for record in records).items())),
    }
