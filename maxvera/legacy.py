"""Read-only importer for historical exports; aggregate CSV never becomes findings."""

import csv
from pathlib import Path

from src.common.provenance import sha256_file


def index_exports(paths: list[Path]) -> dict:
    entries = []
    for path in paths:
        entry = {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        if path.suffix == ".csv":
            with path.open(newline="") as handle:
                entry["rows"] = list(csv.DictReader(handle))
        entries.append(entry)
    return {"schema_version": "2.0", "legacy_only": True, "entries": entries}
