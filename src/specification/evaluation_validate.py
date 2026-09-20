"""Validate separate evaluator-only Phase 10 specification metrics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from src.common.provenance import sha256_file
from src.reproduction.common import read_jsonl

REQUIRED = {
    "STATUS",
    "checksums.sha256",
    "manifest.json",
    "metrics_aggregate.json",
    "project_metrics.jsonl",
    "spec_metrics.jsonl",
}


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def validate(run_root: Path) -> str:
    missing = sorted(name for name in REQUIRED if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 10 evaluation outputs: {', '.join(missing)}")
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != "PASS":
        raise ValueError("Phase 10 evaluation status is not PASS")
    manifest = _json(run_root / "manifest.json")
    if (
        manifest.get("phase") != 10
        or manifest.get("data_role") != "evaluator"
        or manifest.get("run_id") != run_root.name
    ):
        raise ValueError("not a Phase 10 evaluator artifact")
    indexed: set[str] = set()
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 10 evaluation checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if indexed != actual:
        raise ValueError("Phase 10 evaluation checksum coverage mismatch")

    aggregate = _json(run_root / "metrics_aggregate.json")
    projects = read_jsonl(run_root / "project_metrics.jsonl")
    specs = read_jsonl(run_root / "spec_metrics.jsonl")
    project_counts = Counter(str(row["baseline_id"]) for row in projects)
    spec_counts = Counter(str(row["baseline_id"]) for row in specs)
    expected_projects = int(aggregate["annotated_development_projects"])
    baselines = aggregate.get("baselines")
    if not isinstance(baselines, Mapping) or set(baselines) != {"B6", "B7", "B8", "B9"}:
        raise ValueError("Phase 10 evaluation baseline coverage mismatch")
    for baseline_id, value in baselines.items():
        if not isinstance(value, Mapping):
            raise ValueError("invalid Phase 10 evaluation aggregate")
        if project_counts[baseline_id] != expected_projects:
            raise ValueError(f"Phase 10 {baseline_id} annotated project coverage mismatch")
        if spec_counts[baseline_id] != int(value["specifications"]):
            raise ValueError(f"Phase 10 {baseline_id} specification count mismatch")
        precision = float(value["spec_precision_proxy"])
        recall = float(value["project_recall_proxy_intention_to_analyze"])
        if not (0.0 <= precision <= 1.0 and 0.0 <= recall <= 1.0):
            raise ValueError("Phase 10 evaluation metric outside [0,1]")
    return f"PASS: Phase 10 annotated specification proxy ({expected_projects} projects)"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args(argv)
    print(validate(args.run_root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
