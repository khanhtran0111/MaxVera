"""Validate Phase 4 completeness, recomputability, and artifact integrity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.reproduction.common import FINAL_STATUSES, aggregate_metrics, read_jsonl
from src.reproduction.runner import BASELINE_ROOTS


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def _verify_checksums(run_root: Path) -> None:
    index = run_root / "checksums.sha256"
    if not index.is_file():
        raise ValueError(f"missing checksum index: {index}")
    expected_files: set[str] = set()
    for line in index.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = run_root / relative
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError(f"checksum mismatch: {path}")
        expected_files.add(relative)
    actual_files = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and not path.is_symlink() and path != index
    }
    missing = actual_files - expected_files
    if missing:
        raise ValueError(f"unindexed output files: {sorted(missing)[:5]}")


def validate_one(root: Path, baseline_id: str, run_id: str, require_full: bool) -> str:
    run_root = root / "results/reproduction" / BASELINE_ROOTS[baseline_id] / run_id
    manifest = _json(run_root / "manifest.json")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    if len(statuses) != 120 or len({row.get("project_id") for row in statuses}) != 120:
        raise ValueError(f"{baseline_id}: project status coverage is not 120/120")
    invalid = [row for row in statuses if row.get("status") not in FINAL_STATUSES]
    if invalid:
        raise ValueError(f"{baseline_id}: non-final project statuses remain")
    selected = set(manifest.get("selected_project_ids", []))
    selected_rows = [row for row in statuses if row.get("project_id") in selected]
    if require_full and (manifest.get("mode") != "full" or len(selected) != 104):
        raise ValueError(f"{baseline_id}: full gate requires exactly 104 selected databases")
    failed = [row for row in selected_rows if row.get("status") != "SUCCESS"]
    if failed:
        raise ValueError(f"{baseline_id}: {len(failed)} selected analyses did not succeed")
    metrics_rows = read_jsonl(run_root / "metrics_project.jsonl")
    if len(metrics_rows) != 120:
        raise ValueError(f"{baseline_id}: independent metrics do not cover 120 rows")
    stored = _json(run_root / "metrics_dataset_canonical.json")
    if aggregate_metrics(metrics_rows) != stored:
        raise ValueError(f"{baseline_id}: aggregate is not independently recomputable")
    if baseline_id in {"B1", "B2"} and require_full:
        artifact = _json(run_root / "metrics_artifact_compatible.json")
        if artifact.get("projects") != 121 or not artifact.get("artifact_row_121_present"):
            raise ValueError(f"{baseline_id}: public artifact row 121 is incomplete")
    if baseline_id == "B2":
        for row in selected_rows:
            stage = _json(run_root / "projects" / str(row["project_id"]) / "stages.json")
            if stage.get("status") != "SUCCESS" or stage.get("missing_required_artifacts"):
                raise ValueError(f"B2: incomplete IRIS stages for {row['project_id']}")
        if manifest.get("claim") != "IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter":
            raise ValueError("B2: required claim language is missing")
        model = manifest.get("model", {})
        if not isinstance(model, dict) or model.get("id") != "openai/gpt-oss-20b":
            raise ValueError("B2: canonical GPT-OSS 20B model provenance is missing")
        if not model.get("provider_route") or model.get("routing", {}).get(
            "allow_fallbacks"
        ) is not False:
            raise ValueError("B2: pinned no-fallback OpenRouter route is missing")
    if manifest.get("toolchain_variance", {}).get("paper_compatible") is not False:
        raise ValueError(f"{baseline_id}: toolchain substitution is not explicit")
    _verify_checksums(run_root)
    return f"{baseline_id}: PASS ({len(selected)} selected, 120 statuses)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--require-full", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    for baseline_id in BASELINE_ROOTS:
        print(validate_one(root, baseline_id, args.run_id, args.require_full))
    print("Phase 4 validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
