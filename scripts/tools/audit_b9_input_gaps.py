"""Offline evaluator diagnostic; classifications are evidence hints, never waivers."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file, utc_now
from src.pipeline_v2.coverage import application_java
from src.pipeline_v2.runtime import configuration, selection_ids
from src.reproduction.common import atomic_json, write_checksums


def source_text(source: Path, revision: str, name: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "--no-lazy-fetch", "show", f"{revision}:{name}"],
            cwd=source,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return result.stdout.decode("utf-8", errors="replace") if result.returncode == 0 else None


def audit(root: Path, config_path: Path, input_path: Path, output: Path) -> dict[str, Any]:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("input gap audit requires an evaluator process")
    output = output.resolve()
    if not output.is_relative_to((root / "results/diagnostics").resolve()) or output.exists():
        raise ValueError("choose a new output directory inside results/diagnostics")
    config = configuration(root, config_path)
    auditor_hash = sha256_file(Path(__file__))
    selected = selection_ids(root, config)
    payload = input_path.read_bytes()
    records = json.loads(payload)["projects"]
    if [row["project_id"] for row in records] != selected:
        raise ValueError("input report must account for the exact ordered cohort")
    if any(row["status"] == "PENDING" for row in records):
        raise ValueError("wait for the complete input inspection before auditing")
    output.mkdir(parents=True)
    (output / "input_projects.json").write_bytes(payload)
    cases = []
    details = []
    for row in records:
        case: dict[str, Any] = {"project_id": row["project_id"], "status": row["status"]}
        for side in ("vulnerable", "fixed"):
            state = row[side]
            choices = [item for item in state.get("rejected", []) if "coverage" in item]
            best: dict[str, Any] = max(
                choices, key=lambda item: item["coverage"]["coverage_ratio"], default={}
            )
            coverage = state.get("coverage", best.get("coverage", {}))
            missing = coverage.get("missing_application_files", [])
            case[f"{side}_ready"] = state["ready"]
            case[f"{side}_expected"] = coverage.get("expected_application_files", "")
            case[f"{side}_missing"] = len(missing)
            case[f"{side}_reason"] = (
                "READY"
                if state["ready"]
                else "MISSING_SOURCE_FILES" if missing else "NO_VALID_DATABASE"
            )
            if state["ready"]:
                continue
            module_counts = Counter(name.split("/src/", 1)[0] for name in missing)
            hints: Counter[str] = Counter()
            evidence = []
            source = root / config["fixed_preparation"]["source_root"] / row["project_id"]
            # Bound content inspection for very large SDKs; all missing paths
            # remain preserved in the frozen input report and module counts.
            for name in missing[:200]:
                hint = "APPLICATION_SOURCE_MISSING"
                if not application_java(name):
                    hint = "NON_APPLICATION_PATH_UNDER_CURRENT_POLICY"
                else:
                    text = source_text(source, coverage["source_git_commit"], name)
                    if text is None:
                        hint = "SOURCE_CONTENT_UNAVAILABLE"
                    else:
                        # These hints do not exempt files from source coverage.
                        if re.search(r"(?m)^\s*(?:package|import)\b[^;]*\{\{", text):
                            hint = "GENERATOR_TEMPLATE_MARKER"
                        elif "/src/main/aspect/" in name:
                            hint = "ASPECTJ_SOURCE_REQUIRES_BUILD_REVIEW"
                        elif not re.search(r"\b(?:class|interface|enum|record)\s+\w+", text):
                            hint = "POSSIBLE_FRAGMENT_WITHOUT_TYPE_DECLARATION"
                hints[hint] += 1
                evidence.append({"file": name, "hint": hint})
            details.append(
                {
                    "project_id": row["project_id"],
                    "side": side,
                    "database": best.get("database"),
                    "source_git_commit": coverage.get("source_git_commit"),
                    "missing_files": len(missing),
                    "missing_by_module": dict(module_counts),
                    "content_sample_size": len(evidence),
                    "sample_hints": dict(hints),
                    "sample_evidence": evidence,
                    "error": state.get("error"),
                }
            )
        cases.append(case)
    with (output / "cases.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(cases[0]))
        writer.writeheader()
        writer.writerows(cases)
    atomic_json(output / "gaps.json", {"sides": details})
    summary = {
        "created_at": utc_now(),
        "projects": len(cases),
        "ready": sum(row["status"] == "READY" for row in cases),
        "blocked": sum(row["status"] == "BLOCKED" for row in cases),
        "blocked_sides": len(details),
        "api_calls": 0,
        "codeql_queries": 0,
        "coverage_waivers": 0,
        "input_snapshot_sha256": sha256_file(output / "input_projects.json"),
        "config_sha256": sha256_file(config_path),
        "coverage_policy_sha256": sha256_file(root / "src/pipeline_v2/coverage.py"),
        "auditor_sha256": auditor_hash,
        "git_lazy_fetch_enabled": False,
    }
    atomic_json(output / "summary.json", summary)
    write_checksums(output)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/b9_benchmark_120_complete.yaml")
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(audit(root, root / args.config, root / args.input, root / args.output)))


if __name__ == "__main__":
    main()
