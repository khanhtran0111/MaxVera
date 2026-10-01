"""Audit and seal Phase 13 analyzer artifacts before evaluator access."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.baselines.validate import _verify_checksums
from src.baselines.validate import validate as validate_baseline
from src.common.provenance import collect_git, sha256_file, utc_now
from src.experiments.phase13 import DEV_SPLIT, RUN_ID, TEST_SPLIT, AnalyzerPipeline, _phase12_lock
from src.graphs.program.validate import validate as validate_program
from src.graphs.useg.validate import validate as validate_useg
from src.hypotheses.validate import validate as validate_hypotheses
from src.reproduction.common import atomic_json, read_csv, read_jsonl
from src.specification.validate import validate as validate_specifications


def run_roots(root: Path, run_id: str) -> dict[str, Path]:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("invalid Phase 13 run ID")
    pipeline = AnalyzerPipeline(root, run_id, confirm_api_spend=False)
    analysis = pipeline.analysis_root
    roots = {
        "phase6": analysis / "hypotheses/static" / pipeline.p6_id,
        "phase7": analysis / "program_graph" / pipeline.p7_id,
        "phase9": analysis / "useg" / pipeline.p9_id,
        "B0": analysis / "b0" / f"{run_id}_b0",
    }
    for baseline, name in {
        "B3": "raw_context_gptoss20b",
        "B4": "text_rag_gptoss20b",
        "B5": "static_hypothesis",
    }.items():
        roots[baseline] = analysis / "baselines" / name / f"{run_id}_{baseline.lower()}"
    for baseline, name in {
        "B6": "program_graph_only",
        "B7": "security_kg_only",
        "B8": "useg_no_pruning",
        "B9": "full_useg",
    }.items():
        roots[baseline] = analysis / "specifications" / name / f"{run_id}_{baseline.lower()}"
    return roots


def _file_lock_paths(run_id: str) -> tuple[str, ...]:
    return (
        TEST_SPLIT,
        DEV_SPLIT,
        "configs/experiments/phase13.yaml",
        "configs/experiments/ablation.yaml",
        "configs/experiments/main.yaml",
        "configs/experiments/phase11_static_verification.yaml",
        "configs/experiments/phase12_calibration.yaml",
        f"results/phase13/{run_id}/analyzer_status.json",
        f"data/interim/phase13_database_manifests/{run_id}.json",
        f"data/interim/phase13_database_status/{run_id}.jsonl",
    )


def audit(root: Path, run_id: str) -> dict[str, Any]:
    selected = {row["project_id"] for row in read_csv(root / TEST_SPLIT)}
    development = {row["project_id"] for row in read_csv(root / DEV_SPLIT)}
    if len(selected) != 24 or selected & development:
        raise ValueError("invalid frozen Phase 13 split")
    reports: dict[str, Any] = {}
    for name, path in run_roots(root, run_id).items():
        if not path.is_dir() or any(path.parent.glob(".*.inprogress")):
            raise ValueError(f"analyzer output missing or unfinished: {name}")
        _verify_checksums(path)
        manifest = json.loads((path / "manifest.json").read_text())
        rows = read_jsonl(path / "project_status.jsonl")
        active = [row for row in rows if row.get("status") != "EXCLUDED_WITH_REASON"]
        if (
            len(active) != 24
            or {row["project_id"] for row in active} != selected
            or any(row.get("status") not in {"SUCCESS", "ANALYSIS_FAILED"} for row in active)
        ):
            raise ValueError(f"analyzer selected-project coverage is invalid: {name}")
        if manifest.get("git", {}).get("dirty") is not False:
            raise ValueError(f"analyzer output was produced from a dirty worktree: {name}")
        expected_status = (
            "SUCCESS" if all(row["status"] == "SUCCESS" for row in active) else "FAILED"
        )
        if (path / "STATUS").read_text().strip() != expected_status:
            raise ValueError(f"analyzer run STATUS is inconsistent: {name}")
        if name == "phase6":
            result = validate_hypotheses(path, repo_root=root, require_metrics=False)
        elif name == "phase7":
            result = validate_program(path, repo_root=root)
        elif name == "phase9":
            result = validate_useg(path, repo_root=root)
        elif name in {"B3", "B4", "B5"}:
            result = validate_baseline(path, require_metrics=False)
        elif name in {"B6", "B7", "B8", "B9"}:
            result = validate_specifications(path, repo_root=root)
        else:
            result = "PASS: B0 checksum and project coverage audit"
        print(result, flush=True)
        reports[name] = {
            "run_root": path.relative_to(root).as_posix(),
            "run_id": manifest["run_id"],
            "manifest_sha256": sha256_file(path / "manifest.json"),
            "checksums_index_sha256": sha256_file(path / "checksums.sha256"),
            "project_status_sha256": sha256_file(path / "project_status.jsonl"),
            "project_counts": dict(Counter(row["status"] for row in active)),
            "validation": result,
            "git": manifest["git"],
        }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "sealed_at": utc_now(),
        "status": "SEALED_ANALYZER_SNAPSHOT",
        "analysis_scope": "test_locked",
        "evaluator_labels_opened": False,
        "failures_count_as_miss": True,
        "selected_project_ids": sorted(selected),
        "analysis_runs": reports,
        "phase12_lock": dict(_phase12_lock(root)),
        "git": collect_git(root),
        "file_locks": {
            relative: sha256_file(root / relative) for relative in _file_lock_paths(run_id)
        },
    }


def validate_snapshot(root: Path, path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and sha256_file(path) != expected_sha256:
        raise ValueError("analyzer snapshot checksum mismatch")
    snapshot: dict[str, Any] = json.loads(path.read_text())
    if (
        snapshot.get("status") != "SEALED_ANALYZER_SNAPSHOT"
        or snapshot.get("analysis_scope") != "test_locked"
        or snapshot.get("evaluator_labels_opened") is not False
        or snapshot.get("failures_count_as_miss") is not True
    ):
        raise ValueError("invalid analyzer snapshot contract")
    selected = {row["project_id"] for row in read_csv(root / TEST_SPLIT)}
    if len(selected) != 24 or snapshot.get("selected_project_ids") != sorted(selected):
        raise ValueError("sealed analyzer selected-project coverage mismatch")
    if set(snapshot["file_locks"]) != set(_file_lock_paths(str(snapshot["run_id"]))):
        raise ValueError("sealed analyzer file-lock coverage mismatch")
    for relative, digest in snapshot["file_locks"].items():
        if sha256_file(root / relative) != digest:
            raise ValueError(f"sealed analyzer file changed: {relative}")
    expected_roots = run_roots(root, str(snapshot["run_id"]))
    if set(snapshot["analysis_runs"]) != set(expected_roots):
        raise ValueError("sealed analyzer run coverage mismatch")
    for name, lock in snapshot["analysis_runs"].items():
        run = root / lock["run_root"]
        if run.resolve() != expected_roots[name].resolve():
            raise ValueError(f"sealed analyzer run root mismatch: {name}")
        for key, filename in (
            ("manifest_sha256", "manifest.json"),
            ("checksums_index_sha256", "checksums.sha256"),
            ("project_status_sha256", "project_status.jsonl"),
        ):
            if sha256_file(run / filename) != lock[key]:
                raise ValueError(f"sealed analyzer output changed: {name}/{filename}")
        _verify_checksums(run)
    if dict(_phase12_lock(root)) != snapshot["phase12_lock"]:
        raise ValueError("sealed calibration lock changed")
    return snapshot


def seal(root: Path, run_id: str) -> Path:
    path = root / "results/phase13" / run_id / "analyzer_snapshot.json"
    if path.exists():
        validate_snapshot(root, path)
        return path
    if collect_git(root).get("dirty") is not False:
        raise ValueError("sealing requires a clean Git worktree")
    atomic_json(path, audit(root, run_id))
    validate_snapshot(root, path)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    if args.audit_only:
        report = audit(root, args.run_id)
        print(json.dumps({"status": "AUDIT_PASS", "runs": len(report["analysis_runs"])}))
    else:
        print(f"SEALED: {seal(root, args.run_id)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
