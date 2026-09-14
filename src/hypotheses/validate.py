"""Validate Phase 6 structure, development isolation, budgets, and metrics."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from src.common.provenance import sha256_file
from src.hypotheses.signals import PATTERN_VERSION
from src.reproduction.common import read_csv, read_jsonl

REQUIRED_FILES = {
    "STATUS",
    "candidates.jsonl",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "environment.json",
    "hypotheses.jsonl",
    "llm_calls.jsonl",
    "manifest.json",
    "project_status.jsonl",
    "resource_usage.csv",
    "signals.jsonl",
    "status_summary.json",
    "stderr.log",
    "stdout.log",
}
CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,4}$")


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return loaded


def _verify_checksums(run_root: Path) -> None:
    index = run_root / "checksums.sha256"
    indexed: set[str] = set()
    for line in index.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path != index
    }
    if actual - indexed:
        raise ValueError(f"unindexed Phase 6 output: {sorted(actual - indexed)[:5]}")


def _selected_outcomes(statuses: Sequence[Mapping[str, Any]], run_status: str) -> tuple[int, int]:
    invalid = [row for row in statuses if row.get("status") not in {"SUCCESS", "ANALYSIS_FAILED"}]
    if not statuses or invalid:
        raise ValueError("Phase 6 project statuses are empty or non-final")
    successes = sum(row.get("status") == "SUCCESS" for row in statuses)
    failures = len(statuses) - successes
    if run_status == "SUCCESS" and failures:
        raise ValueError("run STATUS is SUCCESS but analysis failures exist")
    if run_status == "FAILED" and not failures:
        raise ValueError("run STATUS is FAILED but every project succeeded")
    if run_status not in {"SUCCESS", "FAILED"}:
        raise ValueError("Phase 6 run STATUS is not final")
    return successes, failures


def _validate_location(location: object, source_root: Path) -> None:
    if not isinstance(location, Mapping):
        raise ValueError("hypothesis location must be an object")
    file = location.get("file")
    line = location.get("line")
    if not isinstance(file, str) or not file.endswith(".java"):
        raise ValueError("hypothesis location must use a relative Java path")
    pure = PurePosixPath(file.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError("hypothesis location escapes the source root")
    target = source_root / pure
    if not target.is_file():
        raise ValueError(f"hypothesis source file does not exist: {file}")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise ValueError("hypothesis location line must be positive")
    if line > len(target.read_text(encoding="utf-8", errors="replace").splitlines()):
        raise ValueError("hypothesis location line exceeds the source file")


def _verify_metrics(run_root: Path, statuses: Sequence[Mapping[str, Any]], successes: int) -> None:
    for name in ("metrics_project.jsonl", "metrics_aggregate.json"):
        if not (run_root / name).is_file():
            raise ValueError(f"missing Phase 6 evaluator output: {name}")
    metrics = read_jsonl(run_root / "metrics_project.jsonl")
    status_by_id = {str(row["project_id"]): row["status"] for row in statuses}
    metric_by_id = {str(row["project_id"]): row for row in metrics}
    if len(metric_by_id) != len(metrics) or set(metric_by_id) != set(status_by_id):
        raise ValueError("Phase 6 metric coverage does not match project statuses")
    for project_id, status in status_by_id.items():
        metric = metric_by_id[project_id]
        if metric.get("status") != status:
            raise ValueError("Phase 6 metric status mismatch")
        if status != "SUCCESS" and (
            metric.get("first_correct_rank") is not None
            or float(metric.get("hypothesis_reciprocal_rank", 0.0)) != 0.0
        ):
            raise ValueError("Phase 6 analysis failure was not evaluated as a miss")
    aggregate = _json(run_root / "metrics_aggregate.json")
    if int(aggregate.get("projects", -1)) != len(statuses):
        raise ValueError("Phase 6 aggregate project coverage mismatch")
    if int(aggregate.get("analysis_successes", -1)) != successes:
        raise ValueError("Phase 6 aggregate success count mismatch")


def validate(run_root: Path, *, repo_root: Path, require_metrics: bool) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 6 outputs: {', '.join(missing)}")
    manifest = _json(run_root / "manifest.json")
    if manifest.get("phase") != 6 or manifest.get("dataset", {}).get("id") != "D_extended":
        raise ValueError("not a Phase 6 D_extended run")
    if manifest.get("pattern_version") != PATTERN_VERSION or manifest.get("top_k") != 10:
        raise ValueError("Phase 6 pattern/top-k contract mismatch")
    development = {
        row["project_id"] for row in read_csv(repo_root / "data/processed/splits/development.csv")
    }
    locked = {
        row["project_id"] for row in read_csv(repo_root / "data/processed/splits/test_locked.csv")
    }
    selected = {str(item) for item in manifest.get("selected_project_ids", [])}
    if not selected or not selected <= development or selected & locked:
        raise ValueError("Phase 6 selection is not development-only")
    if manifest.get("mode") == "full" and selected != development:
        raise ValueError("full Phase 6 run does not cover the complete development split")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    if len({row.get("project_id") for row in statuses}) != len(statuses):
        raise ValueError("Phase 6 status project IDs are duplicated")
    if {str(row.get("project_id")) for row in statuses} != selected:
        raise ValueError("Phase 6 status coverage does not match selected projects")
    successes, failures = _selected_outcomes(
        statuses, (run_root / "STATUS").read_text(encoding="utf-8").strip()
    )
    status_by_id = {str(row["project_id"]): str(row["status"]) for row in statuses}
    source_base = repo_root / "data/interim/phase6_project_sources"
    hypotheses = read_jsonl(run_root / "hypotheses.jsonl")
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    hypothesis_ids: set[str] = set()
    for item in hypotheses:
        project_id = str(item.get("project_id"))
        if project_id not in selected:
            raise ValueError("Phase 6 hypothesis belongs to a non-selected project")
        hypothesis_id = str(item.get("hypothesis_id"))
        if hypothesis_id in hypothesis_ids:
            raise ValueError("Phase 6 hypothesis IDs are duplicated")
        hypothesis_ids.add(hypothesis_id)
        cwes = item.get("candidate_cwe")
        if (
            not isinstance(cwes, list)
            or not cwes
            or any(not isinstance(cwe, str) or not CWE_PATTERN.fullmatch(cwe) for cwe in cwes)
        ):
            raise ValueError("Phase 6 candidate_cwe must be a non-empty canonical list")
        score = item.get("score")
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 1:
            raise ValueError("Phase 6 hypothesis score is outside [0,1]")
        locations = item.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ValueError("Phase 6 hypothesis has no grounded location")
        for location in locations:
            _validate_location(location, source_base / project_id)
        provenance = item.get("provenance")
        if not isinstance(provenance, list) or not provenance:
            raise ValueError("Phase 6 hypothesis has no provenance")
        by_project[project_id].append(item)
    for project_id, items in by_project.items():
        ranks = sorted(int(item.get("rank", 0)) for item in items)
        if ranks != list(range(1, len(items) + 1)) or len(items) > 10:
            raise ValueError(f"Phase 6 ranks are invalid for {project_id}")
        if status_by_id[project_id] != "SUCCESS":
            raise ValueError("Phase 6 analysis failure has emitted hypotheses")
    signals = read_jsonl(run_root / "signals.jsonl")
    candidates = read_jsonl(run_root / "candidates.jsonl")
    if any(str(item.get("project_id")) not in selected for item in [*signals, *candidates]):
        raise ValueError("Phase 6 signal/candidate belongs to a non-selected project")
    if any(item.get("pattern_version") != PATTERN_VERSION for item in signals):
        raise ValueError("Phase 6 signal pattern version mismatch")
    signal_ids = {str(item.get("signal_id")) for item in signals}
    candidate_ids = {str(item.get("hypothesis_id")) for item in candidates}
    if len(signal_ids) != len(signals) or len(candidate_ids) != len(candidates):
        raise ValueError("Phase 6 signal/candidate IDs are duplicated")
    if not hypothesis_ids <= candidate_ids:
        raise ValueError("Phase 6 final hypothesis is absent from the static candidate pool")
    for item in hypotheses:
        referenced = {
            str(entry.get("signal_id"))
            for entry in item["provenance"]
            if isinstance(entry, Mapping) and entry.get("kind") == "source_signal"
        }
        if not referenced or not referenced <= signal_ids:
            raise ValueError("Phase 6 hypothesis provenance does not resolve to source signals")
    candidates_by_project: dict[str, int] = defaultdict(int)
    for item in candidates:
        candidates_by_project[str(item["project_id"])] += 1
    if any(count > 40 for count in candidates_by_project.values()):
        raise ValueError("Phase 6 static candidate cap was exceeded")
    calls = read_jsonl(run_root / "llm_calls.jsonl")
    llm = manifest.get("model")
    if manifest.get("generator") == "hybrid":
        if not isinstance(llm, Mapping) or llm.get("provider_route") != "akashml":
            raise ValueError("Phase 6 hybrid provider provenance is missing")
        successful_calls = [row for row in calls if row.get("status") == "SUCCESS"]
        if any(row.get("provider_route") != "akashml" for row in successful_calls):
            raise ValueError("Phase 6 hybrid call escaped the AkashML route")
    elif calls:
        raise ValueError("Phase 6 static run contains LLM call records")
    with (run_root / "resource_usage.csv").open(encoding="utf-8", newline="") as handle:
        resources = list(csv.DictReader(handle))
    if {row["project_id"] for row in resources} != selected:
        raise ValueError("Phase 6 resource coverage does not match selected projects")
    for row in resources:
        if int(row["calls"]) > 1 or int(row["input_tokens"]) > 8192:
            raise ValueError(f"Phase 6 LLM budget exceeded for {row['project_id']}")
        if manifest.get("generator") == "static" and (
            int(row["calls"]) != 0 or int(row["retries"]) != 0
        ):
            raise ValueError("Phase 6 static resource row contains LLM usage")
    if require_metrics:
        _verify_metrics(run_root, statuses, successes)
    _verify_checksums(run_root)
    if failures:
        return (
            f"PASS_WITH_ANALYSIS_FAILURES: Phase 6 {manifest['generator']} "
            f"({successes}/{len(statuses)} successful; {failures} miss(es))"
        )
    return f"PASS: Phase 6 {manifest['generator']} ({len(statuses)} development projects)"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--require-metrics", action="store_true")
    args = parser.parse_args(argv)
    print(
        validate(
            args.run_root.resolve(),
            repo_root=args.repo_root.resolve(),
            require_metrics=args.require_metrics,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
