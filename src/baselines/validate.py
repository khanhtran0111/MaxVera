"""Validate Phase 5 run structure, budgets, provenance, and checksums."""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.provenance import sha256_file
from src.reproduction.common import FINAL_STATUSES, read_jsonl

REQUIRED_ANALYSIS_FILES = {
    "STATUS",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "environment.json",
    "findings.jsonl",
    "findings.sarif",
    "hypotheses.jsonl",
    "llm_calls.jsonl",
    "manifest.json",
    "project_status.jsonl",
    "resource_usage.csv",
    "specifications.jsonl",
    "stderr.log",
    "stdout.log",
    "timings.jsonl",
}


def _provider_slug(value: object) -> str:
    return "".join(character for character in str(value).casefold() if character.isalnum())


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
    missing = actual - indexed
    if missing:
        raise ValueError(f"unindexed run output: {sorted(missing)[:5]}")


def _selected_outcomes(
    statuses: Sequence[Mapping[str, Any]], selected: set[str], run_status: str
) -> tuple[int, int]:
    if run_status not in {"SUCCESS", "FAILED"}:
        raise ValueError(f"run STATUS is not final: {run_status or '<empty>'}")
    if not selected:
        raise ValueError("manifest selected-project coverage is empty")
    status_by_id = {str(row.get("project_id")): row.get("status") for row in statuses}
    missing = selected - set(status_by_id)
    if missing:
        raise ValueError(f"selected project status coverage is incomplete: {sorted(missing)[:5]}")
    successes = sum(status_by_id[project_id] == "SUCCESS" for project_id in selected)
    failures = len(selected) - successes
    if run_status == "SUCCESS" and failures:
        raise ValueError("run STATUS is SUCCESS but selected project failures exist")
    if run_status == "FAILED" and not failures:
        raise ValueError("run STATUS is FAILED but every selected project is successful")
    return successes, failures


def _verify_failure_policy(run_root: Path, selected_failures: int) -> None:
    if not selected_failures:
        return
    resolved = yaml.safe_load((run_root / "config.resolved.yaml").read_text(encoding="utf-8"))
    try:
        count_as_miss = resolved["experiment"]["evaluation"]["failures_count_as_miss"]
    except (KeyError, TypeError) as error:
        raise ValueError("resolved failure-accounting policy is missing") from error
    if count_as_miss is not True:
        raise ValueError("selected failures are only valid when failures_count_as_miss is true")


def _verify_metrics(
    run_root: Path,
    statuses: Sequence[Mapping[str, Any]],
    analysis_successes: int,
) -> None:
    for name in ("metrics_project.jsonl", "metrics_aggregate.json"):
        if not (run_root / name).is_file():
            raise ValueError(f"missing evaluator output: {name}")
    metrics = read_jsonl(run_root / "metrics_project.jsonl")
    if len(metrics) != len(statuses):
        raise ValueError("metric coverage does not match status coverage")
    status_by_id = {str(row.get("project_id")): row.get("status") for row in statuses}
    metric_by_id = {str(row.get("project_id")): row for row in metrics}
    if len(metric_by_id) != len(metrics) or set(metric_by_id) != set(status_by_id):
        raise ValueError("metric project IDs do not match status coverage")
    if any(
        metric_by_id[project_id].get("status") != status
        for project_id, status in status_by_id.items()
    ):
        raise ValueError("metric statuses do not match project statuses")
    failed_metrics = [
        metric_by_id[project_id]
        for project_id, status in status_by_id.items()
        if status != "SUCCESS"
    ]
    if any(row.get("detected") or int(row.get("alerts", 0)) for row in failed_metrics):
        raise ValueError("non-successful projects were not evaluated as misses")
    aggregate = _json(run_root / "metrics_aggregate.json")
    if int(aggregate.get("projects", -1)) != len(statuses):
        raise ValueError("aggregate project coverage does not match status coverage")
    if int(aggregate.get("analysis_successes", -1)) != analysis_successes:
        raise ValueError("aggregate analysis-success count does not match project statuses")


def validate(run_root: Path, *, require_metrics: bool) -> str:
    missing = sorted(name for name in REQUIRED_ANALYSIS_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing required outputs: {', '.join(missing)}")
    run_status = (run_root / "STATUS").read_text(encoding="utf-8").strip()
    manifest = _json(run_root / "manifest.json")
    if manifest.get("phase") != 5 or manifest.get("baseline_id") not in {"B3", "B4", "B5"}:
        raise ValueError("not a Phase 5 B3-B5 run")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    selected = {str(project_id) for project_id in manifest.get("selected_project_ids", [])}
    if not statuses or len({row.get("project_id") for row in statuses}) != len(statuses):
        raise ValueError("project status coverage is empty or duplicated")
    invalid = [row for row in statuses if row.get("status") not in FINAL_STATUSES]
    if invalid:
        raise ValueError("project statuses contain non-final values")
    selected_successes, selected_failures = _selected_outcomes(statuses, selected, run_status)
    _verify_failure_policy(run_root, selected_failures)
    findings = read_jsonl(run_root / "findings.jsonl")
    if any(item.get("project_id") not in selected for item in findings):
        raise ValueError("finding belongs to a non-selected project")
    budget = manifest.get("budget", {})
    if not isinstance(budget, Mapping):
        raise ValueError("manifest budget is missing")
    with (run_root / "resource_usage.csv").open(encoding="utf-8", newline="") as handle:
        resources = list(csv.DictReader(handle))
    if len(resources) != len(selected):
        raise ValueError("resource usage does not cover every selected project")
    for row in resources:
        if int(row["calls"]) > int(budget["max_calls_per_project"]):
            raise ValueError(f"call budget exceeded for {row['project_id']}")
        if int(row["input_tokens"]) > int(budget["max_total_input_tokens_per_project"]):
            raise ValueError(f"input budget exceeded for {row['project_id']}")
    if manifest["baseline_id"] in {"B3", "B4"}:
        model = manifest.get("model", {})
        if not isinstance(model, Mapping) or model.get("requested_model") != "openai/gpt-oss-20b":
            raise ValueError("canonical model provenance is missing")
        if model.get("returned_models") != ["openai/gpt-oss-20b"]:
            raise ValueError("returned model is absent or inconsistent")
        if model.get("provider_route") != "akashml":
            raise ValueError("Phase 5 provider route must be akashml")
        if model.get("routing", {}).get("allow_fallbacks") is not False:
            raise ValueError("fallback prohibition is missing")
        calls = read_jsonl(run_root / "llm_calls.jsonl")
        successful_calls = [row for row in calls if row.get("status") == "SUCCESS"]
        if not successful_calls or any(
            row.get("provider_route") != "akashml" for row in successful_calls
        ):
            raise ValueError("successful calls do not prove the akashml route")
        if any(_provider_slug(row.get("provider")) != "akashml" for row in successful_calls):
            raise ValueError("OpenRouter returned a provider other than AkashML")
    if require_metrics:
        _verify_metrics(
            run_root,
            statuses,
            sum(row.get("status") == "SUCCESS" for row in statuses),
        )
    _verify_checksums(run_root)
    if selected_failures:
        return (
            f"PASS_WITH_ANALYSIS_FAILURES: {manifest['baseline_id']} "
            f"({selected_successes}/{len(selected)} successful; "
            f"{selected_failures} failure(s) counted as misses)"
        )
    return f"PASS: {manifest['baseline_id']} ({len(selected)} selected projects)"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--require-metrics", action="store_true")
    args = parser.parse_args(argv)
    print(validate(args.run_root.resolve(), require_metrics=args.require_metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
