#!/usr/bin/env python3
"""Run the pinned IRIS v1 built-in CodeQL baseline with audit artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from openiris.codeql import CodeQLRunner
from openiris.config import load_yaml
from openiris.experiments import BaselineRecord, BaselineStatus, RunRegistry, RunStatus


def _default_run_id(experiment_id: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{experiment_id}"


def _load_resolved(config_path: Path) -> dict[str, Any]:
    experiment = load_yaml(config_path)
    workspace = Path.cwd()
    dataset = load_yaml(workspace / str(experiment["dataset_config"]))
    toolchain = load_yaml(workspace / str(experiment["toolchain_config"]))
    codeql_path = workspace / "configs" / "codeql" / f"{dataset['track']}.yaml"
    codeql = load_yaml(codeql_path)
    return {
        "experiment": experiment,
        "dataset": dataset,
        "toolchain": toolchain,
        "codeql": codeql,
    }


def _project_truth(dataset: dict[str, Any]) -> dict[str, tuple[str, str]]:
    source = Path(str(dataset["source_path"]))
    metadata = source / "data" / "project_info.csv"
    values: dict[str, tuple[str, str]] = {}
    with metadata.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            values[str(row["project_slug"])] = (str(row["cve_id"]), str(row["cwe_id"]))
    return values


def _validate_record(record: BaselineRecord, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator(schema).validate(record.to_dict())


def run_from_config(
    config_path: str | Path,
    *,
    run_id: str | None = None,
    runs_root: str | Path = "runs",
    results_root: str | Path = "results/phases/phase_00/baselines",
    python_executable: str = sys.executable,
) -> Path:
    resolved = _load_resolved(Path(config_path).resolve())
    experiment = resolved["experiment"]
    dataset = resolved["dataset"]
    toolchain = resolved["toolchain"]
    codeql = resolved["codeql"]
    projects = list(experiment.get("projects", []))
    if not projects:
        raise ValueError("CodeQL baseline requires at least one project")
    selected_run_id = run_id or _default_run_id(str(experiment["experiment_id"]))
    registry = RunRegistry(runs_root)
    run = registry.create_run(
        selected_run_id,
        resolved,
        dataset=dataset,
        toolchain=toolchain,
        metadata={"baseline": "codeql", "experiment_id": experiment["experiment_id"]},
    )
    runner = CodeQLRunner(
        toolchain.get("codeql", {}).get("executable", "codeql"),
        timeout_seconds=float(experiment.get("timeout_seconds", codeql["timeout_seconds"])),
    )
    truth = _project_truth(dataset)
    query_by_cwe = dict(codeql["query_by_cwe"])
    records: list[BaselineRecord] = []
    schema_path = Path.cwd() / "schemas" / "baseline_record.schema.json"

    for project in projects:
        project_name = str(project)
        command_dir = run.reserve_directory(Path("commands") / project_name)
        cve, cwe = truth.get(project_name, ("", ""))
        query = str(query_by_cwe.get(cwe, ""))
        try:
            if not query:
                raise ValueError(f"no built-in CodeQL query configured for {project_name} ({cwe})")
            record = runner.run_pinned_iris_baseline(
                run_id=selected_run_id,
                project=project_name,
                query=query,
                iris_root=toolchain["iris"]["source_path"],
                artifact_dir=command_dir,
                track=str(dataset["track"]),
                python_executable=python_executable,
            )
        except Exception as exc:  # keep a per-project auditable failure
            record = BaselineRecord(
                run_id=selected_run_id,
                baseline="codeql",
                track=str(dataset["track"]),
                project=project_name,
                cve=cve or None,
                cwe=cwe or None,
                query=query or "unresolved",
                status=BaselineStatus.FAILED,
                runtime_seconds=0.0,
                error=f"{type(exc).__name__}: {exc}",
            )
        _validate_record(record, schema_path)
        run.append_jsonl("baseline.jsonl", record.to_dict())
        run.append_usage(
            {
                "purpose": "codeql_baseline",
                "project": project_name,
                "latency_ms": record.runtime_seconds * 1000,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "estimated_cost_usd": 0.0,
            }
        )
        if record.status is not BaselineStatus.COMPLETE:
            run.append_error(
                code=record.status.value,
                message=record.error or "CodeQL baseline failed",
                stage="codeql_baseline",
                details={"project": project_name, "query": record.query},
            )
        records.append(record)

    complete = sum(record.status is BaselineStatus.COMPLETE for record in records)
    timed_out = sum(record.status is BaselineStatus.TIMEOUT for record in records)
    failed = len(records) - complete - timed_out
    final_status = (
        RunStatus.TIMEOUT if timed_out else RunStatus.FAILED if failed else RunStatus.COMPLETE
    )
    metrics = {
        "projects_total": len(records),
        "projects_complete": complete,
        "projects_failed": failed,
        "projects_timeout": timed_out,
        "detected": sum(record.vulnerability_detected is True for record in records),
        "total_paths": sum(record.number_of_paths or 0 for record in records),
        "runtime_seconds": sum(record.runtime_seconds for record in records),
    }
    run.finalize(final_status, metrics=metrics)

    result_path = Path(results_root).resolve() / "codeql" / f"{selected_run_id}.jsonl"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("x", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    return run.path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument(
        "--results-root", type=Path, default=Path("results/phases/phase_00/baselines")
    )
    parser.add_argument("--python", default=sys.executable, dest="python_executable")
    args = parser.parse_args()
    path = run_from_config(
        args.config,
        run_id=args.run_id,
        runs_root=args.runs_root,
        results_root=args.results_root,
        python_executable=args.python_executable,
    )
    print(path)
    manifest = load_yaml(path / "manifest.yaml")
    return 0 if manifest["status"] == RunStatus.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
