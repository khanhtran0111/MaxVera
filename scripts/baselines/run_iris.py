#!/usr/bin/env python3
"""Run one pinned upstream IRIS v1 reference configuration."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from openiris.config import load_yaml
from openiris.experiments import BaselineRecord, BaselineStatus, RunRegistry, RunStatus
from openiris.iris import IrisRunner


def _default_run_id(experiment_id: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{experiment_id}"


def _load_resolved(config_path: Path) -> dict[str, Any]:
    experiment = load_yaml(config_path)
    workspace = Path.cwd()
    dataset = load_yaml(workspace / str(experiment["dataset_config"]))
    toolchain = load_yaml(workspace / str(experiment["toolchain_config"]))
    model = load_yaml(workspace / str(experiment["model_config"]))
    return {
        "experiment": experiment,
        "dataset": dataset,
        "toolchain": toolchain,
        "model": model,
    }


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
    model = resolved["model"]
    projects = list(experiment.get("projects", []))
    if not projects:
        raise ValueError("IRIS reference requires at least one project")
    selected_run_id = run_id or _default_run_id(str(experiment["experiment_id"]))
    registry = RunRegistry(runs_root)
    run = registry.create_run(
        selected_run_id,
        resolved,
        dataset=dataset,
        toolchain=toolchain,
        model=model,
        metadata={"baseline": "iris", "experiment_id": experiment["experiment_id"]},
    )
    runner = IrisRunner(
        toolchain["iris"]["source_path"],
        python_executable=python_executable,
        timeout_seconds=float(experiment["timeout_seconds"]),
    )
    records: list[BaselineRecord] = []
    schema_path = Path.cwd() / "schemas" / "baseline_record.schema.json"
    query = str(experiment["query"])
    model_name = str(model["iris_model_name"])
    seed = int(model["seed"])

    for project in projects:
        project_name = str(project)
        command_dir = run.reserve_directory(Path("commands") / project_name)
        try:
            record = runner.run(
                run_id=selected_run_id,
                project=project_name,
                query=query,
                model=model_name,
                seed=seed,
                artifact_dir=command_dir,
                track=str(dataset["track"]),
            )
        except Exception as exc:  # retain preflight/orchestration failures
            record = BaselineRecord(
                run_id=selected_run_id,
                baseline="iris",
                track=str(dataset["track"]),
                project=project_name,
                query=query,
                status=BaselineStatus.FAILED,
                runtime_seconds=0.0,
                error=f"{type(exc).__name__}: {exc}",
                metadata={"model": model_name, "seed": seed},
            )
        _validate_record(record, schema_path)
        run.append_jsonl("baseline.jsonl", record.to_dict())
        run.append_usage(
            {
                "purpose": "iris_reference",
                "model": model_name,
                "project": project_name,
                "latency_ms": record.runtime_seconds * 1000,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "estimated_cost_usd": 0.0,
                "note": "token/cost details remain in retained upstream IRIS artifacts",
            }
        )
        if record.status is not BaselineStatus.COMPLETE:
            run.append_error(
                code=record.status.value,
                message=record.error or "IRIS reference failed",
                stage="iris_reference",
                details={"project": project_name, "query": record.query},
            )
        records.append(record)

    complete = sum(record.status is BaselineStatus.COMPLETE for record in records)
    timed_out = sum(record.status is BaselineStatus.TIMEOUT for record in records)
    failed = len(records) - complete - timed_out
    final_status = (
        RunStatus.TIMEOUT if timed_out else RunStatus.FAILED if failed else RunStatus.COMPLETE
    )
    run.finalize(
        final_status,
        metrics={
            "projects_total": len(records),
            "projects_complete": complete,
            "projects_failed": failed,
            "projects_timeout": timed_out,
            "detected": sum(record.vulnerability_detected is True for record in records),
            "total_paths": sum(record.number_of_paths or 0 for record in records),
            "runtime_seconds": sum(record.runtime_seconds for record in records),
        },
    )

    result_path = Path(results_root).resolve() / "iris" / f"{selected_run_id}.jsonl"
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
