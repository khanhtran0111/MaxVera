#!/usr/bin/env python3
"""Run the Phase 0 local Qwen IRIS smoke in the pinned Docker runtime."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from openiris.config import load_yaml
from openiris.experiments import BaselineRecord, BaselineStatus, RunRegistry, RunStatus
from openiris.iris.docker import (
    LEAKAGE_EXCEPTION,
    DockerIrisRunner,
    create_evaluator_bundle,
    load_ground_truth_record,
    select_runtime_instance,
)
from openiris.utils.hashing import sha256_file

_QUERY = re.compile(r"^cwe-(?P<cwe>\d{3})wLLM$")
_LOCAL_SMOKE_MODEL = "qwen2.5-coder-1.5b"


def _default_run_id(experiment_id: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{experiment_id}"


def _workspace_path(workspace: Path, value: str | Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (workspace / path).resolve()


def _load_resolved(config_path: Path, workspace: Path) -> dict[str, Any]:
    experiment = load_yaml(config_path)
    dataset = load_yaml(_workspace_path(workspace, str(experiment["dataset_config"])))
    toolchain = load_yaml(_workspace_path(workspace, str(experiment["toolchain_config"])))
    model = load_yaml(_workspace_path(workspace, str(experiment["model_config"])))
    return {
        "experiment": experiment,
        "dataset": dataset,
        "toolchain": toolchain,
        "model": model,
    }


def _truth_cwe(value: Any) -> str:
    match = re.fullmatch(r"CWE-(\d+)", str(value), re.IGNORECASE)
    if match is None:
        raise ValueError(f"invalid evaluator CWE: {value!r}")
    return f"CWE-{int(match.group(1)):03d}"


def _validate_record(record: BaselineRecord, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator(schema).validate(record.to_dict())


def _descriptor_hash(database: Path) -> dict[str, str]:
    candidates = sorted(database.rglob("codeql-database.yml"))
    return {str(path.relative_to(database)): sha256_file(path) for path in candidates}


def run_from_config(
    config_path: str | Path,
    *,
    instance_id: str,
    runtime_manifest: str | Path,
    runtime_repository: str | Path,
    ground_truth: str | Path,
    codeql_database: str | Path,
    package_names: str | Path | None = None,
    hf_cache: str | Path = "tools/cache/huggingface",
    image: str = "maxvera-phase0:iris",
    docker_executable: str = "docker",
    run_id: str | None = None,
    runs_root: str | Path = "runs",
    results_root: str | Path = "results/phases/phase_00/baselines",
    label_api_batch_size: int = 30,
    label_func_param_batch_size: int = 20,
    num_threads: int = 1,
) -> Path:
    workspace = Path.cwd().resolve()
    config = Path(config_path).resolve()
    resolved = _load_resolved(config, workspace)
    experiment = resolved["experiment"]
    dataset = resolved["dataset"]
    toolchain = resolved["toolchain"]
    model = resolved["model"]

    runtime_manifest_path = _workspace_path(workspace, runtime_manifest)
    runtime_repository_path = _workspace_path(workspace, runtime_repository)
    ground_truth_path = _workspace_path(workspace, ground_truth)
    database_path = _workspace_path(workspace, codeql_database)
    hf_cache_path = _workspace_path(workspace, hf_cache)
    iris_root = _workspace_path(workspace, str(toolchain["iris"]["source_path"]))
    instance = select_runtime_instance(runtime_manifest_path, instance_id)
    truth = load_ground_truth_record(ground_truth_path, instance_id)
    project_slug = str(truth["project_slug"])

    configured_projects = {str(value) for value in experiment.get("projects", [])}
    if configured_projects and project_slug not in configured_projects:
        raise ValueError(
            "opaque instance resolves to a project outside the trusted experiment allowlist"
        )
    query = str(experiment["query"])
    query_match = _QUERY.fullmatch(query)
    if query_match is None:
        raise ValueError("IRIS query must look like cwe-022wLLM")
    if _truth_cwe(truth["cwe_id"]) != f"CWE-{query_match.group('cwe')}":
        raise ValueError("configured oracle query does not match evaluator CWE")
    model_name = str(model["iris_model_name"])
    model_id = str(model["model_id"])
    model_revision = str(model["revision"])
    if model_name != _LOCAL_SMOKE_MODEL:
        raise ValueError(f"Phase 0 local smoke requires {_LOCAL_SMOKE_MODEL}, found {model_name}")
    if re.fullmatch(r"[0-9a-f]{40}", model_revision) is None:
        raise ValueError("Phase 0 local model revision must be a full immutable commit")

    package_names_path = (
        _workspace_path(workspace, package_names)
        if package_names is not None
        else _workspace_path(workspace, str(dataset["source_path"]))
        / "package-names"
        / f"{project_slug}.txt"
    )
    selected_run_id = run_id or _default_run_id(str(experiment["experiment_id"]))
    result_path = _workspace_path(workspace, results_root) / "iris" / f"{selected_run_id}.jsonl"
    if result_path.exists():
        raise FileExistsError(f"refusing to overwrite baseline result: {result_path}")

    invocation = {
        "runtime_instance_id": instance_id,
        "runtime_manifest": str(runtime_manifest_path),
        "runtime_manifest_sha256": sha256_file(runtime_manifest_path),
        "runtime_repository": str(runtime_repository_path),
        "ground_truth": str(ground_truth_path),
        "ground_truth_sha256": sha256_file(ground_truth_path),
        "package_names": str(package_names_path),
        "package_names_sha256": sha256_file(package_names_path),
        "codeql_database": str(database_path),
        "codeql_database_descriptors": _descriptor_hash(database_path),
        "hf_cache": str(hf_cache_path),
        "docker_image": image,
        "docker_executable": docker_executable,
        "label_api_batch_size": label_api_batch_size,
        "label_func_param_batch_size": label_func_param_batch_size,
        "num_threads": num_threads,
        "skip_posthoc_filter": True,
        "model_id": model_id,
        "model_revision": model_revision,
        "model_revision_enforced_via_offline_cache": True,
        "model_quantization_requested": model.get("quantization_bits"),
        "model_quantization_forwarded_by_upstream": False,
        "temperature_requested": model.get("temperature"),
        "upstream_qwen_effective_temperature": 0.01,
        "upstream_qwen_do_sample": False,
    }
    resolved["runtime_invocation"] = invocation
    registry = RunRegistry(_workspace_path(workspace, runs_root), workspace=workspace)
    run = registry.create_run(
        selected_run_id,
        resolved,
        dataset=dataset,
        toolchain=toolchain,
        model=model,
        environment={
            "execution_mode": "docker-gpu",
            "docker_image": image,
            "gpu_request": "all",
        },
        metadata={
            "baseline": "iris",
            "experiment_id": experiment["experiment_id"],
            "runtime_instance_id": instance_id,
            "analysis_boundary": "opaque runtime source selected by instance_id",
            "leakage_exception": LEAKAGE_EXCEPTION,
        },
    )
    command_dir = run.reserve_directory(Path("commands") / instance_id)
    evaluator_dir = run.artifact_path(Path("inputs") / "evaluator_compatibility")
    retained_output = run.artifact_path(Path("artifacts") / "iris")
    run.write_json(
        "provenance.json",
        {
            "schema_version": 1,
            "invocation": invocation,
            "iris_commit": str(toolchain["iris"]["git_commit"]),
            "dataset_commit": str(dataset["git_commit"]),
            "runtime_revision": instance.revision,
            "upstream_project_slug": project_slug,
            "leakage_exception": LEAKAGE_EXCEPTION,
        },
    )

    record: BaselineRecord
    try:
        evaluator_bundle = create_evaluator_bundle(
            evaluator_dir,
            instance=instance,
            ground_truth=truth,
            package_names_path=package_names_path,
        )
        run.write_json(
            "evaluator_bundle_manifest.json",
            {
                "schema_version": 1,
                "evaluator_bundle_hashes": evaluator_bundle.hashes(),
                "leakage_exception": LEAKAGE_EXCEPTION,
            },
        )
        runner = DockerIrisRunner(
            image=image,
            docker_executable=docker_executable,
            platform=str(toolchain["docker"]["platform"]),
            timeout_seconds=float(experiment["timeout_seconds"]),
        )
        record = runner.run(
            run_id=selected_run_id,
            instance=instance,
            upstream_project_slug=project_slug,
            cve=str(truth["cve_id"]),
            query=query,
            model=model_name,
            model_id=model_id,
            model_revision=model_revision,
            seed=int(model["seed"]),
            iris_root=iris_root,
            iris_commit=str(toolchain["iris"]["git_commit"]),
            runtime_repository=runtime_repository_path,
            codeql_database=database_path,
            evaluator_bundle=evaluator_bundle,
            hf_cache=hf_cache_path,
            artifact_dir=command_dir,
            retained_output_dir=retained_output,
            track=str(dataset["track"]),
            label_api_batch_size=label_api_batch_size,
            label_func_param_batch_size=label_func_param_batch_size,
            num_threads=num_threads,
        )
    except Exception as exc:
        record = BaselineRecord(
            run_id=selected_run_id,
            baseline="iris",
            track=str(dataset["track"]),
            project=instance_id,
            cve=str(truth.get("cve_id")) if truth.get("cve_id") else None,
            cwe=f"CWE-{int(query_match.group('cwe'))}",
            query=query,
            status=BaselineStatus.FAILED,
            runtime_seconds=0.0,
            error=f"{type(exc).__name__}: {exc}",
            metadata={
                "orchestrator": "iris_v1_docker_compatibility",
                "runtime_instance_id": instance_id,
                "upstream_project_slug": project_slug,
                "model": model_name,
                "model_id": model_id,
                "model_revision": model_revision,
                "model_revision_enforced_via_offline_cache": True,
                "seed": int(model["seed"]),
                "skip_posthoc_filter": True,
                "leakage_exception": LEAKAGE_EXCEPTION,
            },
        )

    _validate_record(record, workspace / "schemas" / "baseline_record.schema.json")
    run.append_jsonl("baseline.jsonl", record.to_dict())
    run.append_usage(
        {
            "purpose": "iris_local_qwen_smoke",
            "model": model_name,
            "project": instance_id,
            "latency_ms": record.runtime_seconds * 1000,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "estimated_cost_usd": 0.0,
            "note": "local model; token counts remain in retained upstream artifacts",
        }
    )
    if record.status is not BaselineStatus.COMPLETE:
        run.append_error(
            code=record.status.value,
            message=record.error or "Docker IRIS smoke failed",
            stage="iris_local_qwen_smoke",
            details={"instance_id": instance_id, "query": query},
        )

    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    final_status = {
        BaselineStatus.COMPLETE: RunStatus.COMPLETE,
        BaselineStatus.FAILED: RunStatus.FAILED,
        BaselineStatus.TIMEOUT: RunStatus.TIMEOUT,
    }[record.status]
    run.finalize(
        final_status,
        metrics={
            "projects_total": 1,
            "projects_complete": int(record.status is BaselineStatus.COMPLETE),
            "projects_failed": int(record.status is BaselineStatus.FAILED),
            "projects_timeout": int(record.status is BaselineStatus.TIMEOUT),
            "detected": int(record.vulnerability_detected is True),
            "total_paths": record.number_of_paths or 0,
            "runtime_seconds": record.runtime_seconds,
        },
        summary={
            "runtime_instance_id": instance_id,
            "leakage_exception_id": LEAKAGE_EXCEPTION["id"],
        },
    )
    return run.path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--runtime-manifest", required=True, type=Path)
    parser.add_argument("--runtime-repository", required=True, type=Path)
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--codeql-database", required=True, type=Path)
    parser.add_argument("--package-names", type=Path)
    parser.add_argument("--hf-cache", type=Path, default=Path("tools/cache/huggingface"))
    parser.add_argument("--image", default="maxvera-phase0:iris")
    parser.add_argument("--docker", default="docker", dest="docker_executable")
    parser.add_argument("--run-id")
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument(
        "--results-root", type=Path, default=Path("results/phases/phase_00/baselines")
    )
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument("--num-threads", type=int, default=1)
    args = parser.parse_args()
    path = run_from_config(
        args.config,
        instance_id=args.instance_id,
        runtime_manifest=args.runtime_manifest,
        runtime_repository=args.runtime_repository,
        ground_truth=args.ground_truth,
        codeql_database=args.codeql_database,
        package_names=args.package_names,
        hf_cache=args.hf_cache,
        image=args.image,
        docker_executable=args.docker_executable,
        run_id=args.run_id,
        runs_root=args.runs_root,
        results_root=args.results_root,
        label_api_batch_size=args.label_api_batch_size,
        label_func_param_batch_size=args.label_func_param_batch_size,
        num_threads=args.num_threads,
    )
    print(path)
    manifest = load_yaml(path / "manifest.yaml")
    return 0 if manifest["status"] == RunStatus.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
