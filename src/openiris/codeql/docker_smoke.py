"""Auditable Docker execution of the pinned Phase 0 CodeQL smoke baseline."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from openiris.config import load_yaml
from openiris.data import audit_runtime_repository, read_runtime_manifest
from openiris.evaluation import SarifEvaluator
from openiris.experiments import (
    BaselineRecord,
    BaselineStatus,
    ProcessExecutor,
    ProcessResult,
    ProcessStatus,
    RunHandle,
    RunRegistry,
    RunStatus,
)

_CONTAINER_WORKSPACE = "/workspace"
_CONTAINER_SOURCE = f"{_CONTAINER_WORKSPACE}/source"
_CONTAINER_DATABASE = f"{_CONTAINER_WORKSPACE}/database"
_CONTAINER_OUTPUT = f"{_CONTAINER_WORKSPACE}/output"
_CONTAINER_IRIS = "/opt/iris"
_CONTAINER_GRADLE_CACHE = "/root/.gradle"
_CONTAINER_BUILD_HELPER = "/opt/maxvera/codeql_gradle_build.sh"
_CONTAINER_CODEQL = "/opt/codeql/codeql"
_COPY_AND_RUN_LOCATION_QUERY = """\
set -euo pipefail
mkdir -p "$1"
cp "$2" "$1/$3"
exec "$4" query run "--database=$5" "--output=$6" -- "$1/$3"
"""


def _timestamped_run_id(experiment_id: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{experiment_id}"


def _absolute(workspace: Path, value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    return (workspace / path).resolve() if not path.is_absolute() else path.resolve()


def _cwe_number(cwe: str) -> int:
    prefix, separator, number = cwe.upper().partition("-")
    if prefix != "CWE" or separator != "-" or not number.isdigit():
        raise ValueError(f"invalid CWE identifier: {cwe!r}")
    return int(number)


def _query_name(cwe: str) -> str:
    return f"cwe-{_cwe_number(cwe):03d}wCodeQL"


def _query_directory(cwe: str, query_pack_version: str) -> str:
    padded = f"{_cwe_number(cwe):03d}"
    return (
        f"/opt/codeql/qlpacks/codeql/java-queries/{query_pack_version}/Security/CWE/CWE-{padded}/"
    )


def _mount(source: Path, target: str, *, read_only: bool = False) -> str:
    option = f"type=bind,source={source.resolve()},target={target}"
    return f"{option},readonly" if read_only else option


def _tree_sha256(root: Path) -> tuple[str, int]:
    """Hash relative names and bytes of a reusable CodeQL database."""

    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        with path.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest(), len(files)


def _ground_truth_record(path: Path, project_slug: str) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        matches = [
            value
            for line in handle
            if line.strip()
            if isinstance((value := json.loads(line)), dict)
            and value.get("project_slug") == project_slug
        ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one evaluator-only ground-truth record for {project_slug!r}, "
            f"found {len(matches)}"
        )
    return matches[0]


def _validate_baseline_record(record: BaselineRecord, schema_path: Path) -> None:
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator(schema).validate(record.to_dict())


@dataclass(frozen=True, slots=True)
class DockerSmokeOutcome:
    """Completed local smoke result plus IRIS-compatible evaluation metrics."""

    record: BaselineRecord
    evaluation: dict[str, int | bool]
    database: Path


class DockerStageError(RuntimeError):
    """One retained Docker command failed or timed out."""

    def __init__(self, stage: str, result: ProcessResult) -> None:
        self.stage = stage
        self.result = result
        detail = result.error or f"exit code {result.exit_code}"
        super().__init__(f"Docker CodeQL stage {stage!r} failed: {detail}")


class DockerCodeQLSmokeRunner:
    """Run the pinned Java query and evaluator without exposing ground truth to analysis."""

    def __init__(
        self,
        *,
        image: str = "maxvera-phase0:codeql",
        platform: str = "linux/amd64",
        docker_executable: str = "docker",
        codeql_executable: str = _CONTAINER_CODEQL,
        timeout_seconds: float = 3600,
        executor: ProcessExecutor | None = None,
    ) -> None:
        if not image.strip():
            raise ValueError("Docker image cannot be empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout must be greater than zero")
        self.image = image
        self.platform = platform
        self.docker_executable = docker_executable
        self.codeql_executable = codeql_executable
        self.timeout_seconds = timeout_seconds
        self.executor = executor or ProcessExecutor(timeout_seconds)

    def _docker_argv(
        self,
        *,
        workspace: Path,
        gradle_cache: Path,
        iris_root: Path,
        build_helper: Path,
        command: Sequence[str],
    ) -> list[str]:
        return [
            self.docker_executable,
            "run",
            "--rm",
            "--platform",
            self.platform,
            "--mount",
            _mount(workspace, _CONTAINER_WORKSPACE),
            "--mount",
            _mount(gradle_cache, _CONTAINER_GRADLE_CACHE),
            "--mount",
            _mount(iris_root, _CONTAINER_IRIS, read_only=True),
            "--mount",
            _mount(build_helper, _CONTAINER_BUILD_HELPER, read_only=True),
            "--workdir",
            _CONTAINER_SOURCE,
            self.image,
            *command,
        ]

    def _run_stage(
        self,
        run: RunHandle,
        stage: str,
        argv: Sequence[str],
        *,
        cwd: Path,
    ) -> ProcessResult:
        artifact_dir = run.reserve_directory(Path("commands") / stage)
        result = self.executor.run(
            list(argv),
            artifact_dir=artifact_dir,
            cwd=cwd,
            timeout_seconds=self.timeout_seconds,
        )
        if not result.succeeded:
            raise DockerStageError(stage, result)
        return result

    def run(
        self,
        *,
        run: RunHandle,
        runtime_repository: str | Path,
        instance_id: str,
        snapshot_id: str,
        project_slug: str,
        cve: str,
        cwe: str,
        track: str,
        iris_root: str | Path,
        ground_truth_csv: str | Path,
        gradle_cache: str | Path,
        build_helper: str | Path,
        query_pack_version: str = "0.8.3",
        reuse_database: str | Path | None = None,
    ) -> DockerSmokeOutcome:
        started = time.monotonic()
        source_runtime = Path(runtime_repository).resolve()
        iris = Path(iris_root).resolve()
        truth = Path(ground_truth_csv).resolve()
        cache = Path(gradle_cache).resolve()
        helper = Path(build_helper).resolve()
        if source_runtime.parent.name != instance_id or source_runtime.name != "repository":
            raise ValueError("runtime repository must be <snapshot>/<opaque-id>/repository")
        if not iris.is_dir():
            raise NotADirectoryError(iris)
        if not truth.is_file():
            raise FileNotFoundError(truth)
        if not helper.is_file():
            raise FileNotFoundError(helper)
        for query in ("fetch_class_locs.ql", "fetch_func_locs.ql"):
            path = iris / "src" / "queries" / query
            if not path.is_file():
                raise FileNotFoundError(path)
        audit_runtime_repository(source_runtime)
        cache.mkdir(parents=True, exist_ok=True)

        run_workspace = run.reserve_directory("workspace")
        source = run_workspace / "source"
        shutil.copytree(source_runtime, source)
        audit_runtime_repository(source)
        database = run_workspace / "database"
        output = run_workspace / "output"
        output.mkdir()
        provenance: dict[str, Any]
        command_records: list[str] = []
        processes: list[ProcessResult] = []

        if reuse_database is not None:
            reusable = Path(reuse_database).resolve()
            if not (reusable / "db-java").is_dir():
                raise ValueError(f"reusable database must contain db-java/: {reusable}")
            source_hash, source_files = _tree_sha256(reusable)
            shutil.copytree(reusable, database)
            provenance = {
                "mode": "reused_copy",
                "source_path": str(reusable),
                "source_sha256": source_hash,
                "source_file_count": source_files,
            }
        else:
            provenance = {"mode": "created_in_run", "source_path": None, "source_sha256": None}
            argv = self._docker_argv(
                workspace=run_workspace,
                gradle_cache=cache,
                iris_root=iris,
                build_helper=helper,
                command=[
                    self.codeql_executable,
                    "database",
                    "create",
                    _CONTAINER_DATABASE,
                    "--language=java",
                    f"--source-root={_CONTAINER_SOURCE}",
                    f"--command=bash {_CONTAINER_BUILD_HELPER}",
                ],
            )
            process = self._run_stage(run, "database_create", argv, cwd=run_workspace)
            processes.append(process)
            command_records.append(process.record_path)
            if not (database / "db-java").is_dir():
                raise RuntimeError("CodeQL exited successfully without creating database/db-java")

        query_name = _query_name(cwe)
        builtin_query = _query_directory(cwe, query_pack_version)
        outputs = {
            "sarif": output / "results.sarif",
            "csv": output / "results.csv",
            "class_bqrs": output / "fetch_class_locs.bqrs",
            "class_csv": output / "fetch_class_locs.csv",
            "func_bqrs": output / "fetch_func_locs.bqrs",
            "func_csv": output / "fetch_func_locs.csv",
        }
        stages: list[tuple[str, list[str], Path]] = [
            (
                "builtin_sarif",
                [
                    self.codeql_executable,
                    "database",
                    "analyze",
                    _CONTAINER_DATABASE,
                    builtin_query,
                    "--format=sarifv2.1.0",
                    f"--output={_CONTAINER_OUTPUT}/results.sarif",
                ],
                outputs["sarif"],
            ),
            (
                "builtin_csv",
                [
                    self.codeql_executable,
                    "database",
                    "analyze",
                    "--rerun",
                    _CONTAINER_DATABASE,
                    builtin_query,
                    "--format=csv",
                    f"--output={_CONTAINER_OUTPUT}/results.csv",
                ],
                outputs["csv"],
            ),
        ]
        for stage, command, expected in stages:
            argv = self._docker_argv(
                workspace=run_workspace,
                gradle_cache=cache,
                iris_root=iris,
                build_helper=helper,
                command=command,
            )
            process = self._run_stage(run, stage, argv, cwd=run_workspace)
            processes.append(process)
            command_records.append(process.record_path)
            if not expected.is_file():
                raise RuntimeError(f"{stage} did not produce {expected}")

        location_queries = (
            ("class", "fetch_class_locs.ql"),
            ("func", "fetch_func_locs.ql"),
        )
        writable_query_directory = (
            f"/opt/codeql/qlpacks/codeql/java-queries/{query_pack_version}/myqueries/maxvera_phase0"
        )
        for short_name, filename in location_queries:
            bqrs = outputs[f"{short_name}_bqrs"]
            csv_output = outputs[f"{short_name}_csv"]
            run_command = [
                "bash",
                "-lc",
                _COPY_AND_RUN_LOCATION_QUERY,
                "maxvera-location-query",
                writable_query_directory,
                f"{_CONTAINER_IRIS}/src/queries/{filename}",
                filename,
                self.codeql_executable,
                _CONTAINER_DATABASE,
                f"{_CONTAINER_OUTPUT}/{bqrs.name}",
            ]
            argv = self._docker_argv(
                workspace=run_workspace,
                gradle_cache=cache,
                iris_root=iris,
                build_helper=helper,
                command=run_command,
            )
            process = self._run_stage(run, f"fetch_{short_name}_locations", argv, cwd=run_workspace)
            processes.append(process)
            command_records.append(process.record_path)
            if not bqrs.is_file():
                raise RuntimeError(f"location query did not produce {bqrs}")

            decode_command = [
                self.codeql_executable,
                "bqrs",
                "decode",
                f"{_CONTAINER_OUTPUT}/{bqrs.name}",
                "--format=csv",
                f"--output={_CONTAINER_OUTPUT}/{csv_output.name}",
            ]
            argv = self._docker_argv(
                workspace=run_workspace,
                gradle_cache=cache,
                iris_root=iris,
                build_helper=helper,
                command=decode_command,
            )
            process = self._run_stage(
                run, f"decode_{short_name}_locations", argv, cwd=run_workspace
            )
            processes.append(process)
            command_records.append(process.record_path)
            if not csv_output.is_file():
                raise RuntimeError(f"BQRS decode did not produce {csv_output}")

        evaluator = SarifEvaluator.from_files(
            truth,
            outputs["class_csv"],
            outputs["func_csv"],
            project_slug=project_slug,
            cve_id=cve,
            repository_root=_CONTAINER_SOURCE,
        )
        evaluation = evaluator.evaluate_path(outputs["sarif"]).to_dict()
        evaluation_path = run.write_json("evaluation.json", evaluation)
        artifacts = tuple(
            str(path)
            for path in (
                outputs["sarif"],
                outputs["csv"],
                outputs["class_bqrs"],
                outputs["class_csv"],
                outputs["func_bqrs"],
                outputs["func_csv"],
                evaluation_path,
            )
        )
        record = BaselineRecord(
            run_id=run.run_id,
            baseline="codeql",
            track=track,
            project=project_slug,
            cve=cve,
            cwe=f"CWE-{_cwe_number(cwe)}",
            query=query_name,
            status=BaselineStatus.COMPLETE,
            runtime_seconds=time.monotonic() - started,
            number_of_paths=int(evaluation["num_paths"]),
            vulnerability_detected=bool(evaluation["recall_method"]),
            exit_code=processes[-1].exit_code if processes else 0,
            command_record=command_records[-1] if command_records else None,
            output_artifacts=artifacts,
            metadata={
                "orchestrator": "maxvera_docker_codeql_smoke",
                "docker_image": self.image,
                "docker_platform": self.platform,
                "instance_id": instance_id,
                "snapshot_id": snapshot_id,
                "query_directory": builtin_query,
                "command_records": command_records,
                "evaluation": evaluation,
                "database_provenance": provenance,
                "runtime_source_copied": True,
            },
        )
        return DockerSmokeOutcome(record=record, evaluation=evaluation, database=database)


def run_from_config(
    config_path: str | Path,
    *,
    run_id: str | None = None,
    runs_root: str | Path = "runs",
    results_root: str | Path = "results/phases/phase_00/baselines",
    runtime_root: str | Path = "data/runtime_views",
    gradle_cache: str | Path = "artifacts/caches/gradle",
    image: str = "maxvera-phase0:codeql",
    docker_executable: str = "docker",
    reuse_database: str | Path | None = None,
    workspace: str | Path | None = None,
    executor: ProcessExecutor | None = None,
) -> Path:
    """Resolve Phase 0 config, run one opaque instance, and finalize its registry."""

    root = Path(workspace or Path.cwd()).resolve()
    experiment_path = _absolute(root, config_path)
    experiment = load_yaml(experiment_path)
    dataset = load_yaml(_absolute(root, str(experiment["dataset_config"])))
    toolchain = load_yaml(_absolute(root, str(experiment["toolchain_config"])))
    codeql = load_yaml(root / "configs" / "codeql" / f"{dataset['track']}.yaml")
    resolved = {
        "experiment": experiment,
        "dataset": dataset,
        "toolchain": toolchain,
        "codeql": codeql,
        "docker_smoke": {
            "image": image,
            "runtime_root": str(_absolute(root, runtime_root)),
            "gradle_cache": str(_absolute(root, gradle_cache)),
            "reuse_database": str(Path(reuse_database).resolve())
            if reuse_database is not None
            else None,
        },
    }
    projects = list(experiment.get("projects", []))
    if len(projects) != 1:
        raise ValueError("Docker CodeQL smoke requires exactly one configured project")
    project_slug = str(projects[0])
    snapshot_id = str(dataset["snapshot_id"])
    truth_view = root / "data" / "ground_truth" / snapshot_id / "ground_truth.jsonl"
    truth_record = _ground_truth_record(truth_view, project_slug)
    instance_id = str(truth_record["instance_id"])
    runtime_manifest = _absolute(root, runtime_root) / snapshot_id / "manifest.jsonl"
    runtime_instances = {item.instance_id: item for item in read_runtime_manifest(runtime_manifest)}
    if instance_id not in runtime_instances:
        raise ValueError(f"opaque instance {instance_id} is absent from {runtime_manifest}")
    runtime_repository = runtime_manifest.parent / instance_id / "repository"
    cve = str(truth_record["cve_id"])
    cwe = str(truth_record["cwe_id"])
    query = _query_name(cwe)
    configured_queries = set(str(value) for value in codeql["query_by_cwe"].values())
    if query not in configured_queries:
        raise ValueError(f"no pinned CodeQL query configured for {cwe}: expected {query}")

    selected_id = run_id or _timestamped_run_id(str(experiment["experiment_id"]))
    registry = RunRegistry(_absolute(root, runs_root), workspace=root)
    run = registry.create_run(
        selected_id,
        resolved,
        dataset={
            "snapshot_id": snapshot_id,
            "track": dataset["track"],
            "instance_id": instance_id,
            "git_commit": dataset["git_commit"],
        },
        toolchain=toolchain,
        metadata={"baseline": "codeql", "execution": "docker_smoke"},
    )
    runner = DockerCodeQLSmokeRunner(
        image=image,
        platform=str(toolchain.get("docker", {}).get("platform", "linux/amd64")),
        docker_executable=docker_executable,
        codeql_executable=str(toolchain["codeql"].get("linux_executable", _CONTAINER_CODEQL)),
        timeout_seconds=float(experiment.get("timeout_seconds", codeql["timeout_seconds"])),
        executor=executor,
    )
    record: BaselineRecord
    evaluation: Mapping[str, int | bool] = {}
    try:
        outcome = runner.run(
            run=run,
            runtime_repository=runtime_repository,
            instance_id=instance_id,
            snapshot_id=snapshot_id,
            project_slug=project_slug,
            cve=cve,
            cwe=cwe,
            track=str(dataset["track"]),
            iris_root=_absolute(root, str(toolchain["iris"]["source_path"])),
            ground_truth_csv=_absolute(root, str(dataset["source_path"])) / "data" / "fix_info.csv",
            gradle_cache=_absolute(root, gradle_cache),
            build_helper=root / "scripts" / "baselines" / "codeql_gradle_build.sh",
            query_pack_version=str(codeql["query_pack_version"]),
            reuse_database=reuse_database,
        )
        record = outcome.record
        evaluation = outcome.evaluation
    except Exception as exc:
        process = exc.result if isinstance(exc, DockerStageError) else None
        status = (
            BaselineStatus.TIMEOUT
            if process is not None and process.status is ProcessStatus.TIMEOUT
            else BaselineStatus.FAILED
        )
        record = BaselineRecord(
            run_id=selected_id,
            baseline="codeql",
            track=str(dataset["track"]),
            project=project_slug,
            cve=cve,
            cwe=f"CWE-{_cwe_number(cwe)}",
            query=query,
            status=status,
            runtime_seconds=process.duration_seconds if process is not None else 0.0,
            exit_code=process.exit_code if process is not None else None,
            command_record=process.record_path if process is not None else None,
            error=f"{type(exc).__name__}: {exc}",
            metadata={
                "orchestrator": "maxvera_docker_codeql_smoke",
                "instance_id": instance_id,
                "snapshot_id": snapshot_id,
                "failed_stage": exc.stage if isinstance(exc, DockerStageError) else "orchestration",
            },
        )

    _validate_baseline_record(record, root / "schemas" / "baseline_record.schema.json")
    run.append_jsonl("baseline.jsonl", record.to_dict())
    run.append_usage(
        {
            "purpose": "codeql_docker_smoke",
            "instance_id": instance_id,
            "latency_ms": record.runtime_seconds * 1000,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "estimated_cost_usd": 0.0,
        }
    )
    if record.status is not BaselineStatus.COMPLETE:
        run.append_error(
            code=record.status.value,
            message=record.error or "Docker CodeQL smoke failed",
            stage=str(record.metadata.get("failed_stage", "codeql_docker_smoke")),
            details={"instance_id": instance_id, "query": query},
        )
    final_status = {
        BaselineStatus.COMPLETE: RunStatus.COMPLETE,
        BaselineStatus.FAILED: RunStatus.FAILED,
        BaselineStatus.TIMEOUT: RunStatus.TIMEOUT,
    }[record.status]
    metrics: dict[str, Any] = {
        "projects_total": 1,
        "projects_complete": int(record.status is BaselineStatus.COMPLETE),
        "projects_failed": int(record.status is BaselineStatus.FAILED),
        "projects_timeout": int(record.status is BaselineStatus.TIMEOUT),
        "detected": int(record.vulnerability_detected is True),
        "runtime_seconds": record.runtime_seconds,
        **evaluation,
    }
    run.finalize(final_status, metrics=metrics)

    result_path = _absolute(root, results_root) / "codeql" / f"{selected_id}.jsonl"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    return run.path
