"""Docker adapter for the pinned, GPU-backed IRIS v1 smoke run.

IRIS v1 cannot consume the sanitized runtime manifest directly.  Its public
entrypoint derives a CVE from a semantic project slug and reads fix metadata
during construction.  This module keeps that incompatibility at one explicit
trusted bridge: source selection remains opaque, while the minimum legacy CSV
view is generated in the run directory and disclosed in provenance.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openiris.data.runtime_view import (
    RuntimeInstance,
    audit_runtime_repository,
    read_runtime_manifest,
)
from openiris.experiments.baseline import BaselineRecord, BaselineStatus, baseline_status
from openiris.experiments.subprocess import ProcessExecutor
from openiris.utils.hashing import sha256_file

_IRIS_QUERY = re.compile(r"^cwe-(?P<cwe>\d{3})wLLM$")
_SAFE_UPSTREAM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

LEAKAGE_EXCEPTION = {
    "id": "iris-v1-oracle-interface",
    "classification": "declared-paper-reproduction-exception",
    "analysis_source_selection": "opaque_instance_id",
    "exposed_to_upstream": [
        "semantic_project_slug",
        "oracle_cwe_query",
        "selected_fix_metadata_for_upstream_evaluation",
    ],
    "reason": (
        "Pinned IRIS v1 parses the CVE from the semantic project slug, uses an "
        "oracle CWE query, and reads project_info.csv/fix_info.csv in its analysis "
        "constructor. The compatibility data is therefore not a zero-hint input."
    ),
    "scope": "IRIS v1 Phase 0 paper-compatibility smoke only",
}

_PROJECT_INFO_FIELDS = (
    "id",
    "project_slug",
    "cve_id",
    "cwe_id",
    "cwe_name",
    "github_username",
    "github_repository_name",
    "github_tag",
    "github_url",
    "advisory_id",
    "buggy_commit_id",
    "fix_commit_ids",
)
_FIX_INFO_FIELDS = (
    "project_slug",
    "cve_id",
    "github_username",
    "github_repository_name",
    "commit",
    "file",
    "class",
    "class_start",
    "class_end",
    "method",
    "method_start",
    "method_end",
    "signature",
)


@dataclass(frozen=True, slots=True)
class EvaluatorBundle:
    """Minimal evaluator-only compatibility view consumed by upstream IRIS."""

    root: Path
    project_info: Path
    fix_info: Path
    package_names: Path
    selected_ground_truth: Path
    provenance: Path

    def hashes(self) -> dict[str, str]:
        return {
            path.name: sha256_file(path)
            for path in (
                self.project_info,
                self.fix_info,
                self.package_names,
                self.selected_ground_truth,
                self.provenance,
            )
        }


def load_ground_truth_record(path: str | Path, instance_id: str) -> dict[str, Any]:
    """Read exactly one evaluator record by opaque ID."""

    source = Path(path).resolve()
    matches: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid ground-truth JSON at line {line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"ground-truth line {line_number} is not an object")
            if value.get("instance_id") == instance_id:
                matches.append(value)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one ground-truth record for {instance_id}, found {len(matches)}"
        )
    return matches[0]


def select_runtime_instance(path: str | Path, instance_id: str) -> RuntimeInstance:
    """Select one sanitized runtime instance without consulting labels."""

    matches = [item for item in read_runtime_manifest(path) if item.instance_id == instance_id]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one runtime record for {instance_id}, found {len(matches)}"
        )
    return matches[0]


def _text(record: Mapping[str, Any], key: str) -> str:
    value = record.get(key, "")
    return "" if value is None else str(value)


def _padded_cwe(value: str) -> str:
    match = re.fullmatch(r"CWE-(\d+)", value, re.IGNORECASE)
    if match is None:
        raise ValueError(f"invalid ground-truth CWE identifier: {value!r}")
    return f"CWE-{int(match.group(1)):03d}"


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="raise",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def create_evaluator_bundle(
    destination: str | Path,
    *,
    instance: RuntimeInstance,
    ground_truth: Mapping[str, Any],
    package_names_path: str | Path,
) -> EvaluatorBundle:
    """Build the smallest legacy metadata layout that pinned IRIS v1 accepts."""

    root = Path(destination).resolve()
    if root.exists():
        if not root.is_dir() or any(root.iterdir()):
            raise FileExistsError(f"evaluator compatibility directory is not empty: {root}")
    else:
        root.mkdir(parents=True)

    if _text(ground_truth, "instance_id") != instance.instance_id:
        raise ValueError("runtime and ground-truth instance IDs differ")
    if _text(ground_truth, "buggy_commit_id").casefold() != instance.revision.casefold():
        raise ValueError("runtime revision does not match evaluator ground truth")

    project_slug = _text(ground_truth, "project_slug")
    if _SAFE_UPSTREAM_NAME.fullmatch(project_slug) is None:
        raise ValueError(f"unsafe upstream project slug: {project_slug!r}")
    cve_id = _text(ground_truth, "cve_id")
    cwe_id = _padded_cwe(_text(ground_truth, "cwe_id"))
    fix_commits_value = ground_truth.get("fix_commit_ids", [])
    if not isinstance(fix_commits_value, list) or not all(
        isinstance(value, str) for value in fix_commits_value
    ):
        raise ValueError("ground-truth fix_commit_ids must be a string array")

    project_row: dict[str, Any] = {
        "id": _text(ground_truth, "upstream_id"),
        "project_slug": project_slug,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cwe_name": _text(ground_truth, "cwe_name"),
        "github_username": instance.repository.owner,
        "github_repository_name": instance.repository.name,
        "github_tag": _text(ground_truth, "repository_tag"),
        "github_url": instance.repository.url,
        "advisory_id": _text(ground_truth, "advisory_id"),
        "buggy_commit_id": instance.revision,
        "fix_commit_ids": ";".join(fix_commits_value),
    }

    raw_fix_locations = ground_truth.get("fix_locations", [])
    if not isinstance(raw_fix_locations, list) or not all(
        isinstance(value, Mapping) for value in raw_fix_locations
    ):
        raise ValueError("ground-truth fix_locations must be an object array")
    fix_rows: list[dict[str, Any]] = []
    for raw_location in raw_fix_locations:
        fix_rows.append(
            {
                "project_slug": project_slug,
                "cve_id": cve_id,
                "github_username": instance.repository.owner,
                "github_repository_name": instance.repository.name,
                "commit": _text(raw_location, "commit"),
                "file": _text(raw_location, "file"),
                "class": _text(raw_location, "class"),
                "class_start": _text(raw_location, "class_start"),
                "class_end": _text(raw_location, "class_end"),
                "method": _text(raw_location, "method"),
                "method_start": _text(raw_location, "method_start"),
                "method_end": _text(raw_location, "method_end"),
                "signature": _text(raw_location, "signature"),
            }
        )

    project_info = root / "project_info.csv"
    fix_info = root / "fix_info.csv"
    package_names = root / "package-names.txt"
    selected_ground_truth = root / "selected_ground_truth.json"
    provenance = root / "provenance.json"
    _write_csv(project_info, _PROJECT_INFO_FIELDS, [project_row])
    _write_csv(fix_info, _FIX_INFO_FIELDS, fix_rows)

    package_source = Path(package_names_path).resolve()
    if not package_source.is_file():
        raise FileNotFoundError(package_source)
    shutil.copyfile(package_source, package_names)
    with selected_ground_truth.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(dict(ground_truth), handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    with provenance.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(
            {
                "schema_version": 1,
                "runtime_instance_id": instance.instance_id,
                "upstream_project_slug": project_slug,
                "leakage_exception": LEAKAGE_EXCEPTION,
            },
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        handle.write("\n")
    return EvaluatorBundle(
        root=root,
        project_info=project_info,
        fix_info=fix_info,
        package_names=package_names,
        selected_ground_truth=selected_ground_truth,
        provenance=provenance,
    )


def _mount(source: Path, target: str, *, read_only: bool) -> str:
    rendered = str(source.resolve())
    if any(character in rendered for character in (",", "\n", "\r")):
        raise ValueError(f"Docker bind source contains an unsupported character: {rendered!r}")
    suffix = ",readonly" if read_only else ""
    return f"type=bind,source={rendered},target={target}{suffix}"


def _result_metrics(document: Any) -> tuple[int | None, bool | None]:
    if not isinstance(document, dict):
        return None, None
    for section_name in ("posthoc_filter_result", "vanilla_result"):
        section = document.get(section_name)
        if isinstance(section, dict) and isinstance(section.get("num_paths"), int):
            recall_method = section.get("recall_method")
            return int(section["num_paths"]), (
                recall_method if isinstance(recall_method, bool) else None
            )
    if isinstance(document.get("num_paths"), int):
        recall_method = document.get("recall_method")
        return int(document["num_paths"]), (
            recall_method if isinstance(recall_method, bool) else None
        )
    return None, None


class DockerIrisRunner:
    """Run unmodified pinned IRIS v1 in an ephemeral GPU-enabled container."""

    def __init__(
        self,
        *,
        image: str = "maxvera-phase0:iris",
        docker_executable: str = "docker",
        platform: str = "linux/amd64",
        timeout_seconds: float | None = None,
        executor: ProcessExecutor | None = None,
    ) -> None:
        if not image.strip() or any(character.isspace() for character in image):
            raise ValueError("Docker image must be a non-empty reference without whitespace")
        self.image = image
        self.docker_executable = docker_executable
        self.platform = platform
        self.timeout_seconds = timeout_seconds
        self.executor = executor or ProcessExecutor(timeout_seconds)

    def run(
        self,
        *,
        run_id: str,
        instance: RuntimeInstance,
        upstream_project_slug: str,
        cve: str,
        query: str,
        model: str,
        model_id: str,
        model_revision: str,
        seed: int,
        iris_root: str | Path,
        iris_commit: str,
        runtime_repository: str | Path,
        codeql_database: str | Path,
        evaluator_bundle: EvaluatorBundle,
        hf_cache: str | Path,
        artifact_dir: str | Path,
        retained_output_dir: str | Path,
        track: str = "legacy",
        label_api_batch_size: int = 30,
        label_func_param_batch_size: int = 20,
        num_threads: int = 1,
        timeout_seconds: float | None = None,
    ) -> BaselineRecord:
        query_match = _IRIS_QUERY.fullmatch(query)
        if query_match is None:
            raise ValueError("IRIS query must look like cwe-022wLLM")
        if _SAFE_RUN_ID.fullmatch(run_id) is None:
            raise ValueError("run_id must be a portable path-safe value")
        if _SAFE_UPSTREAM_NAME.fullmatch(upstream_project_slug) is None:
            raise ValueError("upstream project slug is not path-safe")
        if not model.strip():
            raise ValueError("IRIS model cannot be empty")
        if not model_id.strip():
            raise ValueError("Hugging Face model ID cannot be empty")
        if re.fullmatch(r"[0-9a-f]{40}", model_revision) is None:
            raise ValueError("model revision must be a full lowercase 40-hex commit")
        if not re.fullmatch(r"[0-9a-f]{40}", iris_commit):
            raise ValueError("IRIS commit must be a full lowercase SHA-1")
        if min(label_api_batch_size, label_func_param_batch_size, num_threads) <= 0:
            raise ValueError("IRIS batch sizes and thread count must be positive")

        iris_source = Path(iris_root).resolve()
        repository = Path(runtime_repository).resolve()
        database = Path(codeql_database).resolve()
        output = Path(retained_output_dir).resolve()
        cache = Path(hf_cache).resolve()
        for required in (iris_source, repository, database, evaluator_bundle.root):
            if not required.is_dir():
                raise NotADirectoryError(required)
        if not (iris_source / "src" / "neusym_vul.py").is_file():
            raise FileNotFoundError(iris_source / "src" / "neusym_vul.py")
        if not (database / "db-java").is_dir():
            raise FileNotFoundError(database / "db-java")
        audit_runtime_repository(repository)
        output.mkdir(parents=True, exist_ok=False)
        cache.mkdir(parents=True, exist_ok=True)

        argv = [
            self.docker_executable,
            "run",
            "--rm",
            "--pull=never",
            f"--platform={self.platform}",
            "--gpus",
            "all",
            "--env",
            f"PYTHONHASHSEED={seed}",
            "--env",
            "HF_HUB_DISABLE_TELEMETRY=1",
            "--mount",
            _mount(iris_source, "/inputs/iris", read_only=True),
            "--mount",
            _mount(repository, "/inputs/repository", read_only=True),
            "--mount",
            _mount(database, "/inputs/database", read_only=True),
            "--mount",
            _mount(evaluator_bundle.root, "/inputs/evaluator", read_only=True),
            "--mount",
            _mount(output, "/outputs", read_only=False),
            "--mount",
            _mount(cache, "/cache/huggingface", read_only=False),
            self.image,
            "/opt/maxvera/run-iris.sh",
            "--project",
            upstream_project_slug,
            "--query",
            query,
            "--model",
            model,
            "--model-id",
            model_id,
            "--model-revision",
            model_revision,
            "--run-id",
            run_id,
            "--seed",
            str(seed),
            "--iris-commit",
            iris_commit,
            "--label-api-batch-size",
            str(label_api_batch_size),
            "--label-func-param-batch-size",
            str(label_func_param_batch_size),
            "--num-threads",
            str(num_threads),
        ]
        process = self.executor.run(
            argv,
            artifact_dir=artifact_dir,
            cwd=Path.cwd(),
            timeout_seconds=(self.timeout_seconds if timeout_seconds is None else timeout_seconds),
        )

        retained = output / "upstream_output"
        model_snapshot = output / "model_snapshot.json"
        final_json = retained / f"{query}-final" / "results.json"
        query_sarif = retained / query / "results.sarif"
        processed_sarif = retained / query / "results_pp.sarif"
        artifacts = tuple(
            str(path)
            for path in (model_snapshot, final_json, query_sarif, processed_sarif)
            if path.is_file()
        )
        status = baseline_status(process)
        error = process.error
        paths: int | None = None
        detected: bool | None = None
        if status is BaselineStatus.COMPLETE:
            if final_json.is_file():
                try:
                    with final_json.open("r", encoding="utf-8") as handle:
                        paths, detected = _result_metrics(json.load(handle))
                    if paths is None:
                        status = BaselineStatus.FAILED
                        error = "IRIS results.json has no recognized num_paths field"
                    elif detected is None:
                        status = BaselineStatus.FAILED
                        error = "IRIS results.json has no boolean recall_method field"
                except (OSError, ValueError) as exc:
                    status = BaselineStatus.FAILED
                    error = f"invalid IRIS results.json: {exc}"
            else:
                status = BaselineStatus.FAILED
                error = "Docker IRIS exited successfully without final results.json"
        elif error is None:
            error = f"Docker IRIS process exited with code {process.exit_code}"

        return BaselineRecord(
            run_id=run_id,
            baseline="iris",
            track=track,
            project=instance.instance_id,
            cve=cve or None,
            cwe=f"CWE-{int(query_match.group('cwe'))}",
            query=query,
            status=status,
            number_of_paths=paths,
            vulnerability_detected=detected,
            runtime_seconds=process.duration_seconds,
            exit_code=process.exit_code,
            command_record=process.record_path,
            output_artifacts=artifacts,
            error=error,
            metadata={
                "orchestrator": "iris_v1_docker_compatibility",
                "runtime_instance_id": instance.instance_id,
                "runtime_revision": instance.revision,
                "upstream_project_slug": upstream_project_slug,
                "iris_commit": iris_commit,
                "docker_image": self.image,
                "docker_platform": self.platform,
                "gpu_request": "all",
                "model": model,
                "model_id": model_id,
                "model_revision_requested": model_revision,
                "model_revision_forwarded_by_upstream": False,
                "model_revision_enforced_via_offline_cache": True,
                "upstream_qwen_effective_temperature": 0.01,
                "upstream_qwen_do_sample": False,
                "seed": seed,
                "skip_posthoc_filter": True,
                "detection_metric": "recall_method",
                "evaluator_bundle_hashes": evaluator_bundle.hashes(),
                "leakage_exception": LEAKAGE_EXCEPTION,
            },
        )
