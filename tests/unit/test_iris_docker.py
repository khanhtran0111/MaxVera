from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from openiris.data.models import BuildInfo
from openiris.data.runtime_view import RuntimeInstance, RuntimeRepository
from openiris.experiments import BaselineStatus
from openiris.experiments.subprocess import ProcessResult, ProcessStatus
from openiris.iris.docker import (
    LEAKAGE_EXCEPTION,
    DockerIrisRunner,
    create_evaluator_bundle,
    load_ground_truth_record,
)

INSTANCE_ID = "oi_0123456789abcdef0123456789abcdef"
REVISION = "1" * 40
PROJECT = "owner__repo_CVE-2024-1234_1.0"


def _instance() -> RuntimeInstance:
    return RuntimeInstance(
        instance_id=INSTANCE_ID,
        snapshot_id="legacy_snapshot",
        track="legacy",
        repository=RuntimeRepository(
            host="github.com",
            owner="owner",
            name="repo",
            url="https://github.com/owner/repo",
        ),
        revision=REVISION,
        build=BuildInfo(),
    )


def _truth() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "instance_id": INSTANCE_ID,
        "upstream_id": "7",
        "project_slug": PROJECT,
        "cve_id": "CVE-2024-1234",
        "cwe_id": "CWE-22",
        "cwe_name": "Path traversal",
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "repository_tag": "1.0",
        "buggy_commit_id": REVISION,
        "fix_commit_ids": ["2" * 40],
        "fix_locations": [
            {
                "commit": "2" * 40,
                "file": "src/main/java/Example.java",
                "class": "Example",
                "class_start": 1,
                "class_end": 20,
                "method": "open",
                "method_start": 5,
                "method_end": 10,
                "signature": "void open(String)",
            }
        ],
        "manual_source_sink_annotations": [],
    }


def test_ground_truth_selection_is_by_opaque_id(tmp_path: Path) -> None:
    path = tmp_path / "ground_truth.jsonl"
    other = {**_truth(), "instance_id": "oi_ffffffffffffffffffffffffffffffff"}
    path.write_text(
        json.dumps(other) + "\n" + json.dumps(_truth()) + "\n",
        encoding="utf-8",
    )

    selected = load_ground_truth_record(path, INSTANCE_ID)

    assert selected["project_slug"] == PROJECT
    assert selected["instance_id"] == INSTANCE_ID


def test_evaluator_bundle_is_minimal_and_declares_exception(tmp_path: Path) -> None:
    packages = tmp_path / "packages.txt"
    packages.write_text("org.example\n", encoding="utf-8")

    bundle = create_evaluator_bundle(
        tmp_path / "bundle",
        instance=_instance(),
        ground_truth=_truth(),
        package_names_path=packages,
    )

    assert sorted(path.name for path in bundle.root.iterdir()) == [
        "fix_info.csv",
        "package-names.txt",
        "project_info.csv",
        "provenance.json",
        "selected_ground_truth.json",
    ]
    with bundle.project_info.open("r", encoding="utf-8", newline="") as handle:
        project_rows = list(csv.DictReader(handle))
    with bundle.fix_info.open("r", encoding="utf-8", newline="") as handle:
        fix_rows = list(csv.DictReader(handle))
    provenance = json.loads(bundle.provenance.read_text(encoding="utf-8"))

    assert project_rows[0]["cwe_id"] == "CWE-022"
    assert project_rows[0]["project_slug"] == PROJECT
    assert fix_rows[0]["file"] == "src/main/java/Example.java"
    assert provenance["leakage_exception"]["id"] == "iris-v1-oracle-interface"
    assert bundle.hashes()["package-names.txt"]


class RecordingDockerExecutor:
    def __init__(self, output: Path, query: str) -> None:
        self.output = output
        self.query = query
        self.argv: tuple[str, ...] = ()

    def run(self, argv: list[str], **kwargs: Any) -> ProcessResult:
        self.argv = tuple(argv)
        final = self.output / "upstream_output" / f"{self.query}-final"
        final.mkdir(parents=True)
        (final / "results.json").write_text(
            json.dumps({"vanilla_result": {"num_paths": 3, "recall_method": False}}),
            encoding="utf-8",
        )
        artifact_dir = Path(kwargs["artifact_dir"])
        return ProcessResult(
            status=ProcessStatus.COMPLETE,
            argv=tuple(argv),
            cwd=str(kwargs["cwd"]),
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_seconds=1.0,
            exit_code=0,
            timeout_seconds=kwargs.get("timeout_seconds"),
            stdout_path=str(artifact_dir / "stdout.log"),
            stderr_path=str(artifact_dir / "stderr.log"),
            record_path=str(artifact_dir / "command.json"),
        )


def test_docker_runner_uses_gpu_readonly_inputs_and_opaque_result(tmp_path: Path) -> None:
    iris = tmp_path / "iris-pinned"
    (iris / "src").mkdir(parents=True)
    (iris / "src" / "neusym_vul.py").write_text("pass\n", encoding="utf-8")
    repository = tmp_path / INSTANCE_ID / "repository"
    repository.mkdir(parents=True)
    (repository / "Example.java").write_text("class Example {}\n", encoding="utf-8")
    database = tmp_path / "database"
    (database / "db-java").mkdir(parents=True)
    packages = tmp_path / "packages.txt"
    packages.write_text("org.example\n", encoding="utf-8")
    bundle = create_evaluator_bundle(
        tmp_path / "evaluator",
        instance=_instance(),
        ground_truth=_truth(),
        package_names_path=packages,
    )
    output = tmp_path / "retained"
    executor = RecordingDockerExecutor(output, "cwe-022wLLM")
    runner = DockerIrisRunner(
        image="maxvera-phase0:iris",
        executor=executor,  # type: ignore[arg-type]
        timeout_seconds=10,
    )

    record = runner.run(
        run_id="phase0-smoke",
        instance=_instance(),
        upstream_project_slug=PROJECT,
        cve="CVE-2024-1234",
        query="cwe-022wLLM",
        model="qwen2.5-coder-1.5b",
        model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        model_revision="b" * 40,
        seed=345,
        iris_root=iris,
        iris_commit="a" * 40,
        runtime_repository=repository,
        codeql_database=database,
        evaluator_bundle=bundle,
        hf_cache=tmp_path / "hf-cache",
        artifact_dir=tmp_path / "command",
        retained_output_dir=output,
    )

    assert record.status is BaselineStatus.COMPLETE
    assert record.project == INSTANCE_ID
    assert record.number_of_paths == 3
    assert record.vulnerability_detected is False
    assert record.metadata["detection_metric"] == "recall_method"
    assert record.metadata["leakage_exception"] == LEAKAGE_EXCEPTION
    assert executor.argv[:3] == ("docker", "run", "--rm")
    assert executor.argv[5:7] == ("--gpus", "all")
    mounts = [
        executor.argv[index + 1]
        for index, argument in enumerate(executor.argv)
        if argument == "--mount"
    ]
    assert sum(value.endswith(",readonly") for value in mounts) == 4
    assert any(INSTANCE_ID in value and PROJECT not in value for value in mounts)
    assert executor.argv[-2:] == ("--num-threads", "1")
