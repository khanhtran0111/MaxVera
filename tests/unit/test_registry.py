from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from openiris.experiments import (
    InvalidRunIdError,
    RunAlreadyExistsError,
    RunFinalizedError,
    RunRegistry,
    RunStatus,
)


def test_run_registry_creates_contract_and_finalizes_immutably(tmp_path: Path) -> None:
    registry = RunRegistry(tmp_path / "runs", workspace=tmp_path)
    run = registry.create_run(
        "phase0_smoke_001",
        {"seed": 345, "baseline": "codeql"},
        dataset={"snapshot_id": "legacy"},
        toolchain={"codeql_version": "2.15.3"},
    )

    assert run.status is RunStatus.RUNNING
    for name in (
        "manifest.yaml",
        "config.resolved.yaml",
        "environment.json",
        "usage.jsonl",
        "errors.jsonl",
    ):
        assert (run.path / name).is_file()
    assert (run.path / "logs").is_dir()
    assert (run.path / "commands").is_dir()

    run.append_usage({"purpose": "codeql", "latency_ms": 12})
    run.append_error(code="NOTICE", message="retained", stage="test")
    run.append_jsonl("baseline.jsonl", {"project": "tiny"})
    run.complete({"recall": 1.0})

    assert run.status is RunStatus.COMPLETE
    assert run.finalized
    assert json.loads((run.path / "metrics.json").read_text(encoding="utf-8")) == {"recall": 1.0}
    with pytest.raises(RunFinalizedError):
        run.append_usage({"purpose": "late mutation"})
    with pytest.raises(RunFinalizedError):
        run.write_json("late.json", {})
    with pytest.raises(RunAlreadyExistsError):
        registry.create_run("phase0_smoke_001", {})


def test_manifest_validates_before_and_after_completion(tmp_path: Path) -> None:
    registry = RunRegistry(tmp_path / "runs", workspace=Path.cwd())
    run = registry.create_run("schema_test", {"temperature": 0.0})
    schema = json.loads(
        (Path.cwd() / "schemas" / "run_manifest.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    validator.validate(yaml.safe_load(run.manifest_path.read_text(encoding="utf-8")))
    run.finalize(RunStatus.FAILED, metrics={})
    validator.validate(yaml.safe_load(run.manifest_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("run_id", ["../escape", "with space", "", ".hidden/start", "a" * 129])
def test_registry_rejects_unsafe_run_ids(tmp_path: Path, run_id: str) -> None:
    registry = RunRegistry(tmp_path / "runs")
    with pytest.raises(InvalidRunIdError):
        registry.create_run(run_id, {})


def test_artifact_paths_cannot_escape_run(tmp_path: Path) -> None:
    run = RunRegistry(tmp_path / "runs").create_run("safe", {})
    with pytest.raises(ValueError, match="escapes"):
        run.write_json("../outside.json", {})


def test_managed_run_retains_exception_and_marks_failed(tmp_path: Path) -> None:
    registry = RunRegistry(tmp_path / "runs")
    with pytest.raises(RuntimeError, match="boom"), registry.managed_run("failed", {"x": 1}):
        raise RuntimeError("boom")

    run = registry.open_run("failed")
    assert run.status is RunStatus.FAILED
    error = json.loads((run.path / "errors.jsonl").read_text(encoding="utf-8"))
    assert error["code"] == "RuntimeError"
    assert error["message"] == "boom"
