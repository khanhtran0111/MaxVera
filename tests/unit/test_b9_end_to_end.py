from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.common.provenance import sha256_file
from src.pipeline_v2 import b9, fixed, runtime, verification
from src.pipeline_v2.runtime import Run
from src.pipeline_v2.validate import validate_stages
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any], Path]:
    repository = Path(__file__).resolve().parents[2]
    config = yaml.safe_load((repository / b9.DEFAULT_CONFIG).read_text())
    config["execution"]["config_path"] = "configs/current.yaml"
    config["execution"]["pilot_project_id"] = "dev_a"
    config["execution"]["cache_cleanup_after_project"] = False
    config["execution"]["api_retry"]["max_stage_retries"] = 0
    split = tmp_path / "data/processed/splits/development.csv"
    split.parent.mkdir(parents=True)
    split.write_text("project_id\ndev_a\ndev_b\n")
    config["dataset"]["development_split_sha256"] = sha256_file(split)
    model = tmp_path / config["model_config"]
    model.parent.mkdir(parents=True)
    model.write_text("model_id: openai/gpt-oss-20b\nprovider_route: akashml\n")
    (tmp_path / runtime.QUERY_ROOT).mkdir(parents=True)
    config_path = tmp_path / "configs/current.yaml"
    config_path.write_text(yaml.safe_dump(config))
    monkeypatch.setattr(runtime, "collect_git", lambda _root: {"commit": "fixture", "dirty": False})
    monkeypatch.setattr(runtime, "collect_environment", lambda _root: {})
    return tmp_path, config, config_path


def synthesis(root: Path, config_path: Path, projects: list[str], run_id: str = "synth") -> Path:
    run = Run(
        root,
        "results/specifications/v2/b9",
        run_id,
        10,
        config_path,
        projects,
        dependencies={"baseline_id": "B9", "dry_run": False, "phase9": {"run_root": "results/p9"}},
    )
    specs = [
        {
            "project_id": project,
            "specification_id": "spec_" + project,
            "hypothesis_id": "hyp_" + project,
            "candidate_cwe": "CWE-22",
            "frozen_endpoints": [{"descriptor": {"file": "src/A.java"}}],
        }
        for project in projects
    ]
    atomic_jsonl(run.work / "specifications.jsonl", specs)
    atomic_jsonl(run.work / "llm_calls.jsonl", [])
    for project in projects:
        run.status(project, "SUCCESS", "synthesis fixture")
    return run.finalize({"specifications": len(specs)})


def stages(root: Path, config_path: Path) -> tuple[Path, Path, Path]:
    p10 = synthesis(root, config_path, ["dev_a", "dev_b"])
    results = [
        {
            "project_id": project,
            "specification_id": "spec_" + project,
            "hypothesis_id": "hyp_" + project,
            "candidate_cwe": "CWE-22",
            "verification_version": "semantic-differential-verifier-v3",
            "status": "UNVERIFIED_NO_VULNERABLE_PATH",
            "vulnerable": None,
            "fixed": None,
        }
        for project in ("dev_a", "dev_b")
    ]
    p11 = Run(
        root,
        "results/verification/v3",
        "verify",
        11,
        config_path,
        ["dev_a", "dev_b"],
        dependencies={"phase10": {"manifest_sha256": sha256_file(p10 / "manifest.json")}},
    )
    atomic_jsonl(p11.work / "verification_results.jsonl", results)
    for project in p11.selected:
        p11.status(project, "SUCCESS", "explicit unverified state")
    verified = p11.finalize({})
    p12 = Run(
        root,
        "results/calibration/v2",
        "route",
        12,
        config_path,
        ["dev_a", "dev_b"],
        dependencies={
            "phase10": {"manifest_sha256": sha256_file(p10 / "manifest.json")},
            "phase11": {"manifest_sha256": sha256_file(verified / "manifest.json")},
        },
    )
    atomic_jsonl(
        p12.work / "routing.jsonl",
        [
            {
                "project_id": row["project_id"],
                "specification_id": row["specification_id"],
                "verification_status": row["status"],
                "decision": "ABSTAIN",
                "oof_candidate_cwe_probability": None,
            }
            for row in results
        ],
    )
    for project in p12.selected:
        p12.status(project, "SUCCESS", "conservative routing")
    return p10, verified, p12.finalize({"calibrated_full": False, "accept_enabled": False})


@pytest.mark.parametrize(
    "defect", ["missing_result", "false_verified", "unverified_accept", "budget"]
)
def test_end_to_end_validator_rejects_incomplete_or_unsafe_outputs(
    workspace: Any, defect: str
) -> None:
    root, config, config_path = workspace
    p10, p11, p12 = stages(root, config_path)
    assert validate_stages(root, config, ["dev_a", "dev_b"], p10, p11, p12)["status"] == "PASS"
    if defect == "missing_result":
        atomic_jsonl(
            p11 / "verification_results.jsonl", read_jsonl(p11 / "verification_results.jsonl")[:1]
        )
    elif defect == "false_verified":
        rows = read_jsonl(p11 / "verification_results.jsonl")
        rows[0]["status"] = "VERIFIED_DIFFERENTIAL"
        atomic_jsonl(p11 / "verification_results.jsonl", rows)
        routes = read_jsonl(p12 / "routing.jsonl")
        routes[0]["verification_status"] = "VERIFIED_DIFFERENTIAL"
        atomic_jsonl(p12 / "routing.jsonl", routes)
    elif defect == "unverified_accept":
        routes = read_jsonl(p12 / "routing.jsonl")
        routes[0]["decision"] = "ACCEPT"
        atomic_jsonl(p12 / "routing.jsonl", routes)
    else:
        atomic_jsonl(
            p10 / "projects/dev_a/api_attempts.jsonl",
            [{"request_estimate_tokens": 1}] * (config["budget"]["max_calls_per_project"] + 1),
        )
    for path in (p10, p11, p12):
        write_checksums(path)
    with pytest.raises(ValueError):
        validate_stages(root, config, ["dev_a", "dev_b"], p10, p11, p12)


def test_fixed_preparation_uses_new_v2_projects_and_preserves_parent(
    workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, config, config_path = workspace
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    labels = root / config["dataset"]["labels"]
    labels.parent.mkdir(parents=True)
    labels.write_text(
        "project_id,fix_commit_ids\ndev_a,fixture_a\ndev_b,fixture_b\nholdout,never_used\n"
    )
    config["dataset"]["labels_sha256"] = sha256_file(labels)
    metadata = root / "data/processed/analysis_input/D_extended_projects.csv"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("project_id,jdk_version\ndev_a,8\ndev_b,8\n")
    parent = root / config["fixed_preparation"]["parent_root"]
    (parent / "dev_a").mkdir(parents=True)
    (parent / "dev_a/src.zip").write_bytes(b"fixture archive")
    (parent / "dev_a/codeql-database.yml").write_text("fixture metadata")
    atomic_jsonl(parent / "build_status.jsonl", [{"project_id": "dev_a", "status": "SUCCESS"}])
    atomic_json(
        parent / "preparation_manifest.json",
        {
            "development_only": True,
            "locked_test_prepared": False,
            "identity_mapping_persisted": False,
            "preparation_complete": True,
            "labels_sha256": config["dataset"]["labels_sha256"],
            "status_sha256": sha256_file(parent / "build_status.jsonl"),
            "development_split_sha256": config["dataset"]["development_split_sha256"],
        },
    )
    for field, filename in (
        ("parent_manifest_sha256", "preparation_manifest.json"),
        ("parent_status_sha256", "build_status.jsonl"),
    ):
        config["fixed_preparation"][field] = sha256_file(parent / filename)
    config_path.write_text(yaml.safe_dump(config))
    p10 = synthesis(root, config_path, ["dev_a", "dev_b"])
    before = (parent / "preparation_manifest.json").read_bytes()
    built = []

    def build(
        _root: Path,
        _config: Any,
        project: str,
        row: Any,
        files: Any,
        destination: Path,
        _logs: Path,
    ) -> dict[str, Any]:
        assert row["fix_commit_ids"] == "fixture_b" and files == ("src/A.java",)
        built.append(project)
        destination.mkdir()
        (destination / "src.zip").write_bytes(b"new fixture archive")
        (destination / "codeql-database.yml").write_text("new fixture metadata")
        return {"build_mode": "none"}

    monkeypatch.setattr(fixed, "_build", build)
    prepared = fixed.prepare(
        root, config, config_path, ["dev_a", "dev_b"], "fixed", p10.relative_to(root).as_posix()
    )
    assert built == ["dev_b"]
    assert (parent / "preparation_manifest.json").read_bytes() == before
    assert {row["project_id"] for row in read_jsonl(prepared / "databases.jsonl")} == {
        "dev_a",
        "dev_b",
    }
    assert json.loads((prepared / "summary.json").read_text())["prepared_databases"] == 2


def test_verifier_preserves_specs_from_partially_failed_project(
    workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, config, config_path = workspace
    p10 = synthesis(root, config_path, ["dev_a"])
    atomic_jsonl(
        p10 / "project_status.jsonl", [{"project_id": "dev_a", "status": "ANALYSIS_FAILED"}]
    )
    write_checksums(p10)
    database_root = root / config["dataset"]["fixed_database_root"]
    database_root.mkdir(parents=True)
    atomic_jsonl(database_root / "build_status.jsonl", [])
    atomic_json(
        database_root / "preparation_manifest.json",
        {
            "development_only": True,
            "locked_test_prepared": False,
            "identity_mapping_persisted": False,
            "preparation_complete": True,
            "development_split_sha256": config["dataset"]["development_split_sha256"],
            "status_sha256": sha256_file(database_root / "build_status.jsonl"),
        },
    )
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    monkeypatch.setattr(verification, "codeql", lambda *_: root / "codeql")
    verified = verification.phase11(
        root, config, config_path, ["dev_a"], "verify_partial", p10.relative_to(root).as_posix()
    )
    results = read_jsonl(verified / "verification_results.jsonl")
    assert len(results) == 1 and results[0]["specification_id"] == "spec_dev_a"
    assert results[0]["status"] == "UNVERIFIED_UPSTREAM_ANALYSIS_FAILURE"


def test_controller_api_outage_retains_waiting_state_and_resume_flag(
    workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _config, config_path = workspace
    controller = Run(root, "results/pipeline_v2/b9", "controller", 0, config_path, ["dev_a"])
    commands = []
    partial = root / "results/specifications/v2/b9/.synth.inprogress"
    partial.mkdir(parents=True)
    (partial / "api_attempts.jsonl").write_text("reserved-budget-fixture\n")

    def unavailable(command: Any, _root: Any, _log: Any, role: str) -> int:
        commands.append(list(command))
        assert role == "analyzer"
        return 75

    monkeypatch.setattr(b9, "execute", unavailable)
    with pytest.raises(b9.RetryableSynthesisError):
        b9.stage(
            controller,
            "phase10",
            "synth",
            "results/specifications/v2/b9",
            10,
            ["dev_a"],
            ["--confirm-api-spend"],
        )
    state = json.loads((controller.work / "steps.json").read_text())["synth"]
    assert state["status"] == "WAITING_FOR_API" and state["exit_code"] == 75
    assert "--resume" in commands[0]
    assert (partial / "api_attempts.jsonl").read_text() == "reserved-budget-fixture\n"


def test_b9_numbered_entrypoint_dispatches_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.cli import run_baseline

    received = []
    monkeypatch.setattr(b9, "main", lambda args: received.append(args) or 0)
    monkeypatch.setattr(
        "sys.argv",
        [
            "baseline",
            "--baseline-id",
            "B9",
            "--config",
            "unused.yaml",
            "--",
            "--pipeline-v2",
            "--mode",
            "pilot",
            "--run-id",
            "fixture",
        ],
    )
    assert run_baseline.main() == 0
    assert received == [["--mode", "pilot", "--run-id", "fixture"]]
