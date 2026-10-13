from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.common.provenance import sha256_file
from src.pipeline_v2 import (
    benchmark_evaluate,
    benchmark_inputs,
    benchmark_recovery,
    calibration,
    runtime,
)
from src.pipeline_v2.benchmark_evaluate import case_alignment, paper_aggregate, path_metric
from src.pipeline_v2.benchmark_inputs import inherit_discovery
from src.pipeline_v2.runtime import Run, configuration, dependency, selection_ids
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums


@pytest.fixture
def benchmark_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any], Path]:
    repository = Path(__file__).resolve().parents[2]
    config = yaml.safe_load((repository / "configs/experiments/b9_benchmark_120.yaml").read_text())
    dev = [f"dev_{i}" for i in range(96)]
    test = [f"test_{i}" for i in range(24)]
    splits = tmp_path / "data/processed/splits"
    splits.mkdir(parents=True)
    (splits / "development.csv").write_text("project_id\n" + "\n".join(dev) + "\n")
    (splits / "test_locked.csv").write_text("project_id\n" + "\n".join(test) + "\n")
    population = tmp_path / config["dataset"]["population"]
    population.parent.mkdir(parents=True)
    population.write_text("project_id\n" + "\n".join(dev + test) + "\n")
    config["dataset"]["development_split_sha256"] = sha256_file(splits / "development.csv")
    config["dataset"]["test_split_sha256"] = sha256_file(splits / "test_locked.csv")
    config["dataset"]["population_sha256"] = sha256_file(population)
    config["execution"]["config_path"] = "configs/current.yaml"
    model = tmp_path / config["model_config"]
    model.parent.mkdir(parents=True)
    model.write_text("fixture model")
    (tmp_path / runtime.QUERY_ROOT).mkdir(parents=True)
    config_path = tmp_path / "configs/current.yaml"
    config_path.write_text(yaml.safe_dump(config))
    monkeypatch.setattr(runtime, "collect_git", lambda _: {"commit": "fixture", "dirty": False})
    monkeypatch.setattr(runtime, "collect_environment", lambda _: {})
    monkeypatch.setattr(benchmark_inputs, "inherit_discovery", lambda _: None)
    return tmp_path, config, config_path


def test_exact120_registration_and_development_boundary(benchmark_workspace: Any) -> None:
    root, config, config_path = benchmark_workspace
    assert len(selection_ids(root, configuration(root, config_path))) == 120
    assert len(runtime.development_ids(root)) == 96
    stage = Run(root, "results/benchmark", "cohort", 7, config_path, ["test_0"])
    stage.status("test_0", "SUCCESS", "diagnostic test case")
    path = stage.finalize({})
    dependency(root, path.relative_to(root).as_posix(), ["test_0"], 7)
    legacy = copy.deepcopy(config)
    legacy["analysis_scope"] = "development"
    legacy["status"] = "development_v2"
    legacy_path = config_path.with_name("legacy.yaml")
    legacy_path.write_text(yaml.safe_dump(legacy))
    with pytest.raises(ValueError, match="registered cohort"):
        Run(root, "results/development", "forbidden", 7, legacy_path, ["test_0"])
    (root / "data/processed/splits/test_locked.csv").write_text("project_id\ndev_0\n")
    with pytest.raises(ValueError, match="checksum mismatch"):
        configuration(root, config_path)


def test_strict_gate_retains_failed_checkpoint_and_resume_budget(benchmark_workspace: Any) -> None:
    root, config, config_path = benchmark_workspace
    config["execution"].update(
        require_all_projects_success=True, retry_failed_projects_on_resume=True
    )
    config_path.write_text(yaml.safe_dump(config))
    selected = ["dev_0", "test_0"]
    stage = Run(root, "results/strict", "gate", 7, config_path, selected)
    atomic_jsonl(stage.work / "projects/test_0/api_attempts.jsonl", [{"reservation": "retained"}])
    stage.status("dev_0", "SUCCESS", "completed")
    stage.status("test_0", "ANALYSIS_FAILED", "query timeout")
    with pytest.raises(ValueError, match="strict completion gate"):
        stage.finalize({})
    assert not stage.final.exists()
    assert (stage.work / "strict_gate.json").is_file()
    resumed = Run(root, "results/strict", "gate", 7, config_path, selected, resume=True)
    assert resumed.pending() == ["test_0"]
    assert read_jsonl(resumed.work / "projects/test_0/api_attempts.jsonl") == [
        {"reservation": "retained"}
    ]
    resumed.status("test_0", "SUCCESS", "query completed")
    result = resumed.finalize({"projects": 1, "analysis_failures": 99})
    summary = json.loads((result / "summary.json").read_text())
    assert summary["projects"] == 2 and summary["analysis_failures"] == 0


def test_dependency_rejects_silently_missing_project_even_with_valid_checksums(
    benchmark_workspace: Any,
) -> None:
    root, _, config_path = benchmark_workspace
    stage = Run(root, "results/dependency", "missing", 7, config_path, ["dev_0", "test_0"])
    for project in stage.selected:
        stage.status(project, "SUCCESS", "completed")
    output = stage.finalize({})
    atomic_jsonl(output / "project_status.jsonl", [{"project_id": "dev_0", "status": "SUCCESS"}])
    write_checksums(output)
    with pytest.raises(ValueError, match="missing, duplicate or unfinished project statuses"):
        dependency(root, output.relative_to(root).as_posix(), ["dev_0", "test_0"], 7)


@pytest.mark.parametrize("artifact_exists", [True, False])
def test_empty_discovery_is_completed_but_missing_artifact_is_an_error(
    benchmark_workspace: Any,
    artifact_exists: bool,
) -> None:
    from src.pipeline_v2.graphs import phase7

    root, config, config_path = benchmark_workspace
    config["execution"].update(empty_discovery_is_success=True)
    config_path.write_text(yaml.safe_dump(config))
    stage = Run(root, "results/p6", "empty", 6, config_path, ["dev_0"])
    if artifact_exists:
        atomic_jsonl(stage.work / "projects/dev_0/hypotheses.jsonl", [])
    stage.status("dev_0", "SUCCESS", "completed discovery with no candidate")
    upstream = stage.finalize({})
    path = phase7(root, config_path, ["dev_0"], "empty", upstream.relative_to(root).as_posix())
    status = read_jsonl(path / "project_status.jsonl")[0]
    if artifact_exists:
        assert status["status"] == "SUCCESS" and status["analysis_outcome"] == "NO_CANDIDATES"
        assert (path / "graphs/dev_0/nodes.jsonl").is_file()
    else:
        assert status["status"] == "ANALYSIS_FAILED"


def test_all120_empty_cases_finish_graph_synthesis_verification_and_routing_without_api(
    benchmark_workspace: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.pipeline_v2 import graphs, specifications, verification
    from src.pipeline_v2.validate import validate_stages

    root, config, config_path = benchmark_workspace
    selected = selection_ids(root, config)
    config["execution"].update(require_all_projects_success=True, empty_discovery_is_success=True)
    config["execution"]["cache_cleanup_after_project"] = False
    kg = root / "results/kg"
    atomic_json(kg / "manifest.json", {"fixture": "empty knowledge graph"})
    atomic_jsonl(kg / "deterministic/nodes.jsonl", [])
    write_checksums(kg)
    config["phase8"].update(
        run_root="results/kg", manifest_sha256=sha256_file(kg / "manifest.json")
    )
    for name, body in {
        "labels": "project_id,ground_truth_cwe\n" + "".join(f"{p},CWE-22\n" for p in selected),
        "split_groups": "project_id,repository_group,split\n"
        + "".join(
            f"{p},{p},{'development' if p.startswith('dev_') else 'test_locked'}\n"
            for p in selected
        ),
    }.items():
        path = root / config["dataset"][name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        config["dataset"][name + "_sha256"] = sha256_file(path)
    config_path.write_text(yaml.safe_dump(config))
    for module in (runtime, specifications, verification):
        monkeypatch.setattr(module, "codeql", lambda *_: Path("/fixture/codeql"))
    monkeypatch.setattr(runtime, "query_csv", lambda *_: [])

    def inventory(project: str, database: Path, *_args: Any) -> tuple[list[Any], dict[str, Any]]:
        database.mkdir(parents=True)
        (database / "codeql-database.yml").write_text("fixture database")
        (database / "src.zip").write_text("fixture archive")
        return [], {
            "database_metadata_sha256": sha256_file(database / "codeql-database.yml"),
            "source_archive_sha256": sha256_file(database / "src.zip"),
        }

    monkeypatch.setattr(runtime, "endpoint_inventory", inventory)
    monkeypatch.setattr(specifications.OpenRouterSettings, "load", lambda *_: object())

    def unexpected_api(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("no-candidate cases must never call the provider")

    monkeypatch.setattr(specifications.OpenRouterClient, "complete", unexpected_api)
    p6 = runtime.phase6(root, config, config_path, selected, "empty120")
    p7 = graphs.phase7(root, config_path, selected, "empty120", p6.relative_to(root).as_posix())
    p9 = graphs.phase9(
        root,
        config,
        config_path,
        selected,
        "empty120",
        p6.relative_to(root).as_posix(),
        p7.relative_to(root).as_posix(),
    )
    p10 = specifications.phase10(
        root,
        config,
        config_path,
        selected,
        "empty120",
        p6.relative_to(root).as_posix(),
        p9.relative_to(root).as_posix(),
        "B9",
        confirm_api_spend=True,
    )
    fixed_root = root / config["dataset"]["fixed_database_root"]
    atomic_jsonl(
        fixed_root / "build_status.jsonl",
        [{"project_id": p, "status": "SUCCESS"} for p in selected],
    )
    atomic_json(
        fixed_root / "preparation_manifest.json",
        {
            "development_only": False,
            "locked_test_prepared": True,
            "identity_mapping_persisted": False,
            "preparation_complete": True,
            "development_split_sha256": config["dataset"]["development_split_sha256"],
            "status_sha256": sha256_file(fixed_root / "build_status.jsonl"),
        },
    )
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    p11 = verification.phase11(
        root, config, config_path, selected, "empty120", p10.relative_to(root).as_posix()
    )
    p12 = calibration.phase12(
        root,
        config,
        config_path,
        selected,
        "empty120",
        p6.relative_to(root).as_posix(),
        p10.relative_to(root).as_posix(),
        p11.relative_to(root).as_posix(),
    )
    result = validate_stages(root, config, selected, p10, p11, p12)
    assert result["status"] == "PASS" and result["analysis_misses"] == 0
    assert result["specifications"] == 0 and result["verified_findings"] == 0
    for path in (p6, p7, p9, p10, p11, p12):
        summary = json.loads((path / "summary.json").read_text())
        assert summary["projects"] == 120 and summary["analysis_failures"] == 0
        assert summary["llm_calls"] == 0
    # A stale SUCCESS status must not hide an operational failure in a finding.
    atomic_jsonl(p10 / "specifications.jsonl", [{"specification_id": "failed-query"}])
    atomic_jsonl(
        p11 / "verification_results.jsonl",
        [
            {
                "specification_id": "failed-query",
                "status": "UNVERIFIED_QUERY_OR_BUDGET_FAILURE",
            }
        ],
    )
    atomic_jsonl(p12 / "routing.jsonl", [{"specification_id": "failed-query"}])
    for path in (p10, p11, p12):
        write_checksums(path)
    with pytest.raises(ValueError, match="verification contains operational failures"):
        validate_stages(root, config, selected, p10, p11, p12)


def test_controller_validate_only_cannot_enter_paid_branch(
    benchmark_workspace: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.pipeline_v2 import benchmark

    root, config, config_path = benchmark_workspace
    config["execution"].update(require_all_projects_success=True, empty_discovery_is_success=True)
    config["benchmark"]["fresh_discovery"] = True
    config_path.write_text(yaml.safe_dump(config))
    monkeypatch.setattr(benchmark, "preflight", lambda *_: {"coverage_manifest_sha256": "fixture"})
    steps: list[str] = []

    def stage(controller: Run, name: str, *_args: Any, **_kwargs: Any) -> Path:
        steps.append(name)
        directory = controller.work / "fixture" / name
        atomic_json(
            directory / "summary.json",
            {
                "llm_calls": 0,
                "rejected_hypotheses": 0,
                "api_eligible": 0,
            },
        )
        atomic_jsonl(
            directory / "project_status.jsonl",
            [{"project_id": p, "status": "SUCCESS"} for p in controller.selected],
        )
        return directory

    def forbidden_branch(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a no-API preflight must never synthesize")

    monkeypatch.setattr(benchmark, "stage", stage)
    monkeypatch.setattr(benchmark, "branch", forbidden_branch)
    result = benchmark.run(
        root, config_path, "no-api", resume=False, confirm_api_spend=False, validate_only=True
    )
    assert isinstance(result, Path)
    summary = json.loads((result / "summary.json").read_text())
    assert summary["projects"] == 120 and summary["api_calls"] == 0
    assert summary["verification_with_generated_specs_validated"] is False
    assert steps == ["inputs", "phase6", "phase7", "phase9", "phase10"]


def test_readiness_accounts_for_all120_when_one_archive_is_broken(
    benchmark_workspace: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.pipeline_v2 import readiness

    root, config, config_path = benchmark_workspace
    selected = selection_ids(root, config)
    config["fixed_preparation"]["coverage_cache_root"] = "data/interim/coverage-cache"
    config["execution"]["minimum_application_source_coverage"] = 1.0
    policy = root / "src/pipeline_v2/coverage.py"
    policy.parent.mkdir(parents=True)
    policy.write_text("fixture policy")
    labels = root / config["dataset"]["labels"]
    labels.parent.mkdir(parents=True, exist_ok=True)
    labels.write_text("project_id,fix_commit_ids\n" + "".join(f"{p},abc\n" for p in selected))
    config["dataset"]["labels_sha256"] = sha256_file(labels)
    config_path.write_text(yaml.safe_dump(config))
    for relative in (
        config["benchmark"]["vulnerable_parent_roots"][0],
        config["fixed_preparation"]["parent_root"],
    ):
        for project in selected:
            database = root / relative / project
            database.mkdir(parents=True)
            (database / "codeql-database.yml").write_text("fixture metadata")
            (database / "src.zip").write_text("fixture source archive")

    def coverage(database: Path, *_args: Any) -> dict[str, Any]:
        if database.name == "test_0":
            raise ValueError("corrupt source archive")
        return {"ready": True, "coverage_ratio": 1.0}

    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    monkeypatch.setattr(readiness.subprocess, "check_output", lambda *_a, **_kw: "abc")
    monkeypatch.setattr(readiness, "_resolve_fixed_revision", lambda *_: "abc")
    monkeypatch.setattr(readiness, "source_coverage", coverage)
    monkeypatch.setattr(readiness, "require_coverage", coverage)
    report = readiness.inspect(root, config_path, root / "results/diagnostics/readiness", workers=3)
    assert report["status"] == "BLOCKED" and report["projects"] == 120
    assert report["ready"] == 119 and report["blocked"] == 1 and report["api_calls"] == 0
    rows = json.loads((root / "results/diagnostics/readiness/projects.json").read_text())[
        "projects"
    ]
    assert [row["project_id"] for row in rows] == selected
    assert next(row for row in rows if row["project_id"] == "test_0")["status"] == "BLOCKED"
    repaired = root / "results/diagnostics/repair"
    attempts = []

    def unrepairable(*args: Any, **_kwargs: Any) -> None:
        snapshot = json.loads((repaired / "projects.json").read_text())["projects"]
        assert len(snapshot) == 120
        assert all(row["status"] != "PENDING" for row in snapshot)
        attempts.append(args[2])
        raise RuntimeError("fixture extraction failure")

    monkeypatch.setattr(readiness, "extract", unrepairable)
    report = readiness.inspect(root, config_path, repaired, workers=3, repair=True)
    assert report["ready"] == 119 and report["blocked"] == 1
    assert attempts == ["test_0", "test_0"]


def test_readiness_retains_database_when_post_extraction_gate_raises(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.pipeline_v2 import readiness

    root, config, _ = benchmark_workspace
    config["benchmark"]["minimum_free_disk_gib"] = 0
    config["execution"]["minimum_application_source_coverage"] = 1.0
    source = root / config["fixed_preparation"]["source_root"] / "dev_0"
    source.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    toolchain = root / "configs/toolchains/cwe_bench_java.yaml"
    toolchain.parent.mkdir(parents=True)
    toolchain.write_text("{}")
    monkeypatch.setattr(readiness, "database_environment", lambda *_: ({}, {}))
    monkeypatch.setattr(readiness, "codeql", lambda *_: Path("/fixture/codeql"))
    monkeypatch.setattr(readiness, "_checkout_fixed_revision", lambda *_a, **_kw: (True, "fixture"))

    def create(_binary: Path, _checkout: Path, database: Path, *_a: Any, **_kw: Any) -> None:
        database.mkdir()
        (database / "src.zip").write_bytes(b"retained native extraction")

    def reject(*_a: Any, **_kw: Any) -> None:
        raise ValueError("supplemental model check not passed")

    monkeypatch.setattr(readiness, "create_complete_database", create)
    monkeypatch.setattr(readiness, "source_coverage", reject)
    destination = root / "data/interim/coverage-cache/fixed/dev_0"
    with pytest.raises(ValueError, match="supplemental model check not passed"):
        readiness.extract(root, config, "dev_0", {}, "abc", destination, root / "logs")
    assert not destination.exists()
    retained = list((destination.parent / "rejected/dev_0").glob("*/src.zip"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == b"retained native extraction"


def test_readiness_persists_peer_reuse_across_fresh_scans(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.pipeline_v2 import readiness

    root, config, config_path = benchmark_workspace
    selected = selection_ids(root, config)
    config["fixed_preparation"].update(
        coverage_cache_root="data/interim/coverage-cache", reuse_exact_revision_databases=True
    )
    config["execution"]["minimum_application_source_coverage"] = 1.0
    policy = root / "src/pipeline_v2/coverage.py"
    policy.parent.mkdir(parents=True)
    policy.write_text("fixture policy")
    labels = root / config["dataset"]["labels"]
    labels.parent.mkdir(parents=True, exist_ok=True)
    labels.write_text("project_id,fix_commit_ids\n" + "".join(f"{p},abc\n" for p in selected))
    config["dataset"]["labels_sha256"] = sha256_file(labels)
    config_path.write_text(yaml.safe_dump(config))
    cache = root / config["fixed_preparation"]["coverage_cache_root"]
    for side in ("vulnerable", "fixed"):
        for project in selected:
            database = cache / side / project
            database.mkdir(parents=True)
            (database / "codeql-database.yml").write_text("fixture metadata")
            (database / "src.zip").write_text("valid")
    stale = cache / "vulnerable/dev_0"
    (stale / "src.zip").write_text("stale")

    def coverage(database: Path, *_a: Any) -> dict[str, Any]:
        ready = (database / "src.zip").read_text() == "valid"
        return {"ready": ready, "coverage_ratio": 1.0 if ready else 0.0}

    def unexpected_extraction(*_a: Any, **_kw: Any) -> None:
        raise AssertionError("checked same-revision database must be reused")

    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    monkeypatch.setattr(readiness.subprocess, "check_output", lambda *_a, **_kw: "abc")
    monkeypatch.setattr(readiness, "_resolve_fixed_revision", lambda *_: "abc")
    monkeypatch.setattr(readiness, "source_coverage", coverage)
    monkeypatch.setattr(readiness, "require_coverage", coverage)
    monkeypatch.setattr(readiness, "extract", unexpected_extraction)
    initial = readiness.inspect(root, config_path, root / "results/diagnostics/initial", workers=1)
    assert initial["blocked"] == 1
    repaired = readiness.inspect(
        root, config_path, root / "results/diagnostics/repair", repair=True, workers=1
    )
    assert repaired["ready"] == 120
    assert stale.is_symlink()
    assert not (cache / "vulnerable/dev_1").is_symlink()
    assert (stale / "src.zip").read_text() == "valid"
    retained = list((cache / "vulnerable/rejected/dev_0").glob("peer-alias-*/src.zip"))
    assert len(retained) == 1 and retained[0].read_text() == "stale"
    final = readiness.inspect(root, config_path, root / "results/diagnostics/final", workers=1)
    assert final["status"] == "PASS" and final["ready"] == 120 and final["blocked"] == 0


def test_benchmark_cannot_claim_confirmatory_or_fit_test(benchmark_workspace: Any) -> None:
    root, config, _ = benchmark_workspace
    config["benchmark"]["confirmatory"] = True
    with pytest.raises(ValueError, match="diagnostic disposition"):
        selection_ids(root, config)
    config["benchmark"]["confirmatory"] = False
    config["benchmark"]["calibration_fit_scope"] = "all120"
    with pytest.raises(ValueError, match="development-only fitting"):
        selection_ids(root, config)


def test_readiness_excludes_concurrent_cache_writers_and_records_interruptions(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fcntl

    from src.pipeline_v2 import readiness

    root, config, config_path = benchmark_workspace
    config["fixed_preparation"]["coverage_cache_root"] = "data/interim/coverage-cache"
    config_path.write_text(yaml.safe_dump(config))
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    cache = root / config["fixed_preparation"]["coverage_cache_root"]
    cache.mkdir(parents=True)
    output = root / "results/diagnostics/interrupted"
    with (cache / ".readiness.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="another readiness process"):
            readiness.inspect(root, config_path, output)
    assert not output.exists()

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt("intentional test interruption")

    monkeypatch.setattr(readiness, "_inspect", interrupted)
    with pytest.raises(KeyboardInterrupt):
        readiness.inspect(root, config_path, output)
    lifecycle = json.loads((output / "lifecycle.json").read_text())
    assert lifecycle["status"] == "INTERRUPTED"
    assert lifecycle["started_at"] and lifecycle["finished_at"]
    assert not (cache / "coverage_manifest.json").exists()


@pytest.fixture
def transport_workspace(benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    root, old_config, old_path = benchmark_workspace
    selected = selection_ids(root, old_config)
    stage = Run(root, "results/p6", "seed", 6, old_path, selected)
    for project in selected:
        stage.status(project, "SUCCESS", "fixture")
    p6 = stage.finalize({})
    _, p6_lock = dependency(root, p6.relative_to(root).as_posix(), selected, 6)
    stage = Run(root, "results/p9", "seed", 9, old_path, selected)
    for project in selected:
        stage.status(project, "SUCCESS", "fixture")
    p9 = stage.finalize({})
    _, p9_lock = dependency(root, p9.relative_to(root).as_posix(), selected, 9)
    dependencies = {
        "phase6": p6_lock,
        "phase9": p9_lock,
        "baseline_id": "B9",
        "dry_run": False,
        "phase10_recovery": {},
    }
    seed = Run(root, "results/p10", "partial", 10, old_path, selected, dependencies=dependencies)
    seed.status("dev_0", "SUCCESS", "completed fixture")
    seed.status("dev_1", "ANALYSIS_FAILED", "rejected fixture")
    for project in ("dev_0", "dev_1", "dev_2"):
        directory = seed.work / "projects" / project
        atomic_jsonl(
            directory / "api_attempts.jsonl",
            [{"project_id": project, "request_estimate_tokens": 200, "outcome": "TRANSPORT_ERROR"}],
        )
        atomic_jsonl(directory / "plans.jsonl", [{"hypothesis_id": project, "status": "REJECTED"}])
        atomic_jsonl(directory / "responses.jsonl", [{"response": "preserved raw response"}])
        atomic_jsonl(directory / "specifications.jsonl", [{"specification_id": project}])
    atomic_jsonl(seed.work / "llm_calls.jsonl", [{"status": "SUCCESS", "project_id": "dev_0"}])
    snapshot = root / "results/pipeline_v2/benchmark_checkpoints/fixture"
    shutil.copytree(seed.work, snapshot)
    atomic_json(snapshot / "controller_manifest.json", {"run_id": "controller"})
    atomic_json(
        snapshot / "controller_steps.json",
        {
            "controller_p6": {
                "output": p6.relative_to(root).as_posix(),
                "status": "COMPLETE",
                "manifest_sha256": p6_lock["manifest_sha256"],
                "checksums_sha256": p6_lock["checksums_sha256"],
            }
        },
    )
    atomic_json(
        snapshot / "checkpoint_snapshot.json", {"kind": "unfinished_synthesis_checkpoint_only"}
    )
    write_checksums(snapshot)
    config = copy.deepcopy(old_config)
    config["execution"]["config_path"] = "configs/90.yaml"
    config["execution"]["llm_request_interval_seconds"] = 90
    config["execution"]["api_retry"]["cooldown_seconds"] = 90
    config["benchmark"]["transport_recovery"] = {
        "source_config": old_path.relative_to(root).as_posix(),
        "source_config_sha256": sha256_file(old_path),
        "checkpoint": snapshot.relative_to(root).as_posix(),
        "manifest_sha256": sha256_file(snapshot / "manifest.json"),
        "checksums_sha256": sha256_file(snapshot / "checksums.sha256"),
    }
    config_path = root / config["execution"]["config_path"]
    config_path.write_text(yaml.safe_dump(config))
    monkeypatch.setattr(benchmark_recovery, "compatible_synthesis", lambda *_: None)
    return root, config, config_path, snapshot, dependencies


def test_transport_recovery_preserves_terminal_states_and_budgets_on_resume(
    transport_workspace: Any,
) -> None:
    root, config, config_path, snapshot, dependencies = transport_workspace
    run = Run(
        root,
        "results/p10",
        "new",
        10,
        config_path,
        selection_ids(root, config),
        dependencies=dependencies,
    )
    assert run.statuses == read_jsonl(snapshot / "project_status.jsonl")
    assert len(run.pending()) == 118
    for relative in (
        "projects/dev_1/plans.jsonl",
        "projects/dev_2/responses.jsonl",
        "llm_calls.jsonl",
    ):
        assert (run.work / relative).read_bytes() == (snapshot / relative).read_bytes()
    reservations = run.work / "projects/dev_2/api_attempts.jsonl"
    records = read_jsonl(reservations)
    records.append({"project_id": "dev_2", "request_estimate_tokens": 300, "outcome": "SUCCESS"})
    atomic_jsonl(reservations, records)
    expected = reservations.read_bytes()
    Run(
        root,
        "results/p10",
        "new",
        10,
        config_path,
        selection_ids(root, config),
        dependencies=dependencies,
        resume=True,
    )
    assert reservations.read_bytes() == expected
    assert json.loads((run.work / "transport_recovery.json").read_text())["budget_reset"] is False


def test_transport_recovery_rejects_scientific_drift_and_snapshot_tampering(
    transport_workspace: Any,
) -> None:
    root, config, _, snapshot, _ = transport_workspace
    benchmark_recovery.checkpoint(root, config)
    changed = copy.deepcopy(config)
    changed["budget"]["max_calls_per_project"] += 1
    with pytest.raises(ValueError, match="only the registered"):
        benchmark_recovery.checkpoint(root, changed)
    changed = copy.deepcopy(config)
    changed["execution"]["llm_request_interval_seconds"] = 15
    with pytest.raises(ValueError, match="only the registered"):
        benchmark_recovery.checkpoint(root, changed)
    (snapshot / "projects/dev_1/plans.jsonl").write_text("[]\n")
    with pytest.raises(ValueError, match="checksum"):
        benchmark_recovery.checkpoint(root, config)


def test_transport_recovery_reuses_only_locked_completed_upstream(transport_workspace: Any) -> None:
    root, config, config_path, _, _ = transport_workspace
    controller = Run(
        root, "results/controller", "recovered", 0, config_path, selection_ids(root, config)
    )
    path = benchmark_recovery.reuse_stage(controller, "_p6", 6, controller.selected)
    steps = json.loads((controller.work / "steps.json").read_text())
    assert steps["controller_p6"]["output"] == path.relative_to(root).as_posix()
    assert steps["controller_p6"]["transport_recovery"]["checksums_sha256"]
    with pytest.raises(ValueError, match="upstream stage changed"):
        benchmark_recovery.reuse_stage(controller, "_p6", 6, ["dev_0"])


def test_paper_metric_denominators_path_dedup_and_no_file_fallback() -> None:
    truth = [{"file": "src/A.java", "method_start": "10", "method_end": "20"}]
    hit = [{"file": "/tmp/source/src/A.java", "line": 15}]
    miss = [{"file": "src/A.java", "line": 99}]
    rows = [
        path_metric("a", "SUCCESS", [hit, hit, miss], truth),
        path_metric("b", "SUCCESS", [], truth),
        path_metric("c", "ANALYSIS_FAILED", [hit], truth),
    ]
    result = paper_aggregate(rows)
    assert result["cases"] == 3 and result["detected"] == 1
    assert result["detection_rate"] == pytest.approx(1 / 3)
    assert result["paths"] == 2 and result["tp_paths"] == 1
    assert result["avg_fdr_denominator"] == 1 and result["avg_fdr"] == 0.5
    assert result["avg_f1"] == pytest.approx((2 / 3) / 3)
    unannotated = path_metric("d", "SUCCESS", [hit], [{"file": "src/A.java"}])
    assert not unannotated["detected"] and not unannotated["method_annotation_available"]
    assert paper_aggregate([rows[1]])["avg_fdr"] is None


def test_case_alignment_uses_case_identity_not_opaque_ids() -> None:
    a = {
        "project_id": "extended",
        "cve_id": "fixture_cve",
        "github_username": "a",
        "github_repository_name": "repo",
        "github_tag": "old",
        "buggy_commit_id": "before",
        "fix_commit_ids": "fix",
    }
    b = {**a, "project_id": "reproduction", "buggy_commit_id": "another"}
    result = case_alignment([a], [b])
    assert (
        result["same_case_population"] and result["different_declared_refs"]["buggy_commit_id"] == 1
    )
    with pytest.raises(ValueError, match="same cases"):
        case_alignment([a], [{**b, "cve_id": "different"}])
    with pytest.raises(ValueError, match="ambiguous"):
        case_alignment([a, a], [b])


def test_discovery_reuse_handles_already_inherited_records_and_is_idempotent(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, config, config_path = benchmark_workspace
    upstream = root / "results/p6/seed"
    lock = {
        "run_root": "results/p6/seed",
        "manifest_sha256": "manifest",
        "checksums_sha256": "checksums",
    }
    config["benchmark"]["phase6_seed"] = lock
    config_path.write_text(yaml.safe_dump(config))
    project = "dev_0"
    source = upstream / "projects" / project
    source.mkdir(parents=True)
    database = root / config["dataset"]["vulnerable_database_root"] / project
    database.mkdir(parents=True)
    (database / "src.zip").write_text("frozen archive")
    (database / "codeql-database.yml").write_text("frozen metadata")
    (source / "database_provenance.json").write_text(
        json.dumps(
            {
                "source_archive_sha256": sha256_file(database / "src.zip"),
                "database_metadata_sha256": sha256_file(database / "codeql-database.yml"),
            }
        )
    )
    atomic_jsonl(
        upstream / "project_status.jsonl",
        [
            {
                "project_id": project,
                "status": "SUCCESS",
                "reason": "prior inheritance",
                "inherited_from": {"run_root": "results/earlier/seed"},
                "hypotheses": 10,
            }
        ],
    )
    monkeypatch.setattr(benchmark_inputs, "configuration", lambda *_: config)
    monkeypatch.setattr(
        benchmark_inputs, "upstream_runs", lambda *_: {"phase6": {"path": upstream, "lock": lock}}
    )
    run = Run(root, "results/p6", "new", 6, config_path, [project])
    inherit_discovery(run)
    assert run.statuses[0]["inherited_from"] == lock
    assert run.statuses[0]["hypotheses"] == 10 and not run.pending()
    before = (run.work / "project_status.jsonl").read_bytes()
    inherit_discovery(run)
    assert (run.work / "project_status.jsonl").read_bytes() == before


def test_missing_database_build_uses_isolated_clean_revision_without_mutating_source(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, config, config_path = benchmark_workspace
    config["benchmark"]["minimum_free_disk_gib"] = 0
    config_path.write_text(yaml.safe_dump(config))
    selected = selection_ids(root, config)
    parent = root / config["benchmark"]["vulnerable_parent_roots"][0]
    for project in selected[1:]:
        database = parent / project
        database.mkdir(parents=True)
        (database / "codeql-database.yml").write_text("historical metadata")
        (database / "src.zip").write_text("historical archive")
    source = root / config["fixed_preparation"]["source_root"] / selected[0]
    source.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet"], cwd=source, check=True)
    java = source / "A.java"
    java.write_text("class A {}\n")
    subprocess.run(["git", "add", "A.java"], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "frozen",
        ],
        cwd=source,
        check=True,
    )
    java.write_text("class UncommittedChange {}\n")
    toolchain = root / "configs/toolchains/cwe_bench_java.yaml"
    toolchain.parent.mkdir(parents=True)
    toolchain.write_text("{}\n")
    monkeypatch.setattr(benchmark_inputs, "codeql", lambda *_: Path("/fixture/codeql"))
    monkeypatch.setattr(
        benchmark_inputs, "database_environment", lambda *_: ({}, {"jdk": "fixture"})
    )

    def extract(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        checkout = Path(kwargs["cwd"])
        assert checkout != source and (checkout / "A.java").read_text() == "class A {}\n"
        assert f"--source-root={checkout}" in command
        destination = Path(command[3])
        destination.mkdir()
        (destination / "codeql-database.yml").write_text("new metadata")
        (destination / "src.zip").write_text("new archive")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(benchmark_inputs, "_run_command", extract)
    move = benchmark_inputs.shutil.move

    def interrupt_move(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt("interrupted before database move")

    monkeypatch.setattr(benchmark_inputs.shutil, "move", interrupt_move)
    with pytest.raises(KeyboardInterrupt, match="before database move"):
        benchmark_inputs.prepare(root, config_path, "isolated")
    monkeypatch.setattr(benchmark_inputs.shutil, "move", move)
    final = benchmark_inputs.prepare(root, config_path, "isolated", resume=True)
    assert java.read_text() == "class UncommittedChange {}\n"
    statuses = read_jsonl(final / "project_status.jsonl")
    assert len(statuses) == 120 and all(r["status"] == "SUCCESS" for r in statuses)
    assert statuses[0]["checkout_method"] == "local" and statuses[0]["build_mode"] == "none"


@pytest.mark.parametrize("eligible", [True, False])
def test_calibration_fits_dev_only_and_applies_frozen_model_to_test(
    benchmark_workspace: Any,
    monkeypatch: pytest.MonkeyPatch,
    eligible: bool,
) -> None:
    root, config, config_path = benchmark_workspace
    selected = [f"dev_{i}" for i in range(10)] + ["test_0"]
    labels = root / config["dataset"]["labels"]
    labels.parent.mkdir(parents=True)
    labels.write_text(
        "project_id,ground_truth_cwe\n"
        + "".join(f"dev_{i},{'CWE-22' if i % 2 else 'CWE-78'}\n" for i in range(10))
        + "test_0,POISON_TEST_LABEL\n"
    )
    groups = root / config["dataset"]["split_groups"]
    groups.write_text(
        "project_id,repository_group,split\n"
        + "".join(f"dev_{i},group_{i},development\n" for i in range(10))
        + "test_0,POISON_TEST_GROUP,test_locked\n"
    )
    config["dataset"]["labels_sha256"] = sha256_file(labels)
    config["dataset"]["split_groups_sha256"] = sha256_file(groups)
    if not eligible:
        config["calibration"]["minimum_repository_groups"] = 999
    config_path.write_text(yaml.safe_dump(config))
    p6 = Run(root, "results/p6", "input", 6, config_path, selected)
    hypotheses = [{"project_id": p, "hypothesis_id": "hyp_" + p, "score": 0.7} for p in selected]
    atomic_jsonl(p6.work / "hypotheses.jsonl", hypotheses)
    for p in selected:
        p6.status(p, "SUCCESS", "fixture")
    p6_path = p6.finalize({})
    p10 = Run(root, "results/p10", "input", 10, config_path, selected)
    specs = [{"project_id": p, "specification_id": "spec_" + p} for p in selected]
    atomic_jsonl(p10.work / "specifications.jsonl", specs)
    for p in selected:
        p10.status(p, "SUCCESS", "fixture")
    p10_path = p10.finalize({})
    p11 = Run(root, "results/p11", "input", 11, config_path, selected)
    results = [
        {
            "project_id": p,
            "specification_id": "spec_" + p,
            "hypothesis_id": "hyp_" + p,
            "candidate_cwe": "CWE-22",
            "status": "VERIFIED_DIFFERENTIAL",
            "verification_version": "semantic-differential-verifier-v3",
            "vulnerable": {"paths": [[{"file": "src/A.java", "line": 10}]]},
        }
        for p in selected
    ]
    atomic_jsonl(p11.work / "verification_results.jsonl", results)
    for p in selected:
        p11.status(p, "SUCCESS", "fixture")
    p11_path = p11.finalize({})
    calls = []
    reader = calibration._development_rows

    def only_dev(path: Path, allowed: set[str]) -> dict[str, dict[str, str]]:
        calls.append(allowed)
        assert "test_0" not in allowed
        return reader(path, allowed)

    monkeypatch.setattr(calibration, "_development_rows", only_dev)
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    final = calibration.phase12(
        root,
        config,
        config_path,
        selected,
        "calibration",
        p6_path.relative_to(root).as_posix(),
        p10_path.relative_to(root).as_posix(),
        p11_path.relative_to(root).as_posix(),
    )
    fit = json.loads((final / "fit_scope.json").read_text())
    assert set(fit["selected_project_ids"]) == set(selected) - {"test_0"}
    assert fit["test_labels_used"] is False and len(calls) == 2
    rows = read_jsonl(final / "routing.jsonl")
    test_row = next(r for r in rows if r["project_id"] == "test_0")
    assert test_row["oof_candidate_cwe_probability"] is None
    assert (test_row["frozen_candidate_cwe_probability"] is not None) == eligible
    assert all(
        r["frozen_candidate_cwe_probability"] is None for r in rows if r["project_id"] != "test_0"
    )


def test_evaluator_exports_all120_and_resumes_without_excluding_failures(
    benchmark_workspace: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, config, config_path = benchmark_workspace
    selected = selection_ids(root, config)
    header = (
        "project_id,cve_id,github_username,github_repository_name,github_tag,"
        "buggy_commit_id,fix_commit_ids,ground_truth_cwe\n"
    )
    for key, prefix in (("labels", ""), ("reproduction_labels", "original_")):
        policy = config["dataset"] if key == "labels" else config["benchmark"]
        path = root / policy[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            header
            + "".join(f"{prefix}{p},cve_{p},owner,repo_{p},tag,bug,fix,CWE-22\n" for p in selected)
        )
        policy[key + "_sha256"] = sha256_file(path)
    policy = config["benchmark"]
    truth = root / policy["truth"]
    atomic_jsonl(
        truth,
        [
            {"project_id": p, "file": "A.java", "method_start": 1, "method_end": 20}
            for p in selected
        ],
    )
    policy["truth_sha256"] = sha256_file(truth)
    local = root / policy["local_baseline_table"]
    local.parent.mkdir(parents=True)
    local.write_text("baseline,detected\nB0,27\n")
    policy["local_baseline_table_sha256"] = sha256_file(local)
    config_path.write_text(yaml.safe_dump(config))
    p10, p11, p12 = [root / "results" / p for p in ("p10", "p11", "p12")]
    for path in (p10, p11, p12):
        path.mkdir(parents=True)
        (path / "manifest.json").write_text("{}")
    atomic_jsonl(
        p10 / "project_status.jsonl",
        [
            {"project_id": p, "status": "ANALYSIS_FAILED" if p == "dev_1" else "SUCCESS"}
            for p in selected
        ],
    )
    atomic_jsonl(
        p11 / "verification_results.jsonl",
        [
            {
                "project_id": p,
                "specification_id": "spec_" + p,
                "status": "VERIFIED_DIFFERENTIAL",
                "vulnerable": {
                    "query_completed": True,
                    "resolution_complete": True,
                    "paths": [[{"file": "A.java", "line": 10}]],
                },
            }
            for p in ("dev_0", "dev_1", "test_0")
        ],
    )
    atomic_jsonl(
        p12 / "routing.jsonl",
        [
            {"specification_id": "spec_" + p, "decision": "VERIFY"}
            for p in ("dev_0", "dev_1", "test_0")
        ],
    )
    monkeypatch.setattr(benchmark_evaluate, "validate_stages", lambda *args: {"status": "fixture"})
    with pytest.raises(ValueError, match="evaluator role"):
        benchmark_evaluate.evaluate(root, config_path, "export", p10, p11, p12)
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    finalize = Run.finalize

    def interrupted(*args: Any, **kwargs: Any) -> Path:
        raise RuntimeError("simulated interruption before finalize")

    monkeypatch.setattr(Run, "finalize", interrupted)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        benchmark_evaluate.evaluate(root, config_path, "export", p10, p11, p12)
    monkeypatch.setattr(Run, "finalize", finalize)
    final = benchmark_evaluate.evaluate(root, config_path, "export", p10, p11, p12, resume=True)
    metrics = json.loads((final / "metrics_paper_proxy.json").read_text())
    all120 = metrics["differential_verified/all120"]
    assert all120["cases"] == 120 and all120["analysis_successes"] == 119
    assert all120["detected"] == 2 and all120["avg_fdr_denominator"] == 2
    assert all120["avg_f1"] == pytest.approx(2 / 120)
    assert metrics["differential_verified/development96"]["cases"] == 96
    assert metrics["differential_verified/test24_diagnostic"]["cases"] == 24
    assert metrics["accept_only/all120"]["avg_fdr"] is None
    for variant in benchmark_evaluate.VARIANTS:
        assert {r["project_id"] for r in read_jsonl(final / f"{variant}_projects.jsonl")} == set(
            selected
        )
    manifest = json.loads((final / "manifest.json").read_text())
    assert manifest["data_access"].startswith("evaluator-only")
