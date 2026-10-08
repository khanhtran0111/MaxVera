from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.common.provenance import sha256_file
from src.pipeline_v2 import benchmark_evaluate, benchmark_inputs, calibration, runtime
from src.pipeline_v2.benchmark_evaluate import case_alignment, paper_aggregate, path_metric
from src.pipeline_v2.benchmark_inputs import inherit_discovery
from src.pipeline_v2.runtime import Run, configuration, dependency, selection_ids
from src.reproduction.common import atomic_jsonl, read_jsonl


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


def test_benchmark_cannot_claim_confirmatory_or_fit_test(benchmark_workspace: Any) -> None:
    root, config, _ = benchmark_workspace
    config["benchmark"]["confirmatory"] = True
    with pytest.raises(ValueError, match="diagnostic disposition"):
        selection_ids(root, config)
    config["benchmark"]["confirmatory"] = False
    config["benchmark"]["calibration_fit_scope"] = "all120"
    with pytest.raises(ValueError, match="development-only fitting"):
        selection_ids(root, config)


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
