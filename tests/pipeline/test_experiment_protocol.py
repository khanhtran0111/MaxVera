"""Exploratory execution is prospectively bound, never scientific approval."""

import json
import sys

import pytest
import yaml

from maxvera.contracts import PipelineConfig, digest
from maxvera.dataset import select_cases, write_snapshot_manifest
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_json, atomic_jsonl, write_checksums


def protocol_fixture(root):
    view = root / "data/processed/analysis_input"
    view.mkdir(parents=True)
    (view / "cases.csv").write_text("project_id,source_dir\nopaque-1,projects/opaque-1\n")
    source = view / "projects/opaque-1"
    source.mkdir(parents=True)
    (source / "App.java").write_text("class App {}\n")
    (source / "build.runtime.json").write_text(
        json.dumps({"attempts": [{"command": [sys.executable, "-V"], "environment": {}}]})
    )
    write_snapshot_manifest(
        source,
        "opaque-1",
        {
            "dataset_id": "D_extended",
            "dataset_revision": "a" * 40,
            "source_commit": "b" * 40,
            "build_patch_sha256": None,
            "preparation_policy": "pinned-git-archive-v1",
        },
    )
    profile = root / "configs/research.yaml"
    profile.parent.mkdir()
    profile.write_text(
        yaml.safe_dump(
            {
                "pipeline": "research",
                "dataset": {
                    "analysis_manifest": "data/processed/analysis_input/cases.csv",
                    "expected_cases": 1,
                },
                "research": {"graph_signal_approved": False},
            }
        )
    )
    for name in ("data/processed/splits/development.csv", "configs/pipelines/research_pilot10.csv"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("project_id\nopaque-1\n")
    paths = []
    for variant in ("static_only", "graph_only"):
        run = root / "results/research" / variant
        run.mkdir(parents=True)
        atomic_json(
            run / "manifest.json",
            {
                "pipeline": "research",
                "mode": "full",
                "case_ids": ["opaque-1"],
                "implementation_hash": "development-code",
                "input_hash": "paired-inputs",
            },
        )
        (run / "STATUS").write_text("COMPLETED\n")
        (run / "config.resolved.yaml").write_text(
            yaml.safe_dump(
                {
                    "selected_variant": {
                        "name": variant,
                        "llm_enabled": False,
                    }
                }
            )
        )
        write_checksums(run)
        output = root / "results/evaluations" / variant / "evaluation"
        output.mkdir(parents=True)
        from maxvera.evaluation import condition_manifest

        evaluator_identity = {"policy_version": "fixture-evaluator"}
        condition = condition_manifest(
            run,
            json.loads((run / "manifest.json").read_text()),
            yaml.safe_load((run / "config.resolved.yaml").read_text()),
            evaluator_identity,
            "labels-sha",
            "truth-sha",
            "zero_hint",
        )
        alignment_identity = {
            "policy_version": "vulnerable-source-alignment-v1",
            "mapping_sha256": None,
        }
        condition.update(
            {
                "missing_truth_policy": "report",
                "truth_alignment": alignment_identity,
                "aligned_source_identities": {"opaque-1": {}},
            }
        )
        atomic_json(
            output / "metrics_aggregate.json",
            {
                "panel": "zero_hint",
                "cases": 1,
                "case_ids": ["opaque-1"],
                "condition_manifest": condition,
                "condition_hash": digest(condition),
                "evaluable_subset": {"denominator": 1},
                "discovery_recall_at_k": None,
                "truth_coverage": {"alignment": {"cases": [{"case_id": "opaque-1"}]}},
            },
        )
        atomic_json(
            output / "evaluator_manifest.json",
            {
                "protocol": "zero_hint",
                "run_hash": sha256_file(run / "checksums.sha256"),
                "condition_hash": digest(condition),
                "evaluator_identity": evaluator_identity,
                "labels_hash": "labels-sha",
                "truth_hash": "truth-sha",
                "missing_truth_policy": "report",
                "truth_alignment": alignment_identity,
            },
        )
        atomic_jsonl(
            output / "metrics_per_case.jsonl",
            [{"case_id": "opaque-1", "ground_truth_evaluable": True}],
        )
        write_checksums(output)
        paths.append(output)
    config = PipelineConfig.load(profile)
    cases = select_cases(root, config.dataset, "full")
    variant = {"name": "graph_llm_verify", "llm_enabled": True}
    return config, cases, variant, paths, source


def test_registration_keeps_approval_false_and_binds_full_condition(tmp_path):
    from maxvera.experiments import register_experiment, validate_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    protocol = tmp_path / "protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="full-registered",
        output=protocol,
        development_evaluations=evaluations,
        rationale="Measure complete end-to-end behavior with explicit unknown truth.",
    )
    receipt = validate_experiment(
        tmp_path, config, variant, cases, run_id="full-registered", protocol=protocol
    )
    assert receipt["purpose"] == "exploratory_full_execution"
    assert receipt["scientific_approved"] is False
    assert config.research["graph_signal_approved"] is False
    assert json.loads(protocol.read_text())["unknown_truth_policy"] == "KEEP_COHORT_REPORT_NULL"
    with pytest.raises(ValueError, match="immutable"):
        register_experiment(
            tmp_path,
            config,
            variant,
            cases,
            run_id="full-registered",
            output=protocol,
            development_evaluations=evaluations,
            rationale="Do not overwrite a registered protocol.",
        )


@pytest.mark.parametrize("change", ["source", "budget", "run_id", "implementation"])
def test_execution_rejects_drift_after_registration(tmp_path, change):
    from maxvera.experiments import register_experiment, validate_experiment

    config, cases, variant, evaluations, source = protocol_fixture(tmp_path)
    protocol = tmp_path / "protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="full-registered",
        output=protocol,
        development_evaluations=evaluations,
        rationale="Frozen prospective execution for the complete configured cohort.",
    )
    run_id = "full-registered"
    if change == "source":
        (source / "App.java").write_text("class Changed {}\n")
    elif change == "budget":
        config = PipelineConfig("research", dataset=config.dataset, evidence={"top_k": [10]})
    elif change == "run_id":
        run_id = "another"
    else:
        package = tmp_path / "maxvera"
        package.mkdir()
        (package / "new.py").write_text("changed = True\n")
    with pytest.raises(ValueError, match=r"identity|input|snapshot"):
        validate_experiment(tmp_path, config, variant, cases, run_id=run_id, protocol=protocol)


def test_development_measurement_is_required_and_cannot_use_locked_cases(tmp_path):
    from maxvera.experiments import register_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    for paths in ([], evaluations):
        if paths:
            (tmp_path / "data/processed/splits/development.csv").write_text("project_id\nother\n")
        with pytest.raises(ValueError, match="development"):
            register_experiment(
                tmp_path,
                config,
                variant,
                cases,
                run_id="full-registered",
                output=tmp_path / "protocol.json",
                development_evaluations=paths,
                rationale="Explicit review of development evidence is mandatory.",
            )


def test_registration_rejects_posthoc_and_unpaired_measurements(tmp_path):
    from maxvera.experiments import register_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    args = dict(
        run_id="graph_only",
        output=tmp_path / "protocol.json",
        development_evaluations=evaluations,
        rationale="Prospective measurement only.",
    )
    with pytest.raises(ValueError, match=r"prospective|exists"):
        register_experiment(tmp_path, config, variant, cases, **args)
    args["run_id"] = "new-full"
    args["development_evaluations"] = [evaluations[0], evaluations[0]]
    with pytest.raises(ValueError, match=r"static_only|graph_only|paired"):
        register_experiment(tmp_path, config, variant, cases, **args)


def test_cli_registers_and_dry_runs_explicit_protocol_without_scientific_approval(
    tmp_path, monkeypatch, capsys
):
    from maxvera.cli import main

    _, _, variant, evaluations, _ = protocol_fixture(tmp_path)
    monkeypatch.setattr("maxvera.cli._variant", lambda *args: variant)
    protocol = tmp_path / "protocol.json"
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "experiment",
                "register",
                "--config",
                "configs/research.yaml",
                "--variant",
                "graph_llm_verify",
                "--run-id",
                "registered-cli",
                "--output",
                str(protocol),
                "--development-evaluations",
                *map(str, evaluations),
                "--rationale",
                "Measure the complete configured cohort and keep unknown truth explicit.",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                "configs/research.yaml",
                "--variant",
                "graph_llm_verify",
                "--mode",
                "full",
                "--run-id",
                "registered-cli",
                "--experiment-protocol",
                str(protocol),
                "--dry-run",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["config"]["experiment_protocol"]["scientific_approved"] is False
    assert output["config"]["research"]["graph_signal_approved"] is False
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                "configs/research.yaml",
                "--variant",
                "graph_llm_verify",
                "--mode",
                "full",
                "--run-id",
                "no-protocol",
                "--execute",
            ]
        )
        == 2
    )
    assert "reviewed" in capsys.readouterr().err


def test_registration_binds_actual_tool_binary_bytes(tmp_path):
    from maxvera.experiments import register_experiment, validate_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    tool = tmp_path / ".cache/codeql"
    tool.parent.mkdir()
    tool.write_text("pinned launcher bytes")
    config.codeql["research_binary"] = ".cache/codeql"
    protocol = tmp_path / "protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="full-registered",
        output=protocol,
        development_evaluations=evaluations,
        rationale="Freeze actual configured tool bytes before the full run.",
    )
    tool.write_text("different launcher bytes")
    with pytest.raises(ValueError, match="identity"):
        validate_experiment(
            tmp_path, config, variant, cases, run_id="full-registered", protocol=protocol
        )


@pytest.mark.parametrize("change", ["condition", "evaluable_count"])
def test_registration_rejects_aggregates_inconsistent_with_frozen_evaluator(tmp_path, change):
    from maxvera.experiments import register_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    for output in evaluations:
        path = output / "metrics_aggregate.json"
        metrics = json.loads(path.read_text())
        if change == "condition":
            metrics["condition_manifest"]["unrecorded_configuration"] = "fabricated"
            metrics["condition_hash"] = digest(metrics["condition_manifest"])
        else:
            metrics["evaluable_subset"]["denominator"] = 99
        atomic_json(path, metrics)
        write_checksums(output)
    with pytest.raises(ValueError, match=r"condition|evaluable"):
        register_experiment(
            tmp_path,
            config,
            variant,
            cases,
            run_id="full-registered",
            output=tmp_path / "protocol.json",
            development_evaluations=evaluations,
            rationale="Require development evaluation consistency with frozen raw runs.",
        )


def test_registration_binds_codeql_runtime_jar(tmp_path):
    from maxvera.experiments import register_experiment, validate_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    launcher = tmp_path / ".cache/codeql"
    jar = launcher.parent / "tools/codeql.jar"
    jar.parent.mkdir(parents=True)
    launcher.write_text("pinned launcher")
    jar.write_text("pinned runtime")
    config.codeql["research_binary"] = ".cache/codeql"
    protocol = tmp_path / "protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="full-registered",
        output=protocol,
        development_evaluations=evaluations,
        rationale="Pin the runtime behind the CodeQL launcher.",
    )
    jar.write_text("modified runtime")
    with pytest.raises(ValueError, match="identity"):
        validate_experiment(
            tmp_path, config, variant, cases, run_id="full-registered", protocol=protocol
        )


def test_registration_binds_effective_model_parameters_without_credentials(tmp_path, monkeypatch):
    from maxvera.experiments import register_experiment, validate_experiment

    config, cases, variant, evaluations, _ = protocol_fixture(tmp_path)
    model = tmp_path / "external-model.yaml"
    parameters = {
        "model_id": "openai/gpt-oss-20b",
        "provider_route": "groq",
        "max_output_tokens": 2048,
        "temperature": 0,
        "top_p": 1,
        "seed": 1,
        "reasoning_effort": "low",
        "timeout_seconds": 30,
        "max_retries": 0,
    }
    model.write_text(yaml.safe_dump(parameters))
    config.llm.update(
        {
            "model_config": str(model),
            "model": "openai/gpt-oss-20b",
            "provider_route": "groq",
            "max_output_tokens": 2048,
        }
    )
    monkeypatch.setenv("MAXVERA_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("MAXVERA_OPENROUTER_PROVIDER", "groq")
    monkeypatch.setenv("OPENROUTER_API_KEY", "fixture-private-credential")
    protocol = tmp_path / "protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="full-registered",
        output=protocol,
        development_evaluations=evaluations,
        rationale="Freeze model runtime values with no secret.",
    )
    assert "fixture-private-credential" not in protocol.read_text()
    assert '"api_key"' not in protocol.read_text()
    parameters["seed"] = 2
    model.write_text(yaml.safe_dump(parameters))
    with pytest.raises(ValueError, match="identity"):
        validate_experiment(
            tmp_path, config, variant, cases, run_id="full-registered", protocol=protocol
        )


def test_registration_binds_maven_boot_runtime(tmp_path):
    from maxvera.experiments import _runtime_inputs

    config, cases, _, _, source = protocol_fixture(tmp_path)
    home = tmp_path / ".cache/toolchains/maven"
    launcher, jar = home / "bin/mvn", home / "boot/classworlds.jar"
    launcher.parent.mkdir(parents=True)
    jar.parent.mkdir()
    launcher.write_text("launcher loads boot/classworlds.jar")
    jar.write_text("pinned classworlds")
    recipe = source / "build.runtime.json"
    recipe.write_text(json.dumps({"attempts": [{"command": [str(launcher)], "environment": {}}]}))
    before = _runtime_inputs(tmp_path, config, cases)
    jar.write_text("changed classworlds")
    assert _runtime_inputs(tmp_path, config, cases) != before


def test_actual_zero_hint_evaluations_can_register_a_prospective_experiment(tmp_path):
    import shutil

    from test_truth_alignment import frozen_source_stage

    from maxvera.evaluation import evaluate
    from maxvera.experiments import register_experiment
    from maxvera.orchestration import Orchestrator, Stage

    config, cases, variant, _old_evaluations, _ = protocol_fixture(tmp_path)
    labels, truth = tmp_path / "labels.csv", tmp_path / "truth.jsonl"
    labels.write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\nopaque-1,CWE-78," + "b" * 40 + "\n"
    )
    atomic_jsonl(
        truth,
        [
            {
                "project_id": "opaque-1",
                "file": "App.java",
                "method_start": 1,
                "method_end": 1,
                "commit": "b" * 40,
            }
        ],
    )

    def finalize(path, selected):
        for name in ("candidates_raw.jsonl", "candidates_pre_llm.jsonl", "findings.jsonl"):
            atomic_jsonl(path / name, [])

    evaluations = []
    for name in ("static_only", "graph_only"):
        shutil.rmtree(tmp_path / "results/research" / name)
        settings = config.resolved()
        settings["runtime"]["min_free_disk_gib"] = 0
        settings["selected_variant"] = {"name": name, "llm_enabled": False}
        runner = Orchestrator(
            tmp_path,
            "research",
            name,
            settings,
            cases,
            [Stage("ingest", frozen_source_stage), Stage("static_extract", frozen_source_stage)],
            implementation_hash="actual-evaluator-fixture",
            finalizer=finalize,
        )
        assert runner.execute() == "COMPLETED"
        evaluations.append(
            evaluate(
                tmp_path,
                runner.path,
                "zero_hint",
                labels=labels,
                truth=truth,
                missing_truth_policy="report",
            )
        )
    output = tmp_path / "genuine-protocol.json"
    register_experiment(
        tmp_path,
        config,
        variant,
        cases,
        run_id="genuine-full",
        output=output,
        development_evaluations=evaluations,
        rationale="Prospective protocol from actual evaluator outputs.",
    )
    assert output.is_file()
