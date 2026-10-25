"""Selected research cohorts fail before work when their inputs are incomplete."""

import json
import sys
from pathlib import Path

import pytest
import yaml

from maxvera.contracts import PipelineConfig, digest
from maxvera.dataset import select_cases


def prepared_source(root, case_id="opaque-1"):
    from maxvera.dataset import write_snapshot_manifest

    source = root / "data/processed/analysis_input/projects" / case_id
    source.mkdir(parents=True)
    (source / "App.java").write_text("class App {}\n")
    (source / "build.runtime.json").write_text(
        json.dumps({"attempts": [{"command": [sys.executable, "-V"], "environment": {}}]})
    )
    provenance = {
        "dataset_id": "D_extended",
        "dataset_revision": "a" * 40,
        "source_commit": "b" * 40,
        "build_patch_sha256": None,
        "preparation_policy": "pinned-git-archive-v1",
    }
    write_snapshot_manifest(source, case_id, provenance)
    return source


def config_fixture(root, count=2):
    (root / "cases.csv").write_text(
        "project_id,source_dir\n"
        + "".join(f"opaque-{i},projects/opaque-{i}\n" for i in range(1, count + 1))
    )
    path = root / "research.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "pipeline": "research",
                "dataset": {
                    "analysis_manifest": "cases.csv",
                    "expected_cases": count,
                    "expected_selected_cases": count,
                },
            }
        )
    )
    return path


def test_total_and_selected_coverage_are_distinct_and_checked_after_split(tmp_path):
    config_fixture(tmp_path, 3)
    (tmp_path / "split.csv").write_text("project_id\nopaque-1\nopaque-3\n")
    dataset = {
        "analysis_manifest": "cases.csv",
        "expected_cases": 3,
        "split": "split.csv",
        "expected_selected_cases": 3,
    }
    with pytest.raises(ValueError, match=r"selected.*coverage"):
        select_cases(tmp_path, dataset, "full")
    dataset["expected_selected_cases"] = 2
    assert [c["case_id"] for c in select_cases(tmp_path, dataset, "full")] == [
        "opaque-1",
        "opaque-3",
    ]
    assert len(select_cases(tmp_path, dataset, "smoke", 1)) == 1


def test_config_accepts_selected_coverage_and_validates_traversal_limit(tmp_path):
    config = config_fixture(tmp_path)
    raw = yaml.safe_load(config.read_text())
    raw["research"] = {"max_traversal_nodes": 12}
    config.write_text(yaml.safe_dump(raw))
    assert PipelineConfig.load(config).research["max_traversal_nodes"] == 12
    for invalid in (0, -1, True, 1.5):
        raw["research"]["max_traversal_nodes"] = invalid
        config.write_text(yaml.safe_dump(raw))
        with pytest.raises(ValueError, match="max_traversal_nodes"):
            PipelineConfig.load(config)


def test_input_preflight_collects_every_missing_or_malformed_case(tmp_path):
    from maxvera.preflight import input_preflight

    config = config_fixture(tmp_path, 3)
    prepared_source(tmp_path)
    broken = tmp_path / "data/processed/analysis_input/projects/opaque-2"
    broken.mkdir()
    (broken / "build.runtime.json").write_text('{"attempts": [{"command": "bad"}]}')
    cfg = PipelineConfig.load(config)
    report = input_preflight(tmp_path, select_cases(tmp_path, cfg.dataset, "full"))
    assert report["ready"] is False
    assert report["selected_cases"] == 3
    assert report["ready_cases"] == 1
    assert {row["case_id"] for row in report["cases"] if not row["ready"]} == {
        "opaque-2",
        "opaque-3",
    }
    assert "BUILD_RECIPE_INVALID" in {i["code"] for i in report["cases"][1]["issues"]}
    assert "SOURCE_MISSING" in {i["code"] for i in report["cases"][2]["issues"]}


def test_build_recipe_supports_audited_metadata_and_bounded_maven_options(tmp_path):
    from maxvera.preflight import build_recipe_issues

    build = {
        "attempts": [
            {
                "command": [sys.executable, "-V"],
                "environment": {"MAVEN_OPTS": "-Xmx1536m -Djava.net.preferIPv4Stack=true"},
            }
        ],
        "recipe": "canonical_maven_package_offline_pinned_dependencies",
        "dependencies": "pinned_generic_toolchain_cache_copied_into_private_workspace",
    }
    assert build_recipe_issues(tmp_path, build) == []
    build["attempts"][0]["environment"]["MAVEN_OPTS"] = "-javaagent:/tmp/untrusted.jar"
    assert {issue["code"] for issue in build_recipe_issues(tmp_path, build)} == {
        "BUILD_RECIPE_INVALID",
        "BUILD_TOOL_UNAVAILABLE",
    }


def test_input_preflight_rejects_tampering_and_legacy_without_overwrite(tmp_path):
    from maxvera.preflight import input_preflight

    source = prepared_source(tmp_path)
    case = {"case_id": "opaque-1", "source_dir": "projects/opaque-1"}
    original = (source / "snapshot.files.json").read_bytes()
    assert input_preflight(tmp_path, [case])["ready"] is True
    (source / "App.java").write_text("class Changed {}\n")
    assert input_preflight(tmp_path, [case])["ready"] is False
    assert (source / "snapshot.files.json").read_bytes() == original
    (source / "snapshot.files.json").unlink()
    assert "SNAPSHOT_MANIFEST_MISSING" in {
        issue["code"] for issue in input_preflight(tmp_path, [case])["cases"][0]["issues"]
    }
    assert not (source / "snapshot.files.json").exists()


def test_manifest_semantic_identity_excludes_recipe_but_integrity_checks_it(tmp_path):
    from maxvera.dataset import validate_snapshot_manifest, write_snapshot_manifest

    source = prepared_source(tmp_path)
    first = validate_snapshot_manifest(source, "opaque-1")
    recipe = source / "build.runtime.json"
    recipe.write_text(
        json.dumps({"attempts": [{"command": [sys.executable, "--version"], "environment": {}}]})
    )
    with pytest.raises(ValueError, match=r"snapshot.*(hash|inventory)"):
        validate_snapshot_manifest(source, "opaque-1")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_snapshot_manifest(source, "opaque-1", first["provenance"])
    (source / "snapshot.files.json").unlink()
    write_snapshot_manifest(source, "opaque-1", first["provenance"])
    second = validate_snapshot_manifest(source, "opaque-1")
    assert first["semantic_snapshot_id"] == second["semantic_snapshot_id"]
    assert digest(first["files"]) != digest(second["files"])


def test_verified_legacy_copy_requires_exact_proof_and_preserves_original(tmp_path):
    from maxvera.dataset import copy_verified_snapshot, validate_snapshot_manifest
    from maxvera.preflight import input_preflight
    from maxvera.snapshots import source_inventory

    source = prepared_source(tmp_path)
    (source / "snapshot.files.json").unlink()
    wrapper = source / "gradlew"
    wrapper.write_text("#!/bin/sh\nexit 0\n")
    wrapper.chmod(0o755)
    (source / "build.runtime.json").write_text(
        json.dumps(
            {
                "attempts": [
                    {"command": [str(wrapper)], "environment": {"PATH": str(source) + ":/usr/bin"}}
                ]
            }
        )
    )
    files = source_inventory(source)
    original = {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    target = tmp_path / "data/processed/analysis_input/readiness/projects/opaque-1"
    provenance = {
        "dataset_id": "D_extended",
        "dataset_revision": "a" * 40,
        "source_commit": "b" * 40,
        "build_patch_sha256": None,
        "preparation_policy": "audited-snapshot-copy-v1",
        "verification": {"kind": "audited-run-ingest", "artifact_sha256": "c" * 64},
    }
    with pytest.raises(ValueError, match="authoritative"):
        copy_verified_snapshot(source, target, "opaque-1", {"App.java": "d" * 64}, provenance)
    assert not target.exists()
    copy_verified_snapshot(source, target, "opaque-1", files, provenance)
    assert original == {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    assert (
        validate_snapshot_manifest(target, "opaque-1")["provenance"]["verification"]
        == provenance["verification"]
    )
    assert json.loads((target / "build.runtime.json").read_text())["attempts"][0]["command"] == [
        str(target / "gradlew")
    ]
    assert input_preflight(
        tmp_path, [{"case_id": "opaque-1", "source_dir": "readiness/projects/opaque-1"}]
    )["ready"]
    with pytest.raises(ValueError, match="refusing to overwrite"):
        copy_verified_snapshot(source, target, "opaque-1", files, provenance)


def test_preparation_is_atomic_reuses_valid_snapshots_and_continues_after_failure(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from maxvera.dataset import prepare

    cfg = SimpleNamespace(dataset_id="D_extended", revision="a" * 40)
    manifest = tmp_path / "data/processed/manifests/cwe_bench_extended.csv"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "project_id,project_slug,buggy_commit_id\n"
        + "".join(f"opaque-{i},project-{i},{'b' * 40}\n" for i in range(1, 4))
    )
    toolchain = tmp_path / "configs/toolchains/cwe_bench_java.yaml"
    toolchain.parent.mkdir(parents=True)
    toolchain.write_text("build_attempts: [{}]\n")
    monkeypatch.setattr("maxvera.dataset.load_dataset_config", lambda _: cfg)
    monkeypatch.setattr("maxvera.dataset.acquire_dataset", lambda *_: None)
    monkeypatch.setattr("maxvera.dataset.materialize_release", lambda *_, **__: {"metadata": True})
    monkeypatch.setattr("src.common.envfile.effective_env", lambda _: {})
    monkeypatch.setattr("src.data.build_projects._fetch_source", lambda *a, **k: (True, "ok", 0))
    monkeypatch.setattr(
        "src.data.build_projects.build_command_and_env", lambda *a: ([sys.executable, "-V"], {})
    )
    fail = {"opaque-2"}

    def archive(source, target, commit, patch):
        (target / "App.java").write_text("class App {}\n")
        if source.name in fail:
            raise ValueError("injected interrupted source preparation")

    monkeypatch.setattr("maxvera.dataset._archive_source", archive)
    first = prepare(tmp_path, tmp_path / "dataset.yaml", sources=True)["source_preparation"]
    assert (first["prepared"], first["failed"], first["ready"]) == (2, 1, False)
    projects = tmp_path / "data/processed/analysis_input/projects"
    assert not (projects / "opaque-2").exists()
    assert not list(projects.glob(".*.preparing-*"))
    immutable = (projects / "opaque-1/snapshot.files.json").read_bytes()
    fail.clear()
    second = prepare(tmp_path, tmp_path / "dataset.yaml", sources=True)["source_preparation"]
    assert (second["prepared"], second["reused"], second["ready"]) == (1, 2, True)
    assert (projects / "opaque-1/snapshot.files.json").read_bytes() == immutable
    (projects / "opaque-1/App.java").write_text("class Tampered {}\n")
    third = prepare(tmp_path, tmp_path / "dataset.yaml", sources=True)["source_preparation"]
    assert third["failed"] == 1 and third["reused"] == 2
    assert (projects / "opaque-1/App.java").read_text() == "class Tampered {}\n"


def test_execute_checks_entire_cohort_before_any_subprocess_or_run(tmp_path, monkeypatch, capsys):
    from maxvera.cli import main

    config = config_fixture(tmp_path)
    prepared_source(tmp_path)
    monkeypatch.setattr("maxvera.cli.subprocess.run", lambda *a, **k: pytest.fail("work started"))
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                str(config),
                "--mode",
                "full",
                "--run-id",
                "blocked",
                "--execute",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["input_preflight"]["selected_cases"] == 2
    assert report["input_preflight"]["ready"] is False
    assert not (tmp_path / "results").exists()


def test_dry_selection_and_standalone_preflight_report_readiness(tmp_path, capsys):
    from maxvera.cli import main

    config = config_fixture(tmp_path)
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                str(config),
                "--mode",
                "full",
                "--run-id",
                "dry",
                "--dry-run",
            ]
        )
        == 0
    )
    dry = json.loads(capsys.readouterr().out)
    assert dry["cases"] == 2 and dry["input_preflight"]["ready"] is False
    assert (
        main(["--root", str(tmp_path), "preflight", "--config", str(config), "--mode", "full"]) == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    assert report["input_preflight"]["selected_cases"] == 2
    assert not (tmp_path / "results").exists()


def test_readiness_requires_a_resolvable_truth_span(tmp_path):
    from maxvera.preflight import readiness_preflight

    cfg = PipelineConfig.load(config_fixture(tmp_path))
    protected = tmp_path / "data/processed/evaluator_only"
    protected.mkdir(parents=True)
    (protected / "D_repro_v1_labels.csv").write_text(
        "project_id,ground_truth_cwe\nopaque-1,CWE-22\nopaque-2,CWE-78\n"
    )
    (protected / "D_repro_v1_fix_locations.jsonl").write_text(
        json.dumps({"project_id": "opaque-1", "file": "App.java", "class_start": 1, "class_end": 4})
        + "\n"
        + json.dumps({"project_id": "opaque-2", "file": "Other.java"})
        + "\n"
    )
    report = readiness_preflight(
        tmp_path,
        cfg,
        select_cases(tmp_path, cfg.dataset, "full"),
        {"name": "graph_only", "llm_enabled": False},
        "full",
    )
    truth = report["ground_truth_coverage"]
    assert truth["ready"] is False
    assert truth["truth_cases"] == 1
    assert truth["missing_span_case_ids"] == ["opaque-2"]
    assert truth["missing_truth_case_ids"] == []


def test_frozen_profiles_select_exact_smoke_pilot_and_full_cohorts():
    root = Path(__file__).resolve().parents[2]
    for filename, expected in [
        ("research_smoke_random.yaml", 2),
        ("research_pilot10.yaml", 10),
        ("research_full120.yaml", 120),
    ]:
        cfg = PipelineConfig.load(root / "configs/pipelines" / filename)
        cases = select_cases(root, cfg.dataset, "full")
        assert len(cases) == expected
    dev = {
        r["case_id"]
        for r in select_cases(
            root, PipelineConfig.load(root / "configs/pipelines/research.yaml").dataset, "full"
        )
    }
    pilot = select_cases(
        root, PipelineConfig.load(root / "configs/pipelines/research_pilot10.yaml").dataset, "full"
    )
    assert {r["case_id"] for r in pilot} <= dev
