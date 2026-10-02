from __future__ import annotations

import copy
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.experiments import phase13_oracles, phase13_robustness
from src.experiments.phase13_audit import (
    archive_source,
    audit_finding,
    line_mapping,
    normalized_path,
)
from src.experiments.phase13_iris import check_budget
from src.experiments.phase13_report import paired_statistics
from src.experiments.phase13_statistics import holm, mcnemar, paired_bootstrap

ROOT = Path(__file__).resolve().parents[2]


def _archive(path: Path, text: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("temporary/source/src/Test.java", text)


def test_line_shift_is_not_evidence_of_removed_endpoint(tmp_path: Path) -> None:
    before, after = tmp_path / "before.zip", tmp_path / "after.zip"
    _archive(before, "class Test {\ninput();\noutput();\n}\n")
    _archive(after, "// new import\nclass Test {\ninput();\noutput();\n}\n")
    nodes = {
        "source": {
            "layer": "program",
            "properties": {"location": {"file": "src/Test.java", "start_line": 2, "end_line": 2}},
        },
        "sink": {"layer": "evidence", "properties": {"file": "src/Test.java", "line": 3}},
    }
    original = copy.deepcopy(nodes)
    spec = {"sources": [{"node_id": "source"}], "sinks": [{"node_id": "sink"}]}
    result = {
        "project_id": "p",
        "specification_id": "s",
        "candidate_cwe": "CWE-22",
        "status": "VERIFIED_DIFFERENTIAL",
        "fixed": {"source_endpoints": 0, "sink_endpoints": 0},
        "vulnerable": {
            "paths": [[{"file": "src/Test.java", "line": 2}, {"file": "src/Test.java", "line": 3}]]
        },
    }
    audit, mapped = audit_finding(result, spec, nodes, before, after)
    assert audit["audit_status"] == "LINE_SHIFT_CONFOUNDED"
    assert mapped["source"]["properties"]["location"]["start_line"] == 3
    assert mapped["sink"]["properties"]["line"] == 4
    assert nodes == original
    assert audit["canonical_verdict_changed"] is False


def test_changed_or_deleted_lines_are_not_guessed() -> None:
    assert 2 not in line_mapping(["start", "oldCall();", "end"], ["start", "newCall();", "end"])
    assert line_mapping(["a", "b"], ["insert", "a", "b"]) == {1: 2, 2: 3}


def test_source_archive_rejects_ambiguous_suffix_and_traversal(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("first/src/Test.java", "a")
        archive.writestr("second/src/Test.java", "b")
    with pytest.raises(ValueError, match="one match"):
        archive_source(path, "src/Test.java")
    with pytest.raises(ValueError, match="relative"):
        archive_source(path, "../Test.java")


def test_path_dedup_preserves_nonconsecutive_locations() -> None:
    path = [{"file": "a", "line": line} for line in [1, 1, 2, 2, 1]]
    assert normalized_path(path) == (("a", 1), ("a", 2), ("a", 1))


def test_paired_bootstrap_resamples_repositories_and_counts_failures_as_miss() -> None:
    left = {
        "a": {"status": "SUCCESS", "detected": True},
        "b": {"status": "SUCCESS", "detected": True},
        "c": {"status": "ANALYSIS_FAILED", "detected": True},
    }
    right = {p: {"status": "SUCCESS", "detected": False} for p in left}
    groups = {"a": "repo1", "b": "repo1", "c": "repo2"}
    result = paired_bootstrap(left, right, groups, samples=1000)
    assert result["effect_size"] == pytest.approx(2 / 3)
    assert result["repository_groups"] == 2
    assert (result["ci_lower"], result["ci_upper"]) == (0.0, 1.0)
    assert result == paired_bootstrap(left, right, groups, samples=1000)
    sensitivity = paired_bootstrap(left, right, groups, samples=100, successful_only=True)
    assert sensitivity["projects"] == 2 and sensitivity["effect_size"] == 1
    with pytest.raises(ValueError, match="coverage"):
        paired_bootstrap(left, {"a": right["a"]}, groups)


def test_exact_mcnemar_and_holm() -> None:
    assert mcnemar([True] * 6, [False] * 6)["p_value"] == 0.03125
    assert mcnemar([True, False], [True, False])["p_value"] == 1
    assert holm([0.04, 0.01, 0.03]) == pytest.approx([0.06, 0.03, 0.06])


def test_statistics_do_not_pool_different_positive_definitions() -> None:
    metrics = [
        {"baseline_id": b, "project_id": "p", "status": "SUCCESS", "detected": True}
        for b in ["B0", "B3", "B6", "B9"]
    ]
    results = paired_statistics(metrics, {"p": "repo"}, 10)
    assert {(r["left"], r["right"]) for r in results} == {("B0", "B3"), ("B6", "B9")}


def test_iris_budget_is_shared_across_provider_instances_and_checks_before_api() -> None:
    records = [{"status": "SUCCESS", "usage": {"prompt_tokens": 1}} for _ in range(30)]
    with pytest.raises(RuntimeError, match="call budget"):
        check_budget([{"role": "user", "content": "hello"}], records)
    with pytest.raises(RuntimeError, match="8192"):
        check_budget([{"role": "user", "content": "x" * 30000}], [])
    with pytest.raises(RuntimeError, match="input-token"):
        check_budget(
            [{"role": "user", "content": "hello"}],
            [{"status": "SUCCESS", "usage": {"prompt_tokens": 159990}}],
        )


def test_oracle_missing_databases_are_final_misses_and_artifact_is_reusable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    ids = [f"proj_{i}" for i in range(24)]
    parent = tmp_path / "results/phase13/test"
    parent.mkdir(parents=True)
    (parent / "analyzer_snapshot.json").write_text("{}")
    labels = tmp_path / "data/processed/evaluator_only"
    labels.mkdir(parents=True)
    (labels / "D_extended_labels.csv").write_text(
        "project_id,ground_truth_cwe\n" + "".join(f"{p},CWE-22\n" for p in ids)
    )
    (labels / "D_extended_fix_locations.jsonl").write_text("")
    source = tmp_path / "src/experiments"
    source.mkdir(parents=True)
    shutil.copyfile(ROOT / "src/experiments/phase13_oracles.py", source / "phase13_oracles.py")
    codeql = tmp_path / "codeql"
    codeql.touch()
    monkeypatch.setattr(
        phase13_oracles, "validate_snapshot", lambda *_: {"selected_project_ids": ids}
    )
    monkeypatch.setattr(phase13_oracles, "collect_git", lambda *_: {"dirty": False})
    monkeypatch.setattr(phase13_oracles, "collect_environment", lambda *_: {})
    monkeypatch.setattr(
        phase13_oracles, "effective_env", lambda *_: {"MAXVERA_CODEQL_HOME": str(codeql)}
    )
    monkeypatch.setattr(phase13_oracles, "_codeql_version", lambda *_: "2.26.2")

    def unexpected_command(*args: Any, **kwargs: Any) -> None:
        pytest.fail("missing DB must not invoke CodeQL or API")

    monkeypatch.setattr(phase13_oracles.subprocess, "run", unexpected_command)
    output = phase13_oracles.run(tmp_path, "test", "B1")
    summary = json.loads((output / "metrics_aggregate.json").read_text())
    assert summary["projects"] == 24 and summary["detected_projects"] == 0
    assert (output / "STATUS").read_text().strip() == "FAILED"
    assert phase13_oracles.run(tmp_path, "test", "B1") == output
    assert "PASS_WITH_ANALYSIS_FAILURES" in phase13_oracles.validate(output, tmp_path)
    (labels / "D_extended_labels.csv").write_text("tampered")
    with pytest.raises(ValueError, match="sealed input"):
        phase13_oracles.validate(output, tmp_path)


def test_robustness_selection_cannot_use_test_projects(tmp_path: Path) -> None:
    split = tmp_path / "data/processed/splits"
    split.mkdir(parents=True)
    (split / "development.csv").write_text("project_id\ndev\n")
    selection = tmp_path / "selection.json"
    selection.write_text(
        json.dumps(
            {"development_only": True, "selected_method": "B4", "selected_project_ids": ["test"]}
        )
    )
    with pytest.raises(ValueError, match="development split"):
        phase13_robustness.selection_lock(tmp_path, selection)


def test_robustness_changes_only_predeclared_seed(tmp_path: Path) -> None:
    models = tmp_path / "configs/models"
    models.mkdir(parents=True)
    original = yaml.safe_load((ROOT / "configs/models/gpt_oss_20b_openrouter.yaml").read_text())
    (models / "gpt_oss_20b_openrouter.yaml").write_text(yaml.safe_dump(original))
    parent = tmp_path / "parent/configs"
    parent.mkdir(parents=True)
    (parent / "phase10.yaml").write_text("llm:\n  model_config: old\nbudget: frozen\n")
    model_path, experiment = phase13_robustness.seed_configs(
        tmp_path, parent.parent, 2345, "B9", tmp_path / "seed2345"
    )
    changed = yaml.safe_load(model_path.read_text())
    assert changed == {**original, "seed": 2345}
    assert yaml.safe_load(experiment.read_text())["budget"] == "frozen"
