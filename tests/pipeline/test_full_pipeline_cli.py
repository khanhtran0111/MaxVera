"""Public full-cohort preparation and low-space execution accounting."""

import json
from types import SimpleNamespace

import pytest

from maxvera.cli import main
from maxvera.orchestration import Orchestrator, Stage
from src.reproduction.common import read_jsonl


def test_versioned_source_preparation_uses_trusted_cli_without_rematerializing(
    tmp_path, monkeypatch, capsys
):
    def prepare_sources(root, config, **options):
        assert root == tmp_path
        assert config == tmp_path / "dataset.yaml"
        assert options == {
            "view_name": "full-inputs",
            "reuse_manifest": tmp_path / "old.csv",
            "selected_ids": None,
            "timeout": 120,
            "offline": True,
            "min_free_gib": 21.0,
        }
        return {"ready": False, "requested": 120, "prepared": 119, "failed": 1}

    monkeypatch.setattr("maxvera.preparation.prepare_sources", prepare_sources)
    monkeypatch.setattr(
        "maxvera.dataset.prepare",
        lambda *a, **kw: pytest.fail("versioned preparation must preserve the frozen release"),
    )
    result = main(
        [
            "--root",
            str(tmp_path),
            "dataset",
            "prepare",
            "--config",
            "dataset.yaml",
            "--sources",
            "--view",
            "full-inputs",
            "--reuse-manifest",
            "old.csv",
            "--fetch-timeout",
            "120",
            "--offline",
            "--min-free-gib",
            "21",
        ]
    )
    assert result == 1
    assert json.loads(capsys.readouterr().out)["requested"] == 120


def test_versioned_source_options_require_sources_and_new_view(tmp_path, capsys):
    for options in (["--view", "new"], ["--sources", "--offline"]):
        result = main(
            ["--root", str(tmp_path), "dataset", "prepare", "--config", "missing.yaml", *options]
        )
        assert result == 2
        assert "require" in capsys.readouterr().err


def test_low_disk_records_every_case_without_starting_tools(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.disk_usage", lambda p: SimpleNamespace(free=1))
    actions = []

    def action(ctx):
        actions.append(ctx.case["case_id"])
        return {"artifacts": []}

    runner = Orchestrator(
        tmp_path,
        "research",
        "full-low-space",
        {"runtime": {"min_free_disk_gib": 20}},
        [{"case_id": f"opaque-{i}"} for i in range(120)],
        [Stage("ingest", action), Stage("analysis", action, ("ingest",))],
        implementation_hash="test-code",
    )
    assert runner.execute() == "COMPLETED_WITH_CASE_FAILURES"
    assert actions == []
    cases = read_jsonl(runner.path / "cases.jsonl")
    assert len(cases) == 120
    assert {row["status"] for row in cases} == {"RESOURCE_EXHAUSTED"}
    assert all(row["stages"]["analysis"] == "BLOCKED_BY_DEPENDENCY" for row in cases)


@pytest.mark.parametrize("value", [-1, True, float("nan"), float("inf")])
def test_runtime_disk_reserve_rejects_invalid_values(value):
    from maxvera.contracts import Runtime

    with pytest.raises(ValueError, match="disk"):
        Runtime(min_free_disk_gib=value)


def test_runtime_disk_reserve_is_resolved_and_zero_can_be_explicit():
    from maxvera.contracts import PipelineConfig, Runtime

    assert PipelineConfig("research").resolved()["runtime"]["min_free_disk_gib"] == 20
    assert Runtime(min_free_disk_gib=0).min_free_disk_gib == 0


def test_preflight_exit_can_require_execution_without_claiming_evaluation(
    tmp_path, monkeypatch, capsys
):
    import yaml

    (tmp_path / "cases.csv").write_text("project_id,source_dir\nopaque-1,projects/opaque-1\n")
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "pipeline": "research",
                "dataset": {"analysis_manifest": "cases.csv", "expected_cases": 1},
            }
        )
    )
    monkeypatch.setattr(
        "maxvera.preflight.readiness_preflight",
        lambda *args, **kwargs: {
            "ready": False,
            "execution_ready": True,
            "evaluation_ready": False,
            "scientific_approved": False,
        },
    )
    base = ["--root", str(tmp_path), "preflight", "--config", "config.yaml", "--mode", "full"]
    assert main([*base, "--require", "execution"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    assert report["evaluation_ready"] is False
    assert report["required_gate"] == "execution"
    assert main(base) == 1
    capsys.readouterr()
    assert main([*base, "--require", "evaluation"]) == 1
