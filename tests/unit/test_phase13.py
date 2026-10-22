from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from src.common.analysis_scope import analysis_scope, selected_rows
from src.experiments.phase13 import AnalyzerPipeline, preflight

ROOT = Path(__file__).resolve().parents[2]


def test_phase13_preflight_keeps_evaluator_closed(tmp_path: Path) -> None:
    # A real lock/checksum fixture replaces dependence on deleted historical runs.
    import src.experiments.phase13 as legacy
    from src.common.provenance import sha256_file
    from src.reproduction.common import read_csv

    for name in (legacy.TEST_SPLIT, legacy.DEV_SPLIT, legacy.ANALYSIS_MANIFEST):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for row in read_csv(tmp_path / legacy.TEST_SPLIT):
        (tmp_path / legacy.SOURCE_ROOT / row["project_id"]).mkdir(parents=True)
    (tmp_path / legacy.PHASE8_RUN).mkdir(parents=True)
    run = tmp_path / "results/calibration/phase12/p12_calibration_dev_full_001"
    run.mkdir(parents=True)
    lock = {"run_id": "p12_calibration_dev_full_001"}
    for key, filename in [
        ("manifest_sha256", "manifest.json"),
        ("model_sha256", "model.json"),
        ("thresholds_sha256", "thresholds.json"),
        ("checksums_index_sha256", "checksums.sha256"),
    ]:
        (run / filename).write_text("fixture-only\n")
        lock[key] = sha256_file(run / filename)
    config = yaml.safe_load((ROOT / "configs/experiments/main.yaml").read_text())
    config["development_stages"]["phase12_calibration_selective_routing"]["canonical_run"] = lock
    target = tmp_path / "configs/experiments/main.yaml"
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(config))
    report = preflight(tmp_path)
    assert report["status"] == "READY_FOR_LONG_ANALYZER_RUN"
    assert report["locked_test_projects"] == 24
    assert report["evaluator_labels_opened"] is False
    assert report["phase12_run_id"] == "p12_calibration_dev_full_001"


def test_phase13_scope_selects_only_test_ids() -> None:
    config = {
        "analysis_scope": "test_locked",
        "dataset": {
            "analysis_manifest": "data/processed/analysis_input/D_extended_projects.csv",
            "analysis_split": "data/processed/splits/test_locked.csv",
            "holdout_split": "data/processed/splits/development.csv",
        },
    }
    rows, selected, holdout = selected_rows(ROOT, config)
    assert analysis_scope(config) == "test_locked"
    assert len(rows) == 24
    assert selected.endswith("test_locked.csv")
    assert holdout.endswith("development.csv")


def test_phase13_generated_phase6_config_is_label_free(tmp_path: Path) -> None:
    pipeline = AnalyzerPipeline(ROOT, "p13_unit_config", confirm_api_spend=False)
    pipeline.run_root = tmp_path
    pipeline.config_root = tmp_path / "configs"
    path = pipeline._phase6_config()
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    serialized = path.read_text(encoding="utf-8")
    assert config["status"] == "frozen_phase_13_test_analysis"
    assert config["analysis_scope"] == "test_locked"
    assert config["dataset"]["analysis_split"].endswith("test_locked.csv")
    assert "evaluator_only" not in serialized
    assert "ground_truth_cwe" not in serialized


def test_phase13_matrix_is_frozen() -> None:
    config = yaml.safe_load((ROOT / "configs/experiments/phase13.yaml").read_text(encoding="utf-8"))
    assert config["status"] == "analyzer_ready"
    assert list(config["matrix"]) == ["A0", "A1", "A2", "A3", "A4", "A5", "Full"]
    assert config["robustness"]["seeds"] == [1234, 2345, 3456, 4567, 5678]


def test_phase13_baselines_reject_setup_error_without_final_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs = tmp_path / "configs/experiments"
    configs.mkdir(parents=True)
    shutil.copyfile(
        ROOT / "configs/experiments/phase5_baselines.yaml", configs / "phase5_baselines.yaml"
    )
    pipeline = AnalyzerPipeline(tmp_path, "p13_setup_error", confirm_api_spend=True)
    (pipeline.analysis_root / "b0/p13_setup_error_b0").mkdir(parents=True)
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1)
    )
    with pytest.raises(ValueError, match="missing required outputs"):
        pipeline.controlled_baselines()
    assert not (pipeline.run_root / "analyzer_status.json").exists()
