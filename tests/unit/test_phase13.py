from __future__ import annotations

from pathlib import Path

import yaml

from src.common.analysis_scope import analysis_scope, selected_rows
from src.experiments.phase13 import AnalyzerPipeline, preflight

ROOT = Path(__file__).resolve().parents[2]


def test_phase13_preflight_keeps_evaluator_closed() -> None:
    report = preflight(ROOT)
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
    config = yaml.safe_load(
        (ROOT / "configs/experiments/phase13.yaml").read_text(encoding="utf-8")
    )
    assert config["status"] == "analyzer_ready"
    assert list(config["matrix"]) == ["A0", "A1", "A2", "A3", "A4", "A5", "Full"]
    assert config["robustness"]["seeds"] == [1234, 2345, 3456, 4567, 5678]
