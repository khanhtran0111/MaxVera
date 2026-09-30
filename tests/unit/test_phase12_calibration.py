from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.calibration.model import (
    calibration_metrics,
    fit_isotonic,
    grouped_oof_predictions,
    predict,
    route,
    select_thresholds,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_phase12_config_pins_phase11_and_forbids_locked_test() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase12_calibration.yaml").read_text(
            encoding="utf-8"
        )
    )
    phase11 = config["development_dependencies"]["phase11"]
    assert config["protocol_version"] == "1.9.0"
    assert config["status"] == "frozen_phase_12_development"
    assert phase11["run_id"] == "p11_diff_dev_full_002"
    assert phase11["verification_results_sha256"] == (
        "12d6a882690eeaf65b9c984cbfe7936598a222c984a3f938d76f18a309d5e656"
    )
    assert config["dataset"]["locked_test_allowed"] is False
    assert config["label_policy"]["eligible_phase11_status"] == "VERIFIED_DIFFERENTIAL"
    assert config["label_policy"]["unverified_is_negative"] is False
    assert config["routing"]["abstain_is_negative"] is False
    assert sum(config["features"]["raw_score_weights"].values()) == pytest.approx(1.0)

    main = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/main.yaml").read_text(encoding="utf-8")
    )
    stage = main["development_stages"]["phase12_calibration_selective_routing"]
    assert main["protocol_version"] == "1.9.0"
    assert stage["status"] == "locked_for_phase13_experiments"
    assert stage["phase11_run_id"] == "p11_diff_dev_full_002"
    assert stage["locked_test_allowed"] is False
    assert stage["clean_pilot"]["run_id"] == "p12_calibration_pilot_003"
    assert stage["clean_pilot"]["run_git_dirty"] is False
    assert stage["clean_pilot"]["tau_accept"] == 1.0
    canonical = stage["canonical_run"]
    assert canonical["run_id"] == "p12_calibration_dev_full_001"
    assert canonical["run_git_dirty"] is False
    assert canonical["selected_model"] == "platt"
    assert canonical["thresholds"]["tau_accept"] == 1.0
    assert canonical["locked_test_used"] is False
    assert stage["next_gate"] == "phase13_full_experiments_ablation_and_robustness"


def test_isotonic_predictions_are_monotone() -> None:
    model = fit_isotonic([0.1, 0.2, 0.3, 0.4, 0.5], [0, 1, 0, 1, 1])
    predictions = [predict(model, {"raw_score": score}) for score in (0.1, 0.2, 0.3, 0.4, 0.5)]
    assert predictions == sorted(predictions)
    assert all(0.0 < probability < 1.0 for probability in predictions)


def test_grouped_oof_predictions_cover_each_row_without_self_fit() -> None:
    rows = [
        {"raw_score": 0.1, "signal": 0.0},
        {"raw_score": 0.2, "signal": 0.0},
        {"raw_score": 0.8, "signal": 1.0},
        {"raw_score": 0.9, "signal": 1.0},
    ]
    probabilities = grouped_oof_predictions(
        "platt",
        rows,
        [0, 0, 1, 1],
        ["a", "b", "c", "d"],
        ["signal"],
        {"l2": 0.05, "iterations": 100, "learning_rate": 0.1},
    )
    assert len(probabilities) == 4
    assert all(0.0 < probability < 1.0 for probability in probabilities)


def test_metrics_thresholds_and_routes_keep_abstention_separate() -> None:
    probabilities = [0.05, 0.1, 0.45, 0.7, 0.9, 0.95]
    labels = [0, 0, 0, 1, 1, 1]
    metrics = calibration_metrics(probabilities, labels, bins=3)
    thresholds = select_thresholds(
        probabilities,
        labels,
        target_accept_precision=1.0,
        target_verify_recall=1.0,
        max_abstain_risk=0.0,
        minimum_accept_count=2,
    )
    assert set(metrics) == {"brier", "ece_equal_width", "ece_equal_mass", "aurc"}
    assert 0.0 <= thresholds["tau_abstain"] <= thresholds["tau_verify"] <= thresholds[
        "tau_accept"
    ] <= 1.0
    decisions = [route(probability, thresholds) for probability in probabilities]
    assert "ACCEPT" in decisions
    assert "ABSTAIN" in decisions
