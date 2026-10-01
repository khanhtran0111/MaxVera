from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.common.provenance import sha256_file
from src.experiments.phase13_evaluator import _metric, proxy_metrics
from src.experiments.phase13_snapshot import run_roots, validate_snapshot
from src.verification.prepare_fixed import _selected_rows, build_parser
from src.verification.runner import _fixed_database_status, _validate_config, run

ROOT = Path(__file__).resolve().parents[2]


def _test_config() -> dict[str, object]:
    config: dict[str, object] = yaml.safe_load(
        (ROOT / "configs/experiments/phase11_static_verification.yaml").read_text()
    )
    config.update(
        {
            "analysis_scope": "test_locked",
            "protocol_version": "1.9.0",
            "status": "frozen_phase_13_test_verification",
            "analyzer_snapshot": "results/phase13/test/analyzer_snapshot.json",
            "analyzer_snapshot_sha256": "a" * 64,
        }
    )
    return config


def test_test_verification_requires_snapshot_and_keeps_development_scope() -> None:
    config = _test_config()
    _validate_config(config)
    config.pop("analyzer_snapshot_sha256")
    with pytest.raises(ValueError, match="sealed analyzer snapshot"):
        _validate_config(config)
    config = _test_config()
    config["analysis_scope"] = "development"
    with pytest.raises(ValueError, match="scope/protocol"):
        _validate_config(config)


def test_test_verification_requires_evaluator_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.verification.runner import build_parser as verification_parser

    config_path = tmp_path / "verification.yaml"
    config_path.write_text(yaml.safe_dump(_test_config()))
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "analyzer")
    args = verification_parser().parse_args(
        [
            "--repo-root",
            str(tmp_path),
            "--config",
            str(config_path),
            "--run-id",
            "test",
        ]
    )
    with pytest.raises(RuntimeError, match="evaluator"):
        run(args)
    assert not (tmp_path / "results").exists()


def test_metrics_do_not_open_labels_before_snapshot_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAXVERA_DATA_ROLE", "evaluator")
    with pytest.raises(FileNotFoundError, match="snapshot"):
        proxy_metrics(tmp_path, tmp_path / "missing_snapshot.json", tmp_path / "metrics")
    assert not (tmp_path / "metrics").exists()


def test_failed_projects_cannot_contribute_partial_alerts() -> None:
    row = _metric("failed", "ANALYSIS_FAILED", 9, 3)
    assert row["alerts"] == row["tp_alerts"] == 0
    assert row["detected"] is False


def test_test_fixed_databases_cannot_be_used_as_development(tmp_path: Path) -> None:
    status_path = tmp_path / "build_status.jsonl"
    status_path.write_text('{"project_id":"p","status":"CODEQL_DB_FAILED"}\n')
    snapshot_sha = "a" * 64
    manifest = {
        "development_only": False,
        "locked_test_prepared": True,
        "identity_mapping_persisted": False,
        "analysis_scope": "test_locked",
        "analyzer_snapshot_sha256": snapshot_sha,
        "status_sha256": sha256_file(status_path),
    }
    (tmp_path / "preparation_manifest.json").write_text(json.dumps(manifest))
    statuses = [{"project_id": "p", "status": "SUCCESS"}]
    with pytest.raises(ValueError, match="scope contract"):
        _fixed_database_status(tmp_path, ["p"], statuses)
    checked = _fixed_database_status(tmp_path, ["p"], statuses, "test_locked", snapshot_sha)
    assert checked["unavailable_databases"] == 1
    with pytest.raises(ValueError, match="scope contract"):
        _fixed_database_status(tmp_path, ["p"], statuses, "test_locked", "b" * 64)


def test_fixed_preparation_selects_only_successful_test_projects(tmp_path: Path) -> None:
    splits = tmp_path / "data/processed/splits"
    splits.mkdir(parents=True)
    (splits / "development.csv").write_text("project_id\ndev\n")
    (splits / "test_locked.csv").write_text("project_id\ntest_ok\ntest_failed\n")
    labels = tmp_path / "data/processed/evaluator_only"
    labels.mkdir()
    (labels / "D_extended_labels.csv").write_text(
        "project_id,fix_commit_ids\ndev,devfix\ntest_ok,testfix\ntest_failed,failedfix\n"
    )
    analysis = tmp_path / "data/processed/analysis_input"
    analysis.mkdir()
    (analysis / "D_extended_projects.csv").write_text("project_id\ndev\ntest_ok\ntest_failed\n")
    run_root = tmp_path / "specifications"
    run_root.mkdir()
    (run_root / "project_status.jsonl").write_text(
        '{"project_id":"dev","status":"SUCCESS"}\n'
        '{"project_id":"test_ok","status":"SUCCESS"}\n'
        '{"project_id":"test_failed","status":"ANALYSIS_FAILED"}\n'
    )
    config = {
        "analysis_scope": "test_locked",
        "development_dependencies": {"phase10": {"run_root": "specifications"}},
    }
    rows = _selected_rows(tmp_path, build_parser().parse_args([]), config)
    assert [row["project_id"] for row in rows] == ["test_ok"]
    assert rows[0]["fix_commit_ids"] == "testfix"


def test_snapshot_rejects_path_traversal_run_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="run ID"):
        run_roots(tmp_path, "../../outside")


def test_snapshot_rejects_unsealed_state(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text('{"status":"RUNNING"}')
    with pytest.raises(ValueError, match="snapshot contract"):
        validate_snapshot(tmp_path, path)
