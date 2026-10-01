from __future__ import annotations

import json
from pathlib import Path

from src.common.preflight import run_preflight
from src.common.provenance import atomic_write_json

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_local_preflight_is_secret_safe(monkeypatch, tmp_path: Path) -> None:
    secret = "must-not-enter-report"
    monkeypatch.setenv("MAXVERA_API_TOKEN", secret)
    env_path = tmp_path / ".env"
    env_path.write_text(f"MAXVERA_MODEL_PATH={tmp_path / 'model.gguf'}\n", encoding="utf-8")
    report = run_preflight(REPO_ROOT, "local", env_path)
    serialized = json.dumps(report)
    assert secret not in serialized
    assert str(tmp_path) not in serialized
    assert report["privacy"] == {
        "environment_values_recorded": False,
        "configured_paths_recorded": False,
        "secret_scan_passed": True,
    }
    output = tmp_path / "environment.json"
    atomic_write_json(output, report)
    assert secret not in output.read_text(encoding="utf-8")
