from __future__ import annotations

from pathlib import Path

from src.common.envfile import effective_env, initialize_env_file, parse_env_file


def test_initialize_env_preserves_values_and_adds_names(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("MAXVERA_CODEQL_HOME=/private/tool\n", encoding="utf-8")
    added = initialize_env_file(env_path, ("MAXVERA_CODEQL_HOME", "MAXVERA_MODEL_PATH"))
    assert added == ("MAXVERA_MODEL_PATH",)
    assert parse_env_file(env_path) == {
        "MAXVERA_CODEQL_HOME": "/private/tool",
        "MAXVERA_MODEL_PATH": "",
    }


def test_effective_env_process_value_overrides_file(monkeypatch, tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("MAXVERA_MODEL_PATH=/file/value\n", encoding="utf-8")
    monkeypatch.setenv("MAXVERA_MODEL_PATH", "/process/value")
    assert effective_env(env_path)["MAXVERA_MODEL_PATH"] == "/process/value"
