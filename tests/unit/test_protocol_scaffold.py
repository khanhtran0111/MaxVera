from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_exactly_ten_numbered_baseline_entrypoints() -> None:
    scripts = sorted((REPO_ROOT / "scripts").glob("*.sh"))
    assert [path.name[:2] for path in scripts] == [f"{index:02d}" for index in range(1, 11)]


def test_baseline_matrix_and_configs_are_consistent() -> None:
    matrix_path = REPO_ROOT / "configs/baselines/matrix.yaml"
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    assert matrix["matrix_version"] == "1.2.3"
    assert set(matrix["entries"]) == {f"B{index}" for index in range(10)}
    for baseline_id, entry in matrix["entries"].items():
        config = yaml.safe_load((REPO_ROOT / entry["config"]).read_text(encoding="utf-8"))
        assert config["baseline_id"] == baseline_id


def test_main_protocol_is_draft_for_explicit_phase_blockers() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/main.yaml").read_text(encoding="utf-8")
    )
    assert config["protocol_version"] == "1.5.0"
    assert config["status"] == "draft"
    assert config["draft_blockers"]
    assert config["leakage_firewall"]["enabled"] is True


def test_upstream_pins_are_immutable_and_dockerfile_matches() -> None:
    pins = yaml.safe_load((REPO_ROOT / "configs/upstreams.yaml").read_text(encoding="utf-8"))
    assert len(pins["iris_reproduction"]["commit"]) == 40
    assert len(pins["cwe_bench_java"]["extended_commit"]) == 40
    assert len(pins["qwen"]["revision"]) == 40
    assert len(pins["qwen"]["sha256"]) == 64
    assert len(pins["iris_reproduction"]["codeql_artifact"]["sha256"]) == 64
    assert "pending" not in str(pins).lower()
    assert pins["codeql_main"]["cli_version"] == "2.26.2"
    assert pins["security_knowledge"]["mitre_cwe_version"] == "4.20"
    assert len(pins["security_knowledge"]["owasp_top10_commit"]) == 40
    digest = pins["container"]["digest"]
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert digest in dockerfile


def test_env_and_large_artifacts_are_ignored() -> None:
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignore
    assert "*.gguf" in ignore
    assert "/results/**" in ignore
