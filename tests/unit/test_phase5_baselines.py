from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.baselines.budget import estimate
from src.baselines.context import (
    SourceChunk,
    estimate_tokens,
    select_raw,
    select_text_rag,
    source_chunks,
    static_hypotheses,
)
from src.baselines.schema import findings_sarif, hypotheses_json_schema, parse_hypotheses
from src.baselines.validate import _selected_outcomes
from src.llm.prompts.phase5 import PROMPT_VERSION, repair_prompt

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_context_strategies_are_deterministic_and_distinct(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "a").mkdir(parents=True)
    (source / "b").mkdir(parents=True)
    (source / "a/A.java").write_text(
        "class A { void safe() { int number = 1; } }\n", encoding="utf-8"
    )
    (source / "b/B.java").write_text(
        "class B { void run(String command) throws Exception { "
        "Runtime.getRuntime().exec(command); } }\n",
        encoding="utf-8",
    )
    chunks = source_chunks(source, chunk_lines=20, overlap_lines=0, max_file_bytes=10000)
    assert [chunk.path for chunk in chunks] == ["a/A.java", "b/B.java"]
    raw = select_raw(chunks, estimate_tokens(chunks[0].serialize()))
    rag = select_text_rag(chunks, estimate_tokens(chunks[1].serialize()))
    assert raw[0].path == "a/A.java"
    assert rag[0].path == "b/B.java"


def test_static_hypothesis_has_location_and_canonical_cwe() -> None:
    chunks = [
        SourceChunk(
            "Example.java",
            10,
            10,
            'Runtime.getRuntime().exec(request.getParameter("cmd"));',
        )
    ]
    hypotheses = static_hypotheses(chunks, project_id="proj_test", top_k=10)
    assert hypotheses[0]["candidate_cwe"] == "CWE-78"
    assert hypotheses[0]["line"] == 10
    assert hypotheses[0]["rank"] == 1


def test_llm_schema_rejects_out_of_tree_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Good.java").write_text("class Good {}\n", encoding="utf-8")
    bad = json.dumps(
        {
            "hypotheses": [
                {
                    "candidate_cwe": "CWE-78",
                    "title": "test",
                    "file": "../Bad.java",
                    "line": 1,
                    "source_symbol": None,
                    "sink_symbol": "exec",
                    "evidence": [],
                    "confidence": 0.5,
                }
            ]
        }
    )
    with pytest.raises(ValueError, match="inside the project"):
        parse_hypotheses(
            bad,
            project_id="proj_test",
            source_root=source,
            top_k=10,
            generator="test",
        )


def test_valid_schema_converts_to_sarif(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Good.java").write_text("class Good {}\n", encoding="utf-8")
    response = json.dumps(
        {
            "hypotheses": [
                {
                    "candidate_cwe": "CWE-94",
                    "title": "dynamic evaluation",
                    "file": "Good.java",
                    "line": 1,
                    "source_symbol": "input",
                    "sink_symbol": "eval",
                    "evidence": ["class Good {}"],
                    "confidence": 0.7,
                }
            ]
        }
    )
    hypotheses = parse_hypotheses(
        response,
        project_id="proj_test",
        source_root=source,
        top_k=10,
        generator="test",
    )
    sarif = findings_sarif(hypotheses)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-94"  # type: ignore[index]


def test_phase5_configs_mark_only_immediately_runnable_entries() -> None:
    for baseline_id in ("b3", "b4", "b5"):
        path = next((REPO_ROOT / "configs/baselines").glob(f"{baseline_id}_*.yaml"))
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert config["status"] == "implemented_phase_5"
    for baseline_id in ("b6", "b7", "b8", "b9"):
        path = next((REPO_ROOT / "configs/baselines").glob(f"{baseline_id}_*.yaml"))
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert config["blocked_by"]


def test_phase5_llm_route_is_pinned_to_akashml() -> None:
    experiment = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase5_baselines.yaml").read_text(encoding="utf-8")
    )
    model = yaml.safe_load(
        (REPO_ROOT / "configs/models/gpt_oss_20b_openrouter.yaml").read_text(encoding="utf-8")
    )
    assert experiment["llm"]["provider_route"] == "akashml"
    assert model["provider_route"] == "akashml"
    for baseline_id in ("b3", "b4", "b6", "b7", "b8", "b9"):
        path = next((REPO_ROOT / "configs/baselines").glob(f"{baseline_id}_*.yaml"))
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert config["provider_route"] == "akashml"


def test_phase5_repair_prompt_reports_constraint_without_changing_task() -> None:
    prompt = repair_prompt(
        "reported source file does not exist: src/main/java/example/Missing.java"
    )
    assert PROMPT_VERSION == "phase5-zero-hint-v3"
    assert "src/main/java/example/Missing.java" in prompt
    assert "exactly from a `// FILE:` header" in prompt
    assert "empty hypotheses array is valid" in prompt


def test_structured_schema_restricts_file_to_supplied_context() -> None:
    schema = hypotheses_json_schema(
        ["src/test/Example.java", "src/main/App.java", "src/test/Example.java"],
        top_k=10,
    )
    hypotheses = schema["properties"]["hypotheses"]
    assert hypotheses["maxItems"] == 10
    assert hypotheses["items"]["properties"]["file"]["enum"] == [
        "src/main/App.java",
        "src/test/Example.java",
    ]
    assert hypotheses["items"]["additionalProperties"] is False


def test_budget_estimator_is_offline_and_covers_two_llm_baselines() -> None:
    result = estimate(
        REPO_ROOT,
        REPO_ROOT / "data/processed/analysis_input/D_repro_v1_projects.csv",
        input_price_per_million=None,
        output_price_per_million=None,
    )
    assert result["network_called"] is False
    assert result["projects"] == 120
    assert result["nominal_calls"] == 240
    assert result["provider_route"] == "akashml"
    assert result["nominal_cost_ceiling_usd"] == pytest.approx(0.088474)


def test_phase5_analysis_runner_does_not_reference_protected_view() -> None:
    runner = (REPO_ROOT / "src/baselines/runner.py").read_text(encoding="utf-8")
    protected = "evaluator" + "_only"
    assert protected not in runner


def test_validator_accepts_final_analysis_failure_as_recorded_miss() -> None:
    statuses = [
        {"project_id": "proj_success", "status": "SUCCESS"},
        {"project_id": "proj_failure", "status": "ANALYSIS_FAILED"},
    ]
    assert _selected_outcomes(statuses, {"proj_success", "proj_failure"}, "FAILED") == (
        1,
        1,
    )


def test_validator_rejects_inconsistent_run_status() -> None:
    statuses = [
        {"project_id": "proj_success", "status": "SUCCESS"},
        {"project_id": "proj_failure", "status": "ANALYSIS_FAILED"},
    ]
    with pytest.raises(ValueError, match="STATUS is SUCCESS"):
        _selected_outcomes(statuses, {"proj_success", "proj_failure"}, "SUCCESS")
    with pytest.raises(ValueError, match="STATUS is FAILED"):
        _selected_outcomes(statuses[:1], {"proj_success"}, "FAILED")
