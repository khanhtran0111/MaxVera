from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.hypotheses.budget import estimate
from src.hypotheses.evaluation import aggregate
from src.hypotheses.prepare import prepare_sources
from src.hypotheses.signals import generate_candidates, scan_project, select_top_k
from src.hypotheses.validate import _selected_outcomes
from src.llm.prompts.phase6 import parse_ranking, ranking_schema

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_phase6_signals_are_grounded_deterministic_and_hint_redacted(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        "public class Example {\n"
        "  public void run(Request request) {\n"
        '    new ProcessBuilder(request.getParameter("cmd")); // CWE-78 CVE-2020-1234\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    first = scan_project(source, project_id="proj_test", max_file_bytes=10000)
    second = scan_project(source, project_id="proj_test", max_file_bytes=10000)
    assert first == second
    assert {item["role"] for item in first} >= {"source", "sink", "boundary"}
    assert all("CVE-2020-1234" not in item["evidence"] for item in first)
    assert all("CWE-78" not in item["evidence"] for item in first)
    candidates = generate_candidates(
        first,
        project_id="proj_test",
        source_window_lines=120,
        sanitizer_window_lines=40,
        max_candidates=40,
    )
    assert candidates[0]["candidate_cwe"] == ["CWE-78"]
    assert candidates[0]["source_candidates"]
    assert candidates[0]["sink_candidates"][0]["line"] == 3
    assert candidates[0]["provenance"]
    assert select_top_k(candidates, 1)[0]["rank"] == 1


def test_phase6_rerank_schema_and_parser_require_exact_permutation() -> None:
    schema = ranking_schema(["hyp_a", "hyp_b"])
    ranked = schema["properties"]["ranked_hypothesis_ids"]
    assert ranked["minItems"] == ranked["maxItems"] == 2
    assert parse_ranking(
        json.dumps({"ranked_hypothesis_ids": ["hyp_b", "hyp_a"]}),
        ["hyp_a", "hyp_b"],
    ) == ["hyp_b", "hyp_a"]
    with pytest.raises(ValueError, match="every candidate"):
        parse_ranking(json.dumps({"ranked_hypothesis_ids": ["hyp_a"]}), ["hyp_a", "hyp_b"])


def test_phase6_failure_is_counted_as_zero_recall() -> None:
    rows = [
        {
            "status": "SUCCESS",
            "hypotheses": 2,
            "hypothesis_recall_at_10": True,
            "hypothesis_reciprocal_rank": 0.5,
        },
        {
            "status": "ANALYSIS_FAILED",
            "hypotheses": 0,
            "hypothesis_recall_at_10": False,
            "hypothesis_reciprocal_rank": 0.0,
        },
    ]
    result = aggregate(rows)
    assert result["projects"] == 2
    assert result["analysis_successes"] == 1
    assert result["hypothesis_recall_at_10"] == 0.5
    assert result["hypothesis_mrr"] == 0.25
    assert _selected_outcomes(rows, "FAILED") == (1, 1)


def test_phase6_source_preparation_uses_only_opaque_output_names(tmp_path: Path) -> None:
    source_manifest = tmp_path / "source.csv"
    target_manifest = tmp_path / "target.csv"
    _write_csv(
        source_manifest,
        [
            {
                "project_id": "proj_source",
                "project_slug": "owner__repo_release",
                "buggy_commit_id": "abc123",
            }
        ],
    )
    _write_csv(
        target_manifest,
        [
            {
                "project_id": "proj_target",
                "project_slug": "owner__repo_release",
                "buggy_commit_id": "abc123",
            }
        ],
    )
    existing = tmp_path / "data/interim/project_sources"
    (existing / "proj_source").mkdir(parents=True)
    target = tmp_path / "data/interim/phase6_project_sources"
    preparation_manifest = tmp_path / "data/interim/phase6_source_preparation.json"
    result = prepare_sources(
        tmp_path,
        source_manifest=source_manifest,
        target_manifest=target_manifest,
        existing_source_root=existing,
        target_source_root=target,
        preparation_manifest=preparation_manifest,
    )
    assert result["prepared_projects"] == 1
    assert (target / "proj_target").is_symlink()
    assert (target / "proj_target").resolve() == (existing / "proj_source").resolve()
    persisted = json.loads(preparation_manifest.read_text(encoding="utf-8"))
    assert persisted["identity_mapping_persisted"] is False
    assert "owner__repo_release" not in json.dumps(persisted)


def test_phase6_hybrid_budget_estimator_is_offline_and_development_only() -> None:
    result = estimate(
        REPO_ROOT,
        input_price_per_million=0.02,
        output_price_per_million=0.10,
    )
    assert result["network_called"] is False
    assert result["development_projects"] == 96
    assert result["maximum_successful_calls"] == 96
    assert result["cost_ceiling_usd"] == pytest.approx(0.02555904)


def test_phase6_analyzer_does_not_reference_protected_view() -> None:
    for relative in ("src/hypotheses/runner.py", "src/hypotheses/signals.py"):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        protected = "evaluator" + "_only"
        assert protected not in text
