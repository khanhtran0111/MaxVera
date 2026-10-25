"""Stage completion cannot hide incomplete reasoning or verification coverage."""

import json

import pytest
import yaml

from src.reproduction.common import atomic_json, atomic_jsonl


def quality_fixture(root, *, assessment="VALID", verification="NO_FLOW_FOUND"):
    config = {"selected_variant": {"llm_enabled": True, "targeted_verification": True}}
    (root / "config.resolved.yaml").write_text(yaml.safe_dump(config))
    case = {"case_id": "opaque"}
    atomic_jsonl(
        root / "cases.jsonl", [{**case, "status": "COMPLETED_WITH_FINDINGS", "stages": {}}]
    )
    stages = (
        "ingest",
        "static_extract",
        "build_graph",
        "candidate_generate",
        "candidate_rank",
        "evidence_retrieve",
        "llm_reason",
        "targeted_verify",
        "final_rank",
    )
    for name in stages:
        atomic_json(root / "stages/opaque" / name / "stage.json", {"status": "SUCCESS"})
    candidate = {
        "case_id": "opaque",
        "candidate_id": "candidate",
        "rank_pre_llm": 1,
        "decision": "REVIEW",
    }
    atomic_jsonl(root / "stages/opaque/candidate_rank/candidates_ranked.jsonl", [candidate])
    atomic_jsonl(
        root / "stages/opaque/evidence_retrieve/evidence_bundles.jsonl",
        [{"candidate_id": "candidate", "evidence_complete": True, "missing_evidence": []}],
    )
    atomic_jsonl(
        root / "stages/opaque/llm_reason/assessments.jsonl",
        [{"candidate_id": "candidate", "status": assessment}],
    )
    atomic_jsonl(
        root / "stages/opaque/targeted_verify/verification.jsonl",
        [{"candidate_id": "candidate", "status": verification, "is_safety_verdict": False}],
    )
    atomic_jsonl(
        root / "stages/opaque/final_rank/findings.jsonl",
        [{**candidate, "verification_status": verification, "rank_final": 1}],
    )
    return [case]


def test_valid_reasoning_and_no_flow_are_accounted_without_safety_claim(tmp_path):
    from maxvera.quality import write_quality_report

    cases = quality_fixture(tmp_path)
    before = (tmp_path / "stages/opaque/final_rank/findings.jsonl").read_bytes()
    report = write_quality_report(tmp_path, cases)
    assert report["engineering_pass"] is True
    assert report["verification_statuses"] == {"NO_FLOW_FOUND": 1}
    assert report["verification_supported_fraction"] == 1.0
    assert report["is_safety_verdict"] is False
    assert report["full120_ready"] is False
    assert (tmp_path / "stages/opaque/final_rank/findings.jsonl").read_bytes() == before
    assert json.loads((tmp_path / "quality_report.json").read_text()) == report


@pytest.mark.parametrize(
    "assessment", ["PROVIDER_FAILED", "INVALID_RESPONSE", "INCOMPLETE_EVIDENCE"]
)
def test_successful_stage_with_failed_assessment_fails_acceptance(tmp_path, assessment):
    from maxvera.quality import write_quality_report

    cases = quality_fixture(tmp_path, assessment=assessment)
    report = write_quality_report(tmp_path, cases)
    assert report["engineering_pass"] is False
    assert "LLM_ASSESSMENT_INCOMPLETE" in report["blockers"]
    assert report["retained_candidates"] == 1
    assert report["final_candidates"] == 1


def test_unsupported_verification_is_explicit_incomplete_coverage(tmp_path):
    from maxvera.quality import write_quality_report

    report = write_quality_report(
        tmp_path, quality_fixture(tmp_path, verification="UNSUPPORTED_SPEC")
    )
    assert report["engineering_pass"] is False
    assert report["verification_supported_fraction"] == 0.0
    assert "VERIFICATION_INCOMPLETE" in report["blockers"]


def test_discovery_truncation_blocks_acceptance(tmp_path):
    from maxvera.quality import write_quality_report

    cases = quality_fixture(tmp_path)
    atomic_json(
        tmp_path / "stages/opaque/candidate_generate/discovery_diagnostics.json",
        {"truncated_traversals": 1},
    )
    report = write_quality_report(tmp_path, cases)
    assert report["engineering_pass"] is False
    assert "DISCOVERY_TRUNCATED" in report["blockers"]


def test_research_finalizer_writes_quality_before_freezing(tmp_path):
    from maxvera.research import finalize

    cases = quality_fixture(tmp_path, assessment="INVALID_RESPONSE")
    finalize(tmp_path, cases)
    report = json.loads((tmp_path / "quality_report.json").read_text())
    assert report["engineering_pass"] is False
    assert "LLM_ASSESSMENT_INCOMPLETE" in report["blockers"]
    assert report["final_candidates"] == 1


def test_bounded_context_truncation_is_counted_with_complete_endpoints(tmp_path):
    from maxvera.quality import write_quality_report

    cases = quality_fixture(tmp_path)
    atomic_jsonl(
        tmp_path / "stages/opaque/evidence_retrieve/evidence_bundles.jsonl",
        [
            {
                "candidate_id": "candidate",
                "evidence_complete": True,
                "retrieval_truncated": True,
                "missing_evidence": [],
            }
        ],
    )
    report = write_quality_report(tmp_path, cases)
    assert report["retrieval_truncated_bundles"] == 1
    assert report["engineering_pass"] is True
