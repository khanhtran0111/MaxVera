"""Analyzer-only acceptance accounting, separate from execution and label metrics."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import yaml

from src.reproduction.common import atomic_json, read_jsonl

STAGES = (
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
SUCCESS = {"SUCCESS", "SKIPPED_BY_VARIANT"}
SUPPORTED_VERIFICATIONS = {"FLOW_FOUND", "NO_FLOW_FOUND"}


def _json(path: Path) -> dict:
    return json.loads(path.read_text()) if path.is_file() else {}


def _same_ids(records: list[dict], ids: list[str]) -> bool:
    observed = [row.get("candidate_id") for row in records]
    return (
        len(observed) == len(ids)
        and len(set(observed)) == len(observed)
        and set(observed) == set(ids)
    )


def write_quality_report(path: Path, cases: list[dict]) -> dict:
    """Account for all selected cases without changing candidates or safety claims.

    Engineering acceptance requires complete work in the selected cohort. It is
    deliberately stricter than stage execution success and cannot approve a full
    benchmark or the separate reviewed development-signal gate.
    """
    config_path = path / "config.resolved.yaml"
    config = yaml.safe_load(config_path.read_text()) if config_path.is_file() else {}
    variant = config.get("selected_variant", {})
    llm_enabled = variant.get("llm_enabled", False)
    verification_enabled = variant.get("targeted_verification", False)
    summaries, blockers = [], set()
    assessment_totals, verification_totals = Counter(), Counter()
    for case in cases:
        base = path / "stages" / case["case_id"]
        reasons = set()
        stage_statuses = {
            name: _json(base / name / "stage.json").get("status", "MISSING") for name in STAGES
        }
        if any(status not in SUCCESS for status in stage_statuses.values()):
            reasons.add("STAGE_INCOMPLETE")
        retained = read_jsonl(base / "candidate_rank/candidates_ranked.jsonl")
        ids = [row["candidate_id"] for row in retained]
        findings = read_jsonl(base / "final_rank/findings.jsonl")
        if len(set(ids)) != len(ids) or not _same_ids(findings, ids):
            reasons.add("CANDIDATE_ACCOUNTING_MISMATCH")
        discovery = _json(base / "candidate_generate/discovery_diagnostics.json")
        if discovery.get("truncated_traversals", 0) or discovery.get("cap_reached", False):
            reasons.add("DISCOVERY_TRUNCATED")
        bundles = read_jsonl(base / "evidence_retrieve/evidence_bundles.jsonl")
        incomplete_evidence = sum(
            row.get("evidence_complete") is not True or bool(row.get("missing_evidence"))
            for row in bundles
        )
        context_truncations = sum(bool(row.get("retrieval_truncated")) for row in bundles)
        assessments = read_jsonl(base / "llm_reason/assessments.jsonl")
        assessment_statuses = Counter(row.get("status", "MISSING") for row in assessments)
        if llm_enabled:
            if not _same_ids(bundles, ids) or incomplete_evidence:
                reasons.add("EVIDENCE_INCOMPLETE")
            if not _same_ids(assessments, ids) or any(
                row.get("status") != "VALID" for row in assessments
            ):
                reasons.add("LLM_ASSESSMENT_INCOMPLETE")
        verifications = read_jsonl(base / "targeted_verify/verification.jsonl")
        verification_statuses = Counter(row.get("status", "MISSING") for row in verifications)
        supported = sum(verification_statuses[s] for s in SUPPORTED_VERIFICATIONS)
        if verification_enabled and (not _same_ids(verifications, ids) or supported != len(ids)):
            reasons.add("VERIFICATION_INCOMPLETE")
        if not ids:
            # An empty pool is an observed result, never evidence of discovery quality.
            reasons.add("EMPTY_CANDIDATE_POOL")
        assessment_totals.update(assessment_statuses)
        verification_totals.update(verification_statuses)
        blockers.update(reasons)
        summaries.append(
            {
                "case_id": case["case_id"],
                "engineering_pass": not reasons,
                "blockers": sorted(reasons),
                "stage_statuses": stage_statuses,
                "retained_candidates": len(ids),
                "final_candidates": len(findings),
                "incomplete_evidence_bundles": incomplete_evidence,
                "retrieval_truncated_bundles": context_truncations,
                "assessment_statuses": dict(assessment_statuses),
                "verification_statuses": dict(verification_statuses),
                "verification_supported_fraction": supported / len(ids)
                if verification_enabled and ids
                else None,
                "discovery_diagnostics": discovery,
                "static_signal_scope": _json(base / "candidate_generate/static_signal_scope.json"),
            }
        )
    expected_ids = [case["case_id"] for case in cases]
    if not cases or len(set(expected_ids)) != len(expected_ids):
        blockers.add("CASE_ACCOUNTING_MISMATCH")
    total = sum(row["retained_candidates"] for row in summaries)
    report = {
        "schema_version": "1.0",
        "acceptance_scope": "SELECTED_COHORT_ENGINEERING_ONLY",
        "selected_cases": len(cases),
        "case_ids": expected_ids,
        "engineering_pass": not blockers,
        "blockers": sorted(blockers),
        "retained_candidates": total,
        "final_candidates": sum(row["final_candidates"] for row in summaries),
        "retrieval_truncated_bundles": sum(row["retrieval_truncated_bundles"] for row in summaries),
        "assessment_statuses": dict(assessment_totals),
        "verification_statuses": dict(verification_totals),
        "verification_supported_fraction": sum(
            verification_totals[status] for status in SUPPORTED_VERIFICATIONS
        )
        / total
        if verification_enabled and total
        else None,
        "graph_signal_approved": config.get("research", {}).get("graph_signal_approved") is True,
        "full120_ready": False,
        "full120_readiness_note": "Requires separate complete-input, truth-coverage and reviewed "
        "development-signal gates; execution completion alone never grants approval.",
        "is_safety_verdict": False,
        "cases": summaries,
    }
    atomic_json(path / "quality_report.json", report)
    return report
