"""Incomplete research truth must never shrink the cohort or become negatives."""

import json

import pytest

from maxvera.orchestration import Orchestrator, Stage
from src.reproduction.common import atomic_jsonl, read_jsonl


def truth_fixture(root, *, span=True, run_id="truth120"):
    from test_truth_alignment import COMMIT, frozen_source_stage, source_fixture

    ids = [f"opaque-{i:03}" for i in range(120)]
    for cid in ids:
        source_fixture(root, cid)

    def finish(path, cases):
        for name in ("candidates_raw.jsonl", "candidates_pre_llm.jsonl", "findings.jsonl"):
            atomic_jsonl(path / name, [])

    run = Orchestrator(
        root,
        "research",
        run_id,
        {"evidence": {"top_k": [5]}, "selected_variant": {"llm_enabled": False}},
        [{"case_id": cid} for cid in ids],
        [Stage("ingest", frozen_source_stage), Stage("static_extract", frozen_source_stage)],
        mode="full",
        implementation_hash="fixture",
        finalizer=finish,
    )
    assert run.execute() == "COMPLETED"
    labels = root / "labels.csv"
    labels.write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\n"
        + "".join(f"{cid},CWE-78,{COMMIT}\n" for cid in ids)
    )
    truth = root / "truth.jsonl"
    atomic_jsonl(
        truth,
        [
            {
                "project_id": cid,
                "file": "App.java",
                "commit": COMMIT,
                **({"method_start": 2, "method_end": 5} if span else {}),
            }
            for cid in ids[:113]
        ],
    )
    return run.path, labels, truth, ids


def test_report_policy_preserves_120_and_distinguishes_seven_unknown_cases(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth, ids = truth_fixture(tmp_path)
    before = (run / "checksums.sha256").read_bytes()
    output = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, missing_truth_policy="report"
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    rows = read_jsonl(output / "metrics_per_case.jsonl")
    assert metrics["cases"] == 120
    assert {row["case_id"] for row in rows} == set(ids)
    assert metrics["truth_coverage"]["evaluable_cases"] == 113
    assert metrics["truth_coverage"]["missing_truth_case_ids"] == ids[113:]
    assert metrics["discovery_recall_at_k"] is None
    assert metrics["verified_detection_rate"] is None
    assert metrics["evaluable_subset"]["denominator"] == 113
    assert metrics["evaluable_subset"]["discovery_recall_at_k"] == {"5": 0.0}
    unknown = [row for row in rows if row["ground_truth_status"] == "GT_MISSING"]
    assert len(unknown) == 7
    assert all(row["discovery_recall_at_k"] is None for row in unknown)
    assert all(row["verified_detected"] is None for row in unknown)
    assert (run / "checksums.sha256").read_bytes() == before


def test_strict_truth_policy_remains_default(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth, _ = truth_fixture(tmp_path)
    with pytest.raises(ValueError, match="missing_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    assert not (tmp_path / "results/evaluations/truth120/zero_hint").exists()


def test_report_policy_marks_unresolvable_spans_unknown(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth, _ = truth_fixture(tmp_path, span=False)
    output = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, missing_truth_policy="report"
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 0
    assert metrics["evaluable_subset"]["denominator"] == 0
    assert metrics["evaluable_subset"]["discovery_recall_at_k"] is None
    assert metrics["discovery_recall_at_k"] is None


@pytest.mark.parametrize("row", [{"file": "App.java"}, {"method_start": 2, "method_end": 5}])
def test_strict_truth_policy_rejects_missing_strong_locations(tmp_path, row):
    from maxvera.evaluation import evaluate

    run, labels, truth, ids = truth_fixture(tmp_path)
    atomic_jsonl(truth, [{"project_id": cid, **row} for cid in ids])
    with pytest.raises(ValueError, match="missing_span_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


def test_evaluation_policy_is_part_of_immutable_identity(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth, ids = truth_fixture(tmp_path)
    atomic_jsonl(
        truth,
        [
            {
                "project_id": cid,
                "file": "App.java",
                "method_start": 2,
                "method_end": 5,
                "commit": "b" * 40,
            }
            for cid in ids
        ],
    )
    report = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, missing_truth_policy="report"
    )
    strict = evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    assert report != strict
    assert report.is_dir() and strict.is_dir()


def test_compare_can_export_explicit_unknown_cohort_metrics(tmp_path):
    from maxvera.evaluation import compare, evaluate

    outputs = []
    for run_id in ("one", "two"):
        run, labels, truth, _ = truth_fixture(tmp_path, run_id=run_id)
        outputs.append(
            evaluate(
                tmp_path,
                run,
                "zero_hint",
                labels=labels,
                truth=truth,
                missing_truth_policy="report",
            )
        )
    output = compare(outputs, tmp_path / "comparison")
    assert (output / "comparison.csv").is_file()
    result = json.loads((output / "comparison.json").read_text())
    assert all(run["discovery_recall_at_k"] is None for run in result["runs"])
