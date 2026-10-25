"""Failed extraction must not remove known vulnerable truth from recall accounting."""

import json
import shutil

import pytest
from test_truth_alignment import COMMIT, frozen_source_stage, source_fixture

from maxvera.evaluation import evaluate
from maxvera.orchestration import Orchestrator, Stage, StageFailure
from src.reproduction.common import atomic_json, atomic_jsonl


def failed_extraction_run(root, *, changed_workspace=False, failure_status="BUILD_FAILED"):
    source = source_fixture(root)

    def fail(ctx):
        shutil.copytree(source, ctx.stage_dir / "workspace")
        if changed_workspace:
            (ctx.stage_dir / "workspace/App.java").write_text("build modified this file\n")
        raise StageFailure(failure_status, "fixture failure before analyzed inventory")

    def finish(path, cases):
        for name in ("candidates_raw.jsonl", "candidates_pre_llm.jsonl", "findings.jsonl"):
            atomic_jsonl(path / name, [])

    run = Orchestrator(
        root,
        "research",
        "failed-extract",
        {"dataset": {}, "evidence": {"top_k": [5]}},
        [{"case_id": "opaque-1"}],
        [Stage("ingest", frozen_source_stage), Stage("static_extract", fail)],
        implementation_hash="fixture",
        finalizer=finish,
    )
    assert run.execute() == "COMPLETED_WITH_CASE_FAILURES"
    labels, truth = root / "labels.csv", root / "truth.jsonl"
    labels.write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\nopaque-1,CWE-78," + COMMIT + "\n"
    )
    atomic_jsonl(
        truth,
        [
            {
                "project_id": "opaque-1",
                "file": "App.java",
                "method_start": 2,
                "method_end": 3,
                "commit": COMMIT,
            }
        ],
    )
    return run.path, labels, truth


@pytest.mark.parametrize("changed_workspace", [False, True])
def test_failed_build_uses_verified_frozen_input_and_counts_recall_failure(
    tmp_path, changed_workspace
):
    run, labels, truth = failed_extraction_run(tmp_path, changed_workspace=changed_workspace)
    output = evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 1
    assert metrics["truth_coverage"]["complete"] is True
    assert metrics["discovery_recall_at_k"] == {"5": 0.0}
    assert metrics["statuses"] == {"BUILD_FAILED": 1}


def test_failed_build_cannot_use_changed_live_input_as_frozen_truth(tmp_path):
    run, labels, truth = failed_extraction_run(tmp_path)
    source = tmp_path / "data/processed/analysis_input/projects/opaque-1"
    (source / "App.java").write_text("changed after ingest\n")
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


@pytest.mark.parametrize("changed_workspace", [False, True])
def test_resource_failure_after_ingest_remains_in_evaluable_recall(tmp_path, changed_workspace):
    run, labels, truth = failed_extraction_run(
        tmp_path, changed_workspace=changed_workspace, failure_status="RESOURCE_EXHAUSTED"
    )
    output = evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 1
    assert metrics["discovery_recall_at_k"] == {"5": 0.0}
    assert metrics["statuses"] == {"RESOURCE_EXHAUSTED": 1}


def test_corrupt_analyzed_inventory_never_falls_back_to_prepared_input(tmp_path):
    from test_truth_alignment import evaluation_fixture

    from src.reproduction.common import write_checksums

    run, labels, truth = evaluation_fixture(
        tmp_path, [{"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT}]
    )
    atomic_json(run / "stages/opaque-1/static_extract/analyzed_snapshot.json", {"corrupt": True})
    write_checksums(run)  # This test's own output only; no repository frozen artifact.
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


def test_success_missing_analyzed_inventory_cannot_fall_back(tmp_path):
    from test_truth_alignment import evaluation_fixture

    from src.reproduction.common import write_checksums

    run, labels, truth = evaluation_fixture(
        tmp_path, [{"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT}]
    )
    (run / "stages/opaque-1/static_extract/analyzed_snapshot.json").unlink()
    write_checksums(run)
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


def test_failed_build_with_corrupt_present_inventory_cannot_fall_back(tmp_path):
    from src.reproduction.common import write_checksums

    run, labels, truth = failed_extraction_run(tmp_path)
    atomic_json(run / "stages/opaque-1/static_extract/analyzed_snapshot.json", {"corrupt": True})
    write_checksums(run)
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


@pytest.mark.parametrize("status", ["RETRYING", "QUEUED", "UNRECOGNIZED"])
def test_nonterminal_or_unknown_stage_status_cannot_recover_truth(tmp_path, status):
    from src.reproduction.common import write_checksums

    run, labels, truth = failed_extraction_run(tmp_path)
    checkpoint = run / "stages/opaque-1/static_extract/stage.json"
    record = json.loads(checkpoint.read_text())
    atomic_json(checkpoint, {**record, "status": status})
    write_checksums(run)
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
