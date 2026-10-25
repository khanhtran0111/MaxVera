"""Final research recall uses actual complete rankings without changing discovery."""

import json

import pytest

from maxvera.orchestration import Orchestrator, Stage
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def frozen_ranked_run(
    root, *, llm_enabled=True, incomplete=None, top_k=None, raw_count=6, correct_rank=6
):
    """Freeze two real orchestrator outputs; only assessment status is controlled."""
    from test_truth_alignment import frozen_source_stage, source_fixture

    for cid in ("opaque-1", "opaque-2"):
        source_fixture(root, cid, name="X.java")
    candidates = [
        {
            "case_id": case_id,
            "candidate_id": f"{case_id}-c{rank}",
            "rank_pre_llm": rank,
            "graph_path_edge_ids": ["edge"],
            "graph_path_node_ids": ["source", "sink"],
            "locations": [{"file": "X.java", "start_line": 7 if rank == correct_rank else 30}],
            "discovery_status": "COMPLETE_CANDIDATE_PATH",
            "origin_generators": ["sink_backward_slice"],
            "verification_status": "NOT_ATTEMPTED",
        }
        for case_id in ("opaque-1", "opaque-2")
        for rank in range(1, raw_count + 1)
    ]
    retained = [c for c in candidates if top_k is None or c["rank_pre_llm"] <= max(top_k)]

    def reasoning(ctx):
        failed = ctx.case["case_id"] == incomplete
        return {"artifacts": [], "failed_assessments": int(failed)}

    def finish(path, cases):
        atomic_jsonl(path / "candidates_raw.jsonl", candidates)
        atomic_jsonl(path / "candidates_pre_llm.jsonl", retained)
        # The sixth discovery candidate rises to first; the negative candidate
        # stays present, at sixth. rank_post_llm deliberately remains unchanged
        # so the evaluator must use rank_final from evidence fusion.
        final = [
            {
                **candidate,
                "rank_final": (
                    1
                    if candidate["rank_pre_llm"] == correct_rank
                    else candidate["rank_pre_llm"] + 1
                )
                if top_k is None or correct_rank <= max(top_k)
                else candidate["rank_pre_llm"],
                "rank_post_llm": candidate["rank_pre_llm"],
                "llm_assessment": {
                    "status": "VALID",
                    "verdict": "NOT_SUPPORTED" if candidate["rank_pre_llm"] == 5 else "SUPPORTED",
                },
                "decision": "REVIEW",
            }
            for candidate in retained
        ]
        atomic_jsonl(path / "findings.jsonl", final)

    run = Orchestrator(
        root,
        "research",
        "ranked",
        {
            "selected_variant": {"name": "graph_llm", "llm_enabled": llm_enabled},
            **({"evidence": {"top_k": top_k}} if top_k is not None else {}),
        },
        [{"case_id": "opaque-1"}, {"case_id": "opaque-2"}],
        [
            Stage("ingest", frozen_source_stage),
            Stage("static_extract", frozen_source_stage),
            Stage("llm_reason", reasoning),
        ],
        implementation_hash="code",
        finalizer=finish,
    )
    assert run.execute() == "COMPLETED"
    labels = root / "labels.csv"
    labels.write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\n"
        + f"opaque-1,CWE-78,{'b' * 40}\nopaque-2,CWE-22,{'b' * 40}\n"
    )
    truth = root / "truth.jsonl"
    atomic_jsonl(
        truth,
        [
            {
                "project_id": case_id,
                "file": "X.java",
                "method_start": 5,
                "method_end": 9,
                "commit": "b" * 40,
            }
            for case_id in ("opaque-1", "opaque-2")
        ],
    )
    return run.path, labels, truth


def evaluated(root, run, labels, truth):
    from maxvera.evaluation import evaluate

    output = evaluate(root, run, "zero_hint", labels=labels, truth=truth)
    return json.loads((output / "metrics_aggregate.json").read_text()), read_jsonl(
        output / "metrics_per_case.jsonl"
    )


def test_complete_llm_final_ranking_is_scored_without_changing_discovery(tmp_path):
    run, labels, truth = frozen_ranked_run(tmp_path)
    before = (run / "checksums.sha256").read_bytes()
    aggregate, rows = evaluated(tmp_path, run, labels, truth)
    assert aggregate["discovery_recall_at_k"] == {"5": 0.0, "10": 1.0, "20": 1.0}
    assert aggregate["ranked_recall_at_k"] == {"5": 1.0, "10": 1.0, "20": 1.0}
    assert aggregate["ranking_complete_cases"] == 2
    assert all(row["ranked_recall_at_k"] == {"5": True, "10": True, "20": True} for row in rows)
    findings = read_jsonl(run / "findings.jsonl")
    assert len(findings) == 12
    assert sum(row["llm_assessment"]["verdict"] == "NOT_SUPPORTED" for row in findings) == 2
    assert (run / "checksums.sha256").read_bytes() == before


def test_one_failed_assessment_makes_full_selected_ranking_metric_null(tmp_path):
    run, labels, truth = frozen_ranked_run(tmp_path, incomplete="opaque-2")
    aggregate, rows = evaluated(tmp_path, run, labels, truth)
    assert aggregate["ranked_recall_at_k"] is None
    assert aggregate["ranking_complete_cases"] == 1
    by_id = {row["case_id"]: row for row in rows}
    assert by_id["opaque-1"]["ranked_recall_at_k"]["5"] is True
    assert by_id["opaque-2"]["ranked_recall_at_k"] is None
    assert aggregate["discovery_recall_at_k"]["10"] == 1


def test_configured_cutoff_does_not_publish_recall_for_discarded_rank_eight(tmp_path):
    run, labels, truth = frozen_ranked_run(tmp_path, top_k=[5], raw_count=10, correct_rank=8)
    aggregate, rows = evaluated(tmp_path, run, labels, truth)
    # The known candidate at rank eight is outside the retained pool. Reporting
    # zero at ten/twenty would turn uncomputed recall into a false negative.
    assert aggregate["discovery_recall_at_k"] == {"5": 0.0}
    assert aggregate["ranked_recall_at_k"] == {"5": 0.0}
    assert aggregate["retained_candidate_cutoff"] == 5
    assert aggregate["raw_candidate_count"] == 20
    assert aggregate["retained_candidate_count"] == 10
    assert aggregate["candidate_pool_truncated"] is True
    for row in rows:
        assert row["discovery_recall_at_k"] == {"5": False}
        assert row["ranked_recall_at_k"] == {"5": False}
        assert row["raw_candidate_count"] == 10
        assert row["retained_candidate_count"] == 5
        assert row["retained_candidate_cutoff"] == 5
        assert row["candidate_pool_truncated"] is True


def test_graph_only_cannot_publish_post_llm_metrics_from_final_rank_fields(tmp_path):
    run, labels, truth = frozen_ranked_run(tmp_path, llm_enabled=False)
    aggregate, rows = evaluated(tmp_path, run, labels, truth)
    assert aggregate["ranked_recall_at_k"] is None
    assert aggregate["ranking_complete_cases"] == 0
    assert all(row["ranked_recall_at_k"] is None for row in rows)


@pytest.mark.parametrize(
    ("source", "sink", "nodes", "expected"),
    [
        ("shared", "shared", ["shared"], True),
        ("source", "sink", ["source", "sink"], False),
        (None, None, [], False),
        ("shared", "shared", [], False),
        ("shared", "shared", ["other"], False),
        ("", "", [""], False),
    ],
)
def test_zero_edge_recall_requires_complete_single_node_identity_path(
    tmp_path, source, sink, nodes, expected
):
    from src.reproduction.common import write_checksums

    run, labels, truth = frozen_ranked_run(tmp_path, top_k=[1], raw_count=1, correct_rank=1)
    for filename in ("candidates_raw.jsonl", "candidates_pre_llm.jsonl", "findings.jsonl"):
        records = read_jsonl(run / filename)
        for record in records:
            record.update(
                graph_path_edge_ids=[],
                graph_path_node_ids=nodes,
                source_node_id=source,
                sink_node_id=sink,
            )
        atomic_jsonl(run / filename, records)
    write_checksums(run)

    aggregate, rows = evaluated(tmp_path, run, labels, truth)

    assert aggregate["discovery_recall_at_k"] == {"1": float(expected)}
    assert aggregate["ranked_recall_at_k"] == {"1": float(expected)}
    assert all(row["discovery_recall_at_k"] == {"1": expected} for row in rows)
    assert all(row["weak_location_matches"] == int(not expected) for row in rows)


@pytest.mark.parametrize(
    "broken", ["missing_stage", "failed_stage", "missing_count", "missing_rank"]
)
def test_incomplete_final_ranking_evidence_does_not_publish_metrics(tmp_path, broken):
    from src.reproduction.common import write_checksums

    run, labels, truth = frozen_ranked_run(tmp_path)
    stage = run / "stages/opaque-2/llm_reason/stage.json"
    if broken == "missing_stage":
        stage.unlink()
    elif broken in {"failed_stage", "missing_count"}:
        record = json.loads(stage.read_text())
        if broken == "failed_stage":
            record["status"] = "LLM_FAILED"
        else:
            record["result"].pop("failed_assessments")
        atomic_json(stage, record)
    else:
        findings = read_jsonl(run / "findings.jsonl")
        findings[-1].pop("rank_final")
        atomic_jsonl(run / "findings.jsonl", findings)
    write_checksums(run)
    aggregate, rows = evaluated(tmp_path, run, labels, truth)
    assert aggregate["ranked_recall_at_k"] is None
    assert aggregate["ranking_complete_cases"] == 1
    assert rows[1]["ranked_recall_at_k"] is None
