"""Public CLI behavior is exercised through commands and immutable run outputs."""

import json

import pytest


def test_dry_run_lists_all_cases_without_network_or_creating_run(tmp_path, capsys):
    from maxvera.cli import main

    manifest = tmp_path / "cases.csv"
    manifest.write_text(
        "project_id,source_dir\nopaque-1,projects/opaque-1\nopaque-2,projects/opaque-2\n"
    )
    config = tmp_path / "research.yaml"
    config.write_text(
        "pipeline: research\ndataset:\n  analysis_manifest: cases.csv\n  expected_cases: 2\n"
    )
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                str(config),
                "--mode",
                "full",
                "--run-id",
                "dry",
                "--dry-run",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["cases"] == 2
    assert report["expected_requests_upper_bound"] == 0
    assert report["dag"][0] == "ingest"
    assert not (tmp_path / "results").exists()


def frozen_run(root, run_id="run1"):
    from maxvera.orchestration import Orchestrator, Stage
    from src.reproduction.common import atomic_jsonl

    candidates = [
        dict(
            case_id="opaque-1",
            candidate_id="c1",
            rank_pre_llm=1,
            graph_path_edge_ids=["e1"],
            graph_path_node_ids=["n1", "n2"],
            locations=[{"file": "X.java", "start_line": 7, "end_line": 7}],
            discovery_status="COMPLETE_CANDIDATE_PATH",
            origin_generators=["sink_backward_slice"],
            verification_status="NOT_ATTEMPTED",
        )
    ]

    def work(ctx):
        return {"artifacts": []}

    def finish(path, cases):
        atomic_jsonl(path / "candidates_pre_llm.jsonl", candidates)
        atomic_jsonl(path / "findings.jsonl", [{**candidates[0], "decision": "REVIEW"}])

    config = {
        "dataset": {"track": "development_seen_benchmark"},
        "selected_variant": {"name": "graph_only"},
    }
    run = Orchestrator(
        root,
        "research",
        run_id,
        config,
        [{"case_id": "opaque-1"}, {"case_id": "opaque-2"}],
        [Stage("extract", work)],
        implementation_hash="code",
        finalizer=finish,
    )
    run.execute()
    return run


def test_evaluator_counts_failures_and_weak_matches_without_false_precision(tmp_path):
    from maxvera.evaluation import evaluate

    run = frozen_run(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\nopaque-2,CWE-22\n")
    truth = tmp_path / "truth.jsonl"
    truth.write_text(
        json.dumps({"project_id": "opaque-1", "file": "X.java", "method_start": 5, "method_end": 9})
        + "\n"
        + json.dumps(
            {"project_id": "opaque-2", "file": "Y.java", "method_start": 2, "method_end": 4}
        )
        + "\n"
    )
    output = evaluate(tmp_path, run.path, "zero_hint", labels=labels, truth=truth)
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["cases"] == 2
    assert metrics["discovery_recall_at_k"]["5"] == 0.5
    assert metrics["verified_detection_rate"] == 0
    assert metrics["unmatched_label_status"] == "UNKNOWN_UNREVIEWED"
    assert "precision" not in metrics
    assert (run.path / "STATUS").read_text().strip() == "COMPLETED"


def test_compare_rejects_mismatched_pools_for_paired_llm_claims(tmp_path):
    from maxvera.contracts import digest
    from maxvera.evaluation import compare
    from src.reproduction.common import write_checksums

    a = tmp_path / "a"
    b = tmp_path / "b"
    for path, pool in [(a, "pool-a"), (b, "pool-b")]:
        path.mkdir()
        (path / "metrics_aggregate.json").write_text(
            json.dumps(
                {
                    "case_ids": ["opaque-1"],
                    "candidate_pool_hash": pool,
                    "condition_hash": digest({"budget": "budget-1"}),
                    "condition_manifest": {"budget": "budget-1"},
                    "panel": "zero_hint",
                    "cases": 1,
                }
            )
        )
        write_checksums(path)
    with pytest.raises(ValueError, match="pool"):
        compare([a, b], tmp_path / "comparison", paired_llm=True)


def test_evaluation_refuses_tampered_raw_run(tmp_path):
    from maxvera.evaluation import evaluate

    run = frozen_run(tmp_path)
    (run.path / "findings.jsonl").write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        evaluate(
            tmp_path, run.path, "zero_hint", labels=tmp_path / "missing", truth=tmp_path / "missing"
        )


def test_status_evaluate_and_compare_cli_on_frozen_fixture_runs(tmp_path, capsys):
    from maxvera.cli import main

    frozen_run(tmp_path, "one")
    frozen_run(tmp_path, "two")
    labels = tmp_path / "labels.csv"
    labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\nopaque-2,CWE-22\n")
    truth = tmp_path / "truth.jsonl"
    truth.write_text(
        json.dumps({"project_id": "opaque-1", "file": "X.java", "method_start": 5, "method_end": 9})
        + "\n"
        + json.dumps(
            {"project_id": "opaque-2", "file": "Y.java", "method_start": 2, "method_end": 4}
        )
        + "\n"
    )
    for name in ("one", "two"):
        assert main(["--root", str(tmp_path), "status", "--run-id", name]) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["status"] == "COMPLETED"
        assert len(status["cases"]) == 2
        assert (
            main(
                [
                    "--root",
                    str(tmp_path),
                    "evaluate",
                    "--run-id",
                    name,
                    "--protocol",
                    "zero_hint",
                    "--labels",
                    str(labels),
                    "--truth",
                    str(truth),
                ]
            )
            == 0
        )
        capsys.readouterr()
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "compare",
                "--runs",
                "one,two",
                "--output",
                "results/aggregate/fixture",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (tmp_path / "results/aggregate/fixture/comparison.csv").is_file()


def test_research_cli_isolated_worker_accounts_missing_snapshot_without_labels(tmp_path):
    from maxvera.cli import main
    from maxvera.sandbox import landlock_available

    if not landlock_available():
        pytest.skip("Linux Landlock unavailable")
    path = tmp_path / "data/processed/analysis_input"
    path.mkdir(parents=True)
    (path / "cases.csv").write_text("project_id,source_dir\nopaque-1,projects/opaque-1\n")
    protected = tmp_path / "data/processed/evaluator_only"
    protected.mkdir()
    (protected / "labels").write_text("POISON_MUST_NOT_BE_READ")
    config = tmp_path / "research.yaml"
    config.write_text(
        "pipeline: research\ndataset:\n"
        "  analysis_manifest: data/processed/analysis_input/cases.csv\n"
        "  expected_cases: 1\n"
    )
    result = main(
        [
            "--root",
            str(tmp_path),
            "pipeline",
            "research",
            "--config",
            str(config),
            "--mode",
            "smoke",
            "--limit",
            "1",
            "--run-id",
            "fixture_failure",
            "--execute",
        ]
    )
    assert result == 1
    run = tmp_path / "results/_smoke/research/fixture_failure"
    rows = [json.loads(line) for line in (run / "cases.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["stages"]["ingest"] == "FETCH_FAILED"
    assert (run / "findings.jsonl").read_text() == ""
    assert "POISON" not in "".join(p.read_text() for p in run.rglob("*.json*"))
