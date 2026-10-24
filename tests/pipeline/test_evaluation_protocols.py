"""Lock distinct artifact/path units against real pinned IRIS matching."""

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def flow(line, message="value"):
    return {
        "threadFlows": [
            {
                "locations": [
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "X.java"},
                                "region": {"startLine": line},
                            },
                            "message": {"text": message},
                        }
                    }
                ]
            }
        ]
    }


def frozen_reproduction(tmp_path):
    from src.reproduction.common import write_checksums

    root = tmp_path / "repo"
    root.mkdir()
    (root / "third_party").symlink_to(REPO / "third_party", target_is_directory=True)
    run = root / "results/_smoke/reproduction/protocols"
    run.mkdir(parents=True)
    (run / "STATUS").write_text("COMPLETED\n")
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "protocols",
                "pipeline": "reproduction",
                "mode": "smoke",
                "case_ids": ["opaque-1", "opaque-2"],
                "input_hash": "input",
                "implementation_hash": "implementation",
            }
        )
    )
    (run / "config.resolved.yaml").write_text("pipeline: reproduction\n")
    (run / "cases.jsonl").write_text(
        "".join(
            json.dumps({"case_id": c, "status": "SUCCESS"}) + "\n" for c in ("opaque-1", "opaque-2")
        )
    )
    for case_id in ("opaque-1", "opaque-2"):
        for stage in ("finalize", "codeql_reference"):
            folder = run / "stages" / case_id / stage
            folder.mkdir(parents=True)
            (folder / "stage.json").write_text(
                json.dumps({"status": "SUCCESS", "result": {"sarif": "result.sarif"}})
            )
            alerts = (
                [
                    {"codeFlows": []},
                    {"codeFlows": [flow(7), flow(15)]},
                    {"codeFlows": [flow(7, "println")]},
                    {"message": {"text": "wrapper without paths"}},
                ]
                if case_id == "opaque-1"
                else [{"codeFlows": []}]
            )
            (folder / "result.sarif").write_text(json.dumps({"runs": [{"results": alerts}]}))
            (folder / "class_locs_path.csv").write_text(
                "file,name,start_line,end_line\nX.java,C,1,20\n"
            )
            (folder / "func_locs_path.csv").write_text(
                "file,name,start_line,end_line\nX.java,hit,5,9\nX.java,other,12,17\n"
            )
    write_checksums(run)
    labels = root / "labels.csv"
    labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\nopaque-2,CWE-22\n")
    truth = root / "truth.jsonl"
    truth.write_text(
        "".join(
            json.dumps({"project_id": c, "file": "X.java", "class": "C", "method": "hit"}) + "\n"
            for c in ("opaque-1", "opaque-2")
        )
    )
    return root, run, labels, truth


def test_named_protocols_keep_legacy_alias_and_use_surviving_path_counts(tmp_path):
    from maxvera.evaluation import evaluate

    root, run, labels, truth = frozen_reproduction(tmp_path)
    outputs = {}
    before = (run / "checksums.sha256").read_bytes()
    for protocol in ("legacy_artifact", "paper_formula_path", "iris_paper"):
        output = evaluate(root, run, protocol, labels=labels, truth=truth)
        outputs[protocol] = json.loads((output / "metrics_aggregate.json").read_text())
        provenance = json.loads((output / "evaluator_manifest.json").read_text())
        assert provenance["evaluator_identity"]["upstream"]["commit"]
        assert provenance["evaluator_identity"]["metric_unit"] == (
            "path" if protocol == "paper_formula_path" else "alert_container"
        )
        assert provenance["missing_ground_truth_policy"] == "ERROR_WITH_CASE_IDS"
        first = json.loads((output / "metrics_per_case.jsonl").read_text().splitlines()[0])
        assert first["alerts"] == 4
        assert first["paths"] == 2
        assert first["tp_paths"] == 1
        assert first["metric_denominator"] == (2 if protocol == "paper_formula_path" else 4)
    legacy = outputs["legacy_artifact"]["branches"]["iris"]
    path = outputs["paper_formula_path"]["branches"]["iris"]
    assert legacy == outputs["iris_paper"]["branches"]["iris"]
    assert legacy["detection_rate"] == path["detection_rate"] == 0.5
    # Legacy: one TP container out of four; second case contributes F1=0.
    assert legacy["avg_f1"] == pytest.approx(0.2)
    assert legacy["avg_fdr"] == pytest.approx(0.875)
    assert legacy["avg_fdr_denominator"] == 2
    # Path: one TP out of two non-ignored surviving flows, zero-path case excluded from FDR.
    assert path["avg_f1"] == pytest.approx(1 / 3)
    assert path["avg_fdr"] == pytest.approx(0.5)
    assert path["avg_fdr_denominator"] == 1
    assert (run / "checksums.sha256").read_bytes() == before
    # Returning a cached path evaluation must not return the legacy condition/metrics.
    again = evaluate(root, run, "paper_formula_path", labels=labels, truth=truth)
    assert (
        json.loads((again / "metrics_aggregate.json").read_text()) == outputs["paper_formula_path"]
    )
    assert (
        outputs["paper_formula_path"]["condition_hash"]
        != outputs["legacy_artifact"]["condition_hash"]
    )


def test_missing_ground_truth_rejection_names_case_without_inventing_labels(tmp_path):
    from maxvera.evaluation import evaluate

    root, run, labels, truth = frozen_reproduction(tmp_path)
    truth.write_text(json.dumps({"project_id": "opaque-1", "file": "X.java"}) + "\n")
    with pytest.raises(ValueError, match=r"missing_truth_case_ids=.*opaque-2"):
        evaluate(root, run, "paper_formula_path", labels=labels, truth=truth)
    assert not (root / "results/evaluations/protocols").exists()


@pytest.mark.parametrize("missing", ["label_row", "cwe_value", "method_value"])
def test_incomplete_label_data_is_rejected_with_case_id(tmp_path, missing):
    from maxvera.evaluation import evaluate

    root, run, labels, truth = frozen_reproduction(tmp_path)
    if missing == "label_row":
        labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\n")
    elif missing == "cwe_value":
        labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\nopaque-2,\n")
    else:
        records = [json.loads(line) for line in truth.read_text().splitlines()]
        records[1]["method"] = None
        truth.write_text("".join(json.dumps(row) + "\n" for row in records))
    with pytest.raises(ValueError, match=r"ground truth.*opaque-2"):
        evaluate(root, run, "paper_formula_path", labels=labels, truth=truth)


def test_checksum_index_is_streamed_with_nested_files_and_spaces(tmp_path, monkeypatch):
    from maxvera.orchestration import verify_checksums
    from src.reproduction.common import write_checksums

    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "a file.txt").write_text("frozen")
    index = write_checksums(tmp_path)
    original = Path.read_text

    def no_bulk_index_read(path, *args, **kwargs):
        if path == index:
            pytest.fail("full-run checksum index must be streamed, not loaded into RAM")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", no_bulk_index_read)
    verify_checksums(tmp_path)


def test_completed_resume_checks_full_inventory_once_without_stage_reexecution(
    tmp_path, monkeypatch
):
    import maxvera.orchestration as orchestration

    executed = []

    def action(ctx):
        executed.append(ctx.case["case_id"])
        return {"artifacts": []}

    settings = dict(
        root=tmp_path,
        pipeline="research",
        run_id="resume",
        config={},
        cases=[{"case_id": "opaque-1"}],
        stages=[orchestration.Stage("work", action)],
        implementation_hash="code",
    )
    runner = orchestration.Orchestrator(**settings)
    assert runner.execute() == "COMPLETED"
    original = orchestration.verify_checksums
    checked = []

    def verify_once(path):
        checked.append(path)
        original(path)

    monkeypatch.setattr(orchestration, "verify_checksums", verify_once)
    assert orchestration.Orchestrator(**settings, resume=True).execute() == "COMPLETED"
    assert executed == ["opaque-1"]
    assert checked == [runner.path]


@pytest.mark.parametrize(
    "attack", ["duplicate", "dotdot", "unindexed_symlink", "directory_symlink"]
)
def test_checksum_verifier_rejects_ambiguous_paths_and_symlinks(tmp_path, attack):
    from maxvera.orchestration import verify_checksums
    from src.reproduction.common import write_checksums

    (tmp_path / "data").write_text("frozen")
    index = write_checksums(tmp_path)
    line = index.read_text()
    if attack == "duplicate":
        index.write_text(line + line)
    elif attack == "dotdot":
        index.write_text(line.replace("  data", "  nested/../data"))
        (tmp_path / "nested").mkdir()
    elif attack == "unindexed_symlink":
        (tmp_path / "alias").symlink_to(tmp_path / "data")
    else:
        target = tmp_path / "empty"
        target.mkdir()
        (tmp_path / "alias").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match=r"checksum|symlink|unsafe"):
        verify_checksums(tmp_path)
