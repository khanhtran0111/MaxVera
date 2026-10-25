"""Trusted annotations must identify the frozen vulnerable source, not a fix tree."""

import json

import pytest

from maxvera.contracts import digest
from maxvera.orchestration import Orchestrator, Stage
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl

COMMIT = "b" * 40
FIX = "c" * 40


def source_fixture(root, cid="opaque-1", *, name="App.java"):
    from maxvera.dataset import write_snapshot_manifest

    source = root / "data/processed/analysis_input/projects" / cid
    source.mkdir(parents=True, exist_ok=True)
    if (source / "snapshot.files.json").exists():
        return source
    (source / name).write_text("class App {\n" + "  // source\n" * 8 + "}\n")
    (source / "build.runtime.json").write_text('{"attempts": []}')
    write_snapshot_manifest(
        source,
        cid,
        {
            "dataset_id": "D_extended",
            "dataset_revision": "a" * 40,
            "source_commit": COMMIT,
            "build_patch_sha256": None,
            "preparation_policy": "pinned-git-archive-v1",
        },
    )
    return source


def frozen_source_stage(ctx):
    import shutil

    from maxvera.snapshots import source_inventory

    source = ctx.root / "data/processed/analysis_input/projects" / ctx.case["case_id"]
    files = source_inventory(source)
    if ctx.stage_dir.name == "ingest":
        atomic_json(
            ctx.stage_dir / "snapshot.json",
            {
                "case_id": ctx.case["case_id"],
                "source": str(source),
                "files": files,
                "snapshot_id": digest(files),
            },
        )
        return {"artifacts": ["snapshot.json"]}
    shutil.copytree(source, ctx.stage_dir / "workspace")
    atomic_json(
        ctx.stage_dir / "analyzed_snapshot.json",
        {
            "input_snapshot_id": digest(files),
            "analyzed_snapshot_id": digest(files),
            "analyzed_files": files,
        },
    )
    return {"artifacts": ["analyzed_snapshot.json", *["workspace/" + p for p in files]]}


def evaluation_fixture(root, truth_rows):
    source_fixture(root)

    def finish(path, cases):
        for name in ("candidates_raw.jsonl", "candidates_pre_llm.jsonl", "findings.jsonl"):
            atomic_jsonl(path / name, [])

    run = Orchestrator(
        root,
        "research",
        "alignment",
        {"dataset": {}, "evidence": {"top_k": [5]}},
        [{"case_id": "opaque-1"}],
        [Stage("ingest", frozen_source_stage), Stage("static_extract", frozen_source_stage)],
        implementation_hash="fixture",
        finalizer=finish,
    )
    assert run.execute() == "COMPLETED"
    labels = root / "labels.csv"
    labels.write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\nopaque-1,CWE-78," + COMMIT + "\n"
    )
    truth = root / "truth.jsonl"
    atomic_jsonl(truth, [{"project_id": "opaque-1", **r} for r in truth_rows])
    return run.path, labels, truth


@pytest.mark.parametrize(
    "row",
    [
        {"file": "Renamed.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
        {"file": "App.java", "method_start": 7, "method_end": 15, "commit": COMMIT},
        {"file": "App.java", "method_start": 2, "method_end": 3, "commit": FIX},
        {"file": "../App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
    ],
)
def test_strict_rejects_truth_outside_exact_vulnerable_snapshot(tmp_path, row):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(tmp_path, [row])
    with pytest.raises(ValueError, match=r"unaligned_truth_case_ids=.*opaque-1"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


def test_report_does_not_hide_one_invalid_annotation_behind_valid_row(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
            {"file": "FixOnly.java", "method_start": 2, "method_end": 3, "commit": FIX},
        ],
    )
    output = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, missing_truth_policy="report"
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 0
    assert metrics["discovery_recall_at_k"] is None
    assert metrics["evaluable_subset"]["denominator"] == 0
    assert read_jsonl(output / "metrics_per_case.jsonl")[0]["ground_truth_status"] == "GT_UNALIGNED"


def test_new_alignment_policy_does_not_reuse_old_frozen_evaluation_directory(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
        ],
    )
    old = tmp_path / "results/evaluations/alignment/zero_hint"
    old.mkdir(parents=True)
    (old / "old-output").write_text("preserve frozen output")
    output = evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    assert output != old
    assert (old / "old-output").read_text() == "preserve frozen output"
    assert (
        json.loads((output / "metrics_aggregate.json").read_text())["truth_coverage"][
            "evaluable_cases"
        ]
        == 1
    )


def mapping_fixture(root, run, truth, *, status="MAPPED"):
    from src.common.provenance import sha256_file

    row = read_jsonl(truth)[0]
    source = root / "data/processed/analysis_input/projects/opaque-1"
    evidence = root / "review.txt"
    evidence.write_text("Reviewed exact fix-to-vulnerable git diff and selected unique method.\n")
    snapshot = json.loads((run / "stages/opaque-1/ingest/snapshot.json").read_text())
    mapping = {
        "truth_row_sha256": digest(row),
        "status": status,
        "reviewed_by": "fixture-reviewer",
        "reason": "verified rename and line shift",
        "evidence": {"file": "review.txt", "sha256": sha256_file(evidence)},
    }
    if status == "MAPPED":
        mapping["target"] = {
            "file": "App.java",
            "start_line": 2,
            "end_line": 3,
            "sha256": sha256_file(source / "App.java"),
        }
    path = root / "alignment.json"
    atomic_json(
        path,
        {
            "schema_version": "1.0",
            "policy_version": "vulnerable-source-alignment-v1",
            "truth_sha256": sha256_file(truth),
            "cases": [
                {
                    "case_id": "opaque-1",
                    "source_commit": COMMIT,
                    "source_inventory_sha256": snapshot["snapshot_id"],
                    "mappings": [mapping],
                }
            ],
        },
    )
    return path


def test_reviewed_rename_line_shift_mapping_is_evaluator_only_and_identity_bound(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "Renamed.java", "method_start": 70, "method_end": 90, "commit": FIX},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth)
    before = (run / "checksums.sha256").read_bytes()
    output = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, truth_alignment=mapping
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 1
    assert metrics["condition_manifest"]["truth_alignment"]["mapping_sha256"]
    assert (run / "checksums.sha256").read_bytes() == before
    data = json.loads(mapping.read_text())
    data["cases"][0]["mappings"][0]["reason"] = "changed review"
    atomic_json(mapping, data)
    revised = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, truth_alignment=mapping
    )
    assert revised != output
    assert output.is_dir()


@pytest.mark.parametrize("status", ["FIX_ONLY", "AMBIGUOUS", "UNRESOLVED"])
def test_reviewed_unresolved_mapping_preserves_unknown_case(tmp_path, status):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "AddedOnlyByFix.java", "method_start": 2, "method_end": 3, "commit": FIX},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth, status=status)
    output = evaluate(
        tmp_path,
        run,
        "zero_hint",
        labels=labels,
        truth=truth,
        truth_alignment=mapping,
        missing_truth_policy="report",
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["evaluable_cases"] == 0
    assert metrics["truth_coverage"]["alignment"]["cases"][0]["issues"][0]["code"] == status
    assert metrics["discovery_recall_at_k"] is None


@pytest.mark.parametrize("field", ["source_inventory_sha256", "source_commit", "truth_sha256"])
def test_mapping_rejects_mismatched_source_or_annotation_identity(tmp_path, field):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "Renamed.java", "method_start": 2, "method_end": 3, "commit": FIX},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth)
    data = json.loads(mapping.read_text())
    if field == "truth_sha256":
        data[field] = "d" * 64
    else:
        data["cases"][0][field] = "d" * (40 if field == "source_commit" else 64)
    atomic_json(mapping, data)
    with pytest.raises(ValueError, match=r"identity|unaligned_truth"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth, truth_alignment=mapping)


def test_trusted_cli_accepts_alignment_artifact_without_pipeline_exposure(tmp_path, capsys):
    from maxvera.cli import main, parser

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "Renamed.java", "method_start": 70, "method_end": 90, "commit": FIX},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth)
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "evaluate",
                "--run-id",
                "alignment",
                "--protocol",
                "zero_hint",
                "--labels",
                str(labels),
                "--truth",
                str(truth),
                "--truth-alignment",
                str(mapping),
            ]
        )
        == 0
    )
    assert "zero_hint_aligned_v1" in capsys.readouterr().out
    args = parser().parse_args(
        ["preflight", "--config", "x.yaml", "--truth-alignment", str(mapping)]
    )
    assert args.truth_alignment == mapping
    with pytest.raises(SystemExit):
        parser().parse_args(
            [
                "pipeline",
                "research",
                "--config",
                "x.yaml",
                "--run-id",
                "x",
                "--truth-alignment",
                str(mapping),
            ]
        )


def test_preflight_separates_record_coverage_from_vulnerable_alignment(tmp_path):
    from types import SimpleNamespace

    from maxvera.preflight import readiness_preflight

    source_fixture(tmp_path)
    folder = tmp_path / "data/processed/evaluator_only"
    folder.mkdir()
    (folder / "D_extended_labels.csv").write_text(
        "project_id,ground_truth_cwe,buggy_commit_id\nopaque-1,CWE-78," + COMMIT + "\n"
    )
    atomic_jsonl(
        folder / "D_extended_fix_locations.jsonl",
        [
            {
                "project_id": "opaque-1",
                "file": "App.java",
                "method_start": 2,
                "method_end": 3,
                "commit": FIX,
            }
        ],
    )
    config = SimpleNamespace(dataset={"config": "extended"}, codeql={}, research={})
    report = readiness_preflight(
        tmp_path,
        config,
        [{"case_id": "opaque-1", "source_dir": "projects/opaque-1"}],
        {"name": "graph_only"},
        "full",
    )
    coverage = report["ground_truth_coverage"]
    assert coverage["truth_record_cases"] == 1
    assert coverage["truth_cases"] == 1
    assert coverage["aligned_truth_cases"] == 0
    assert coverage["alignment"]["unaligned_case_ids"] == ["opaque-1"]
    assert coverage["ready"] is False
    assert "GROUND_TRUTH_UNALIGNED" in {i["code"] for i in report["issues"]}


def test_review_can_create_new_evaluation_of_same_frozen_run_without_overwrite(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "Renamed.java", "method_start": 70, "method_end": 90, "commit": FIX},
        ],
    )
    unknown = evaluate(
        tmp_path, run, "zero_hint", labels=labels, truth=truth, missing_truth_policy="report"
    )
    old_checksum = (unknown / "checksums.sha256").read_bytes()
    mapping = mapping_fixture(tmp_path, run, truth)
    reviewed = evaluate(
        tmp_path,
        run,
        "zero_hint",
        labels=labels,
        truth=truth,
        truth_alignment=mapping,
        missing_truth_policy="report",
    )
    assert unknown != reviewed
    assert (unknown / "checksums.sha256").read_bytes() == old_checksum
    assert (
        evaluate(
            tmp_path,
            run,
            "zero_hint",
            labels=labels,
            truth=truth,
            truth_alignment=mapping,
            missing_truth_policy="report",
        )
        == reviewed
    )
    assert (
        json.loads((unknown / "metrics_aggregate.json").read_text())["discovery_recall_at_k"]
        is None
    )
    assert (
        json.loads((reviewed / "metrics_aggregate.json").read_text())["truth_coverage"][
            "evaluable_cases"
        ]
        == 1
    )


def test_frozen_source_hash_change_cannot_be_hidden_by_resealing_run_inventory(tmp_path):
    from maxvera.evaluation import evaluate
    from src.reproduction.common import write_checksums

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
        ],
    )
    (run / "stages/opaque-1/static_extract/workspace/App.java").write_text("changed\n" * 10)
    write_checksums(run)
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)


def test_frozen_evaluation_does_not_read_changed_live_source(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
        ],
    )
    (tmp_path / "data/processed/analysis_input/projects/opaque-1/App.java").write_text(
        "later source\n"
    )
    output = evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth)
    assert (
        json.loads((output / "metrics_aggregate.json").read_text())["truth_coverage"][
            "evaluable_cases"
        ]
        == 1
    )


def test_mapping_review_evidence_must_remain_exact(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "Renamed.java", "method_start": 70, "method_end": 90, "commit": FIX},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth)
    (tmp_path / "review.txt").write_text("changed evidence")
    with pytest.raises(ValueError, match="evidence hash mismatch"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth, truth_alignment=mapping)


def test_mapping_does_not_accept_stale_unrelated_annotation_binding(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(
        tmp_path,
        [
            {"file": "App.java", "method_start": 2, "method_end": 3, "commit": COMMIT},
        ],
    )
    mapping = mapping_fixture(tmp_path, run, truth)
    data = json.loads(mapping.read_text())
    data["cases"][0]["mappings"][0]["truth_row_sha256"] = "f" * 64
    atomic_json(mapping, data)
    with pytest.raises(ValueError, match="unaligned_truth_case_ids"):
        evaluate(tmp_path, run, "zero_hint", labels=labels, truth=truth, truth_alignment=mapping)


@pytest.mark.parametrize("policy", ["error", "report"])
def test_reviewed_mapping_supplies_missing_original_span(tmp_path, policy):
    from maxvera.evaluation import evaluate

    run, labels, truth = evaluation_fixture(tmp_path, [{"file": "Renamed.java", "commit": FIX}])
    mapping = mapping_fixture(tmp_path, run, truth)
    output = evaluate(
        tmp_path,
        run,
        "zero_hint",
        labels=labels,
        truth=truth,
        truth_alignment=mapping,
        missing_truth_policy=policy,
    )
    metrics = json.loads((output / "metrics_aggregate.json").read_text())
    assert metrics["truth_coverage"]["alignment"]["aligned_cases"] == 1
    assert metrics["truth_coverage"]["evaluable_cases"] == 1
    assert metrics["truth_coverage"]["missing_span_case_ids"] == ["opaque-1"]
    assert metrics["truth_coverage"]["complete"] is True
    assert read_jsonl(output / "metrics_per_case.jsonl")[0]["ground_truth_status"] == "AVAILABLE"


def test_preflight_reviewed_mapping_supplies_missing_original_span(tmp_path):
    import shutil
    from types import SimpleNamespace

    from maxvera.preflight import readiness_preflight

    run, labels, truth = evaluation_fixture(tmp_path, [{"file": "Renamed.java", "commit": FIX}])
    mapping = mapping_fixture(tmp_path, run, truth)
    folder = tmp_path / "data/processed/evaluator_only"
    folder.mkdir()
    shutil.copyfile(labels, folder / "D_extended_labels.csv")
    shutil.copyfile(truth, folder / "D_extended_fix_locations.jsonl")
    config = SimpleNamespace(dataset={"config": "extended"}, codeql={}, research={})
    report = readiness_preflight(
        tmp_path,
        config,
        [{"case_id": "opaque-1", "source_dir": "projects/opaque-1"}],
        {"name": "graph_only"},
        "full",
        truth_alignment=mapping,
    )
    coverage = report["ground_truth_coverage"]
    assert coverage["missing_span_case_ids"] == ["opaque-1"]
    assert coverage["aligned_truth_cases"] == 1
    assert coverage["ready"] is True
    assert not any(i["code"].startswith("GROUND_TRUTH") for i in report["issues"])


@pytest.mark.parametrize("value", [None, "", "f" * 63, 123, ["f" * 64]])
def test_mapping_requires_exact_nonnull_target_hash(tmp_path, value):
    from maxvera.truth_alignment import load_mapping
    from src.common.provenance import sha256_file

    run, _labels, truth = evaluation_fixture(tmp_path, [{"file": "Renamed.java", "commit": FIX}])
    mapping = mapping_fixture(tmp_path, run, truth)
    data = json.loads(mapping.read_text())
    data["cases"][0]["mappings"][0]["target"]["sha256"] = value
    atomic_json(mapping, data)
    with pytest.raises(ValueError, match=r"target.*hash"):
        load_mapping(mapping, sha256_file(truth))


@pytest.mark.parametrize("field", ["case", "mapping", "evidence", "target", "status"])
@pytest.mark.parametrize("value", [None, [], "invalid", 123])
def test_malformed_mapping_nested_values_raise_clean_value_error(tmp_path, field, value):
    from maxvera.truth_alignment import load_mapping
    from src.common.provenance import sha256_file

    run, _labels, truth = evaluation_fixture(tmp_path, [{"file": "Renamed.java", "commit": FIX}])
    mapping = mapping_fixture(tmp_path, run, truth)
    data = json.loads(mapping.read_text())
    if field == "case":
        data["cases"][0] = value
    elif field == "mapping":
        data["cases"][0]["mappings"][0] = value
    else:
        data["cases"][0]["mappings"][0][field] = value
    atomic_json(mapping, data)
    with pytest.raises(ValueError):
        load_mapping(mapping, sha256_file(truth))
