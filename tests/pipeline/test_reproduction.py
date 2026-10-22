"""IRIS adapter and evaluator fixtures catch branch mixing and stage loss."""

import json
from pathlib import Path

import pytest


def test_worker_dispatch_preserves_upstream_order_without_evaluation():
    from maxvera.iris_worker import run_stage

    class Pipeline:
        def __init__(self):
            self.events = []

        def __getattr__(self, name):
            def call():
                self.events.append(name)

            return call

    p = Pipeline()
    for stage in ("candidate_extract", "llm_specs", "static_taint", "context_filter"):
        run_stage(p, stage)
    assert p.events == [
        "collect_invoked_external_apis",
        "collect_internal_function_parameters",
        "query_gpt_for_api_src_tp_sink_batched",
        "query_gpt_for_func_param_src",
        "build_project_specific_query",
        "find_vulnerability",
        "post_process_cwe_query_result",
        "query_gpt_for_posthoc_filtering",
    ]


def test_full_selection_keeps_failed_builds_and_refuses_truncation(tmp_path):
    from maxvera.dataset import select_cases

    path = tmp_path / "cases.csv"
    path.write_text(
        "project_id,source_dir\nopaque-1,projects/opaque-1\nopaque-2,projects/opaque-2\n"
    )
    cases = select_cases(tmp_path, {"analysis_manifest": "cases.csv", "expected_cases": 2}, "full")
    assert [c["case_id"] for c in cases] == ["opaque-1", "opaque-2"]
    with pytest.raises(ValueError, match="full"):
        select_cases(tmp_path, {"analysis_manifest": "cases.csv", "expected_cases": 2}, "full", 1)
    with pytest.raises(ValueError, match=r"coverage|expected"):
        select_cases(tmp_path, {"analysis_manifest": "cases.csv", "expected_cases": 3}, "full")


def test_reproduction_normalization_never_uses_reference_as_iris(tmp_path):
    from maxvera.reproduction import finalize

    root = tmp_path / "stages/opaque-1/codeql_reference"
    root.mkdir(parents=True)
    loc = {"physicalLocation": {"artifactLocation": {"uri": "X.java"}, "region": {"startLine": 7}}}
    sarif = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "q", "locations": [loc]}]}]}
    (root / "reference.sarif").write_text(json.dumps(sarif))
    (root / "stage.json").write_text(
        json.dumps({"status": "SUCCESS", "result": {"sarif": "reference.sarif"}})
    )
    finalize(tmp_path, [{"case_id": "opaque-1"}])
    assert (tmp_path / "findings.jsonl").read_text() == ""
    reference = json.loads((tmp_path / "reference_findings.jsonl").read_text())
    assert reference["case_id"] == "opaque-1"
    assert reference["branch"] == "codeql_reference"


def test_iris_paper_metric_excludes_no_alerts_from_fdr_denominator():
    from maxvera.evaluation import paper_aggregate

    rows = [
        dict(case_id="a", status="SUCCESS", detected=True, alerts=2, tp_alerts=1),
        dict(case_id="b", status="SUCCESS", detected=False, alerts=0, tp_alerts=0),
        dict(case_id="c", status="BUILD_FAILED", detected=False, alerts=0, tp_alerts=0),
    ]
    metric = paper_aggregate(rows, expected=3)
    assert metric["detected"] == 1
    assert metric["denominator_intention_to_analyze"] == 3
    assert metric["avg_fdr"] == 0.5
    assert metric["avg_fdr_denominator"] == 1
    assert metric["avg_f1"] == pytest.approx(2 / 9)
    with pytest.raises(ValueError, match=r"missing|coverage"):
        paper_aggregate(rows[:2], expected=3)


def test_upstream_paper_evaluator_matches_methods_instead_of_only_line_ranges(tmp_path):
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[2]
    classes = tmp_path / "classes.csv"
    methods = tmp_path / "methods.csv"
    classes.write_text("name,file,start_line,end_line\nX,X.java,1,20\n")
    methods.write_text("name,file,start_line,end_line\nvulnerable,X.java,5,10\n")

    def location(line):
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": "X.java"},
                    "region": {"startLine": line},
                },
                "message": {"text": "value"},
            }
        }

    sarif = tmp_path / "raw.sarif"
    sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "codeFlows": [
                                    {"threadFlows": [{"locations": [location(6), location(7)]}]}
                                ]
                            }
                        ]
                    }
                ]
            }
        )
    )
    request = {
        "iris_root": str(repo / "third_party/iris"),
        "classes": str(classes),
        "methods": str(methods),
        "sarif": str(sarif),
        "truth": [{"file": "X.java", "class": "X", "method": "vulnerable"}],
    }
    result = subprocess.run(
        [sys.executable, "-m", "maxvera.evaluator_worker"],
        cwd=repo,
        input=json.dumps(request),
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    metric = json.loads(
        next(
            line.split("=", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("MAXVERA_METRIC=")
        )
    )
    assert metric["recall_method"] is True
    assert metric["num_tp_results_method"] == 1
