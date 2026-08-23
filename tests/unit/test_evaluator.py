from __future__ import annotations

import json
from pathlib import Path

from openiris.evaluation import (
    EvaluationPipeline,
    GroundTruth,
    LocationIndex,
    SarifEvaluator,
    evaluate_sarif,
    load_ground_truth,
    normalize_uri,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "evaluation"
REPOSITORY_ROOT = Path(r"C:\workspace\repo")


def test_normalize_windows_posix_and_file_uris() -> None:
    expected = "src/main/java/com/acme/Vulnerable.java"

    assert normalize_uri(r"src\main\java\com\acme\Vulnerable.java") == expected
    assert normalize_uri(f"./{expected}") == expected
    assert (
        normalize_uri(
            "file:///C:/workspace/repo/src/main/java/com/acme/Vulnerable.java",
            REPOSITORY_ROOT,
        )
        == expected
    )
    assert normalize_uri("src/a%20file.java") == "src/a file.java"


def _evaluator() -> SarifEvaluator:
    return SarifEvaluator.from_files(
        FIXTURES / "fix_info.csv",
        FIXTURES / "class_locations.csv",
        FIXTURES / "function_locations.csv",
        project_slug="fixture_project",
        repository_root=REPOSITORY_ROOT,
    )


def test_evaluator_reproduces_iris_v1_path_and_result_counts() -> None:
    metrics = _evaluator().evaluate_path(FIXTURES / "iris_v1_paths.sarif.json")

    assert metrics.to_dict() == {
        "num_results": 4,
        "num_paths": 4,
        "recall_file": True,
        "num_tp_paths_file": 3,
        "num_tp_results_file": 2,
        "recall_method": True,
        "num_tp_paths_method": 2,
        "num_tp_results_method": 2,
    }


def test_ground_truth_excludes_src_test_like_iris_v1() -> None:
    ground_truth = load_ground_truth(
        FIXTURES / "fix_info.csv",
        project_slug="fixture_project",
    )

    assert len(ground_truth.methods) == 2
    assert ground_truth.fixed_files == {
        "src/main/java/com/acme/Vulnerable.java",
    }


def test_method_overlap_uses_closest_class_and_function_locations() -> None:
    evaluator = _evaluator()
    sarif = json.loads((FIXTURES / "iris_v1_paths.sarif.json").read_text(encoding="utf-8"))
    first_flow = next(evaluator.iter_code_flows(sarif))[2]

    assert list(evaluator.extract_code_flow_passing_methods(first_flow)) == [
        "src/main/java/com/acme/Vulnerable.java:Inner:dangerous"
    ]


def test_endpoint_filter_is_limited_to_first_and_last_messages() -> None:
    sarif = json.loads((FIXTURES / "iris_v1_paths.sarif.json").read_text(encoding="utf-8"))
    flows = [entry[2] for entry in SarifEvaluator.iter_code_flows(sarif)]

    assert not SarifEvaluator.ignore_code_flow(flows[0])
    assert SarifEvaluator.ignore_code_flow(flows[1])  # first endpoint: toString
    assert SarifEvaluator.ignore_code_flow(flows[2])  # last endpoint: println
    # A println in the second threadFlow has no effect: IRIS only reads index 0.
    assert not SarifEvaluator.ignore_code_flow(flows[4])


def test_function_api_and_iris_compatibility_facade_return_same_metrics() -> None:
    ground_truth = GroundTruth.from_records(
        FIXTURES / "fix_info.csv",
        project_slug="fixture_project",
        repository_root=REPOSITORY_ROOT,
    )
    classes = LocationIndex.from_csv(
        FIXTURES / "class_locations.csv",
        repository_root=REPOSITORY_ROOT,
    )
    functions = LocationIndex.from_csv(
        FIXTURES / "function_locations.csv",
        repository_root=REPOSITORY_ROOT,
    )
    expected = evaluate_sarif(
        FIXTURES / "iris_v1_paths.sarif.json",
        ground_truth,
        classes,
        functions,
        repository_root=REPOSITORY_ROOT,
    )
    pipeline = EvaluationPipeline(
        ground_truth,
        classes,
        functions,
        REPOSITORY_ROOT,
    )

    assert pipeline.evaluate_sarif_result(FIXTURES / "iris_v1_paths.sarif.json") == expected
