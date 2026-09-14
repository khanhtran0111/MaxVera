from __future__ import annotations

import json
from pathlib import Path

from src.reproduction.common import aggregate_metrics, evaluate_sarif
from src.reproduction.iris_subprocess import _compatible_query_source, _inject_codeql_ram
from src.reproduction.runner import RUN_ID_PATTERN, _prepare_iris_workspace


def _sarif(path: Path, file_name: str, line: int) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file_name},
                                            "region": {"startLine": line},
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_independent_evaluator_matches_ground_truth_range(tmp_path: Path) -> None:
    sarif = tmp_path / "results.sarif"
    _sarif(sarif, "src/main/java/example/App.java", 15)
    metric = evaluate_sarif(
        "proj_test",
        "SUCCESS",
        sarif,
        [
            {
                "file": "src/main/java/example/App.java",
                "method_start": "10",
                "method_end": "20",
            }
        ],
    )
    assert metric["detected"] is True
    assert metric["alerts"] == 1
    assert metric["tp_alerts"] == 1
    assert metric["precision"] == 1.0
    assert metric["f1"] == 1.0
    assert metric["ground_truth_scopes"] == {"method": 1, "class": 0, "file": 0}


def test_independent_evaluator_falls_back_to_class_range(tmp_path: Path) -> None:
    sarif = tmp_path / "results.sarif"
    _sarif(sarif, "src/main/java/example/App.java", 15)
    metric = evaluate_sarif(
        "proj_test",
        "SUCCESS",
        sarif,
        [
            {
                "file": "src/main/java/example/App.java",
                "method_start": "",
                "method_end": "",
                "class_start": "10",
                "class_end": "20",
            }
        ],
    )
    assert metric["detected"] is True
    assert metric["ground_truth_scopes"] == {"method": 0, "class": 1, "file": 0}


def test_independent_evaluator_falls_back_to_file(tmp_path: Path) -> None:
    sarif = tmp_path / "results.sarif"
    _sarif(sarif, "src/main/java/example/App.java", 999)
    metric = evaluate_sarif(
        "proj_test",
        "SUCCESS",
        sarif,
        [
            {
                "file": "src/main/java/example/App.java",
                "method_start": "",
                "method_end": "",
                "class_start": "",
                "class_end": "",
            }
        ],
    )
    assert metric["detected"] is True
    assert metric["ground_truth_scopes"] == {"method": 0, "class": 0, "file": 1}


def test_failed_projects_remain_in_intention_to_analyze_metrics() -> None:
    aggregate = aggregate_metrics(
        [
            {"status": "SUCCESS", "detected": True, "precision": 0.5, "f1": 0.6, "fdr": 0.5},
            {"status": "BUILD_FAILED", "detected": False},
        ]
    )
    assert aggregate["projects"] == 2
    assert aggregate["analysis_successes"] == 1
    assert aggregate["recall_intention_to_analyze"] == 0.5
    assert aggregate["recall_build_success_only"] == 1.0


def test_phase4_run_ids_are_filename_safe() -> None:
    assert RUN_ID_PATTERN.fullmatch("phase4_gptoss20b_full_001")
    assert not RUN_ID_PATTERN.fullmatch("../overwrite")


def test_iris_query_migration_is_workspace_local(tmp_path: Path) -> None:
    source = tmp_path / "original"
    source.mkdir()
    query = source / "query.ql"
    original = (
        "import semmle.code.java.security.PathCreation\n"
        "predicate p(DataFlow::Node n) { n instanceof ThreatModelFlowSource }\n"
        "DataFlow::Node getReportingNode(DataFlow::Node sink) {\n"
        "  if exists(PathCreation pc | pc.getAnInput() = sink.asExpr())\n"
        "  then result.asExpr() = pc\n"
        "  else result = sink\n"
        "}\n\n"
        'bindingset[src]\nstring sourceType(DataFlow::Node src) { result = "x" }\n'
    )
    query.write_text(original, encoding="utf-8")
    migrated_root = _compatible_query_source(source, tmp_path / "workspace")
    migrated = (migrated_root / "query.ql").read_text(encoding="utf-8")
    assert query.read_text(encoding="utf-8") == original
    assert "PathCreation" not in migrated
    assert "ActiveThreatModelSource" in migrated


def test_iris_codeql_commands_receive_explicit_ram_limit(tmp_path: Path) -> None:
    codeql = tmp_path / "codeql"
    command = [str(codeql), "database", "analyze", "--rerun", "database"]
    assert _inject_codeql_ram(command, codeql, 16384) == [
        str(codeql),
        "database",
        "analyze",
        "--ram=16384",
        "--rerun",
        "database",
    ]
    assert command == [str(codeql), "database", "analyze", "--rerun", "database"]


def test_iris_workspace_adds_hapi_package_aliases_without_mutating_raw_data(
    tmp_path: Path,
) -> None:
    source_name = "hapifhir__hapi-fhir_CVE-2023-24057_5.6.91.txt"
    alias_name = "hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91.txt"
    raw = tmp_path / "data/raw/cwe_bench_java_v1/package-names"
    raw.mkdir(parents=True)
    (raw / source_name).write_text("org.hl7.fhir\n", encoding="utf-8")
    # The second configured alias must also have a valid source.
    (raw / "hapifhir__hapi-fhir_CVE-2023-28465_5.6.105.txt").write_text(
        "org.hl7.fhir\n", encoding="utf-8"
    )
    project_id = "proj_test"
    slug = "hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91"
    (tmp_path / "data/interim/project_sources" / project_id).mkdir(parents=True)
    (tmp_path / "data/interim/codeql_databases" / project_id).mkdir(parents=True)
    run_root = tmp_path / "results/reproduction/iris_gptoss20b/test_run"
    workspace = _prepare_iris_workspace(
        tmp_path, run_root, [{"project_id": project_id, "project_slug": slug}]
    )
    alias = workspace["package_root"] / alias_name
    assert alias.is_symlink()
    assert alias.read_text(encoding="utf-8") == "org.hl7.fhir\n"
    assert not (raw / alias_name).exists()


def test_analysis_runner_does_not_reference_evaluator_only_view() -> None:
    runner = Path("src/reproduction/runner.py").read_text(encoding="utf-8")
    assert "evaluator_only" not in runner
