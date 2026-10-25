"""Build bookkeeping must not make identical frozen discovery pools incomparable."""

from maxvera.evaluation import candidate_pool_hash, condition_manifest
from src.reproduction.common import atomic_json


def test_candidate_pool_identity_keeps_semantics_and_ignores_full_build_digest():
    first = {
        "case_id": "opaque",
        "snapshot_id": "semantic",
        "candidate_id": "candidate",
        "locations": [{"file": "App.java", "start_line": 2}],
        "provenance": {"graph_hash": "graph", "analyzed_snapshot_id": "build-one"},
    }
    second = {**first, "provenance": {**first["provenance"], "analyzed_snapshot_id": "build-two"}}
    assert candidate_pool_hash([first]) == candidate_pool_hash([second])
    second["locations"] = [{"file": "App.java", "start_line": 3}]
    assert candidate_pool_hash([first]) != candidate_pool_hash([second])


def test_research_comparison_conditions_use_semantic_source_identity(tmp_path):
    manifests = []
    for build in ("one", "two"):
        run = tmp_path / build
        atomic_json(run / "stages/opaque/ingest/snapshot.json", {"snapshot_id": "input"})
        atomic_json(
            run / "stages/opaque/static_extract/analyzed_snapshot.json",
            {"analyzed_snapshot_id": build, "semantic_snapshot_id": "semantic"},
        )
        manifests.append(
            condition_manifest(
                run,
                {
                    "case_ids": ["opaque"],
                    "pipeline": "research",
                    "mode": "full",
                    "input_hash": "input",
                    "implementation_hash": "implementation",
                },
                {},
                {"implementation_hash": "evaluator"},
                "labels",
                "truth",
                "zero_hint",
            )
        )
    assert manifests[0] == manifests[1]
