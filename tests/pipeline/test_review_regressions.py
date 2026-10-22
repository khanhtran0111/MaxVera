"""Independent-review regressions: every test failed before its corresponding fix."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest


def _settings():
    from src.llm.providers.openrouter import OpenRouterSettings

    return OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "fixture-key",
        "openai/gpt-oss-20b",
        "fixture-provider",
        64,
        0,
        1,
        1234,
        "low",
        5,
        1,
    )


def test_iris_real_batch_shape_validates_json_without_forcing_json_object(tmp_path, monkeypatch):
    from maxvera.llm import IrisProvider

    seen = []

    def remote(client, messages, **kwargs):
        seen.append(kwargs["expect_json"])
        client._append_log({"status": "SUCCESS", "usage": {"cost": 0}, "finish_reason": "stop"})
        return "invalid" if len(seen) == 1 else "[]"

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    monkeypatch.setattr(IrisProvider, "settings", _settings())
    monkeypatch.setattr(
        IrisProvider, "request", {"journal": str(tmp_path), "budgets": {}, "stage": "llm_specs"}
    )
    provider = IrisProvider()
    assert provider.predict([[{"role": "user", "content": "original prompt"}]], batch_size=1) == [
        "[]"
    ]
    assert seen == [False, False]


def test_over_budget_response_cannot_be_replayed_or_used_by_next_stage(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    def remote(client, messages, **kwargs):
        client._append_log({"status": "SUCCESS", "usage": {"cost": 2}, "finish_reason": "stop"})
        return "[]"

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    for content in ("same", "same", "next-stage"):
        client = JournaledClient(
            replace(_settings(), max_retries=0), tmp_path, {"max_cost_usd_per_case": 1}
        )
        with pytest.raises(RuntimeError, match="budget"):
            client.complete([{"role": "user", "content": content}])


def test_landlock_protects_labels_source_and_other_runs_from_mutation(tmp_path):
    from maxvera.sandbox import landlock_available

    if not landlock_available():
        pytest.skip("Landlock unavailable")
    source, writable = tmp_path / "source", tmp_path / "current-run"
    source.mkdir()
    writable.mkdir()
    protected = tmp_path / "labels"
    protected.write_text("POISON_ORIGINAL")
    source_file = source / "X.java"
    source_file.write_text("class X {}")
    script = """from pathlib import Path
import sys
from maxvera.sandbox import restrict_reads
source,run,labels=map(Path,sys.argv[1:])
restrict_reads([source], write_paths=[run])
(run/'result').write_text('safe')
assert (source/'X.java').read_text()=='class X {}'
for target in [labels,source/'X.java']:
 for operation in [lambda:target.write_text('corrupt'),lambda:target.unlink()]:
  try:operation()
  except PermissionError:continue
  raise AssertionError('protected file mutated')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(source), str(writable), str(protected)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert protected.read_text() == "POISON_ORIGINAL"
    assert source_file.read_text() == "class X {}"
    assert (writable / "result").read_text() == "safe"


def test_research_builds_use_private_copy_and_record_actual_source_bytes(tmp_path, monkeypatch):
    from maxvera.orchestration import Context
    from maxvera.research import ingest, static_extract

    source = tmp_path / "data/processed/analysis_input/projects/opaque-1"
    source.mkdir(parents=True)
    (source / "X.java").write_text("class X {}")
    (source / "build.runtime.json").write_text(
        json.dumps({"attempts": [{"command": ["fixture-build"], "environment": {}}]})
    )
    binary = tmp_path / ".cache/toolchains/codeql"
    binary.parent.mkdir(parents=True)
    binary.write_text("fixture executable")
    run = tmp_path / "results/research/run"
    ing = run / "stages/opaque-1/ingest"
    ing.mkdir(parents=True)
    config = {
        "codeql": {
            "research_binary": str(binary),
            "generic_suite": "generic.qls",
            "ram_mb": 256,
            "threads": 1,
            "per_query_timeout_s": 10,
        },
        "budgets": {"timeout_case_s": 10},
        "selected_variant": {"graph_enabled": False},
    }
    case = {"case_id": "opaque-1", "source_dir": "projects/opaque-1"}
    ctx = Context(tmp_path, run, ing, case, config, {})
    snapshot = ingest(ctx)
    extract = run / "stages/opaque-1/static_extract"
    extract.mkdir(parents=True)
    ctx.stage_dir = extract
    ctx.results = {"ingest": {"status": "SUCCESS", "result": snapshot}}

    def command(args, *, cwd, log, **kwargs):
        log.write_text("fixture")
        if args[0] == "fixture-build":
            (cwd / "X.java").write_text("class X { int generated; }")
        elif args[1:3] == ["database", "create"]:
            Path(args[3]).mkdir(parents=True, exist_ok=True)
        elif args[1:3] == ["database", "analyze"]:
            Path(next(a.split("=", 1)[1] for a in args if a.startswith("--output="))).write_text(
                '{"runs":[{"results":[]}]}'
            )

    monkeypatch.setattr("maxvera.research.command", command)
    result = static_extract(ctx)
    assert (source / "X.java").read_text() == "class X {}"
    assert result["analyzed_files"]["X.java"] != snapshot["files"]["X.java"]
    assert result["modified_input_files"] == ["X.java"]
    assert result["analyzed_snapshot_id"] != snapshot["snapshot_id"]


def test_resume_restores_only_validated_upstream_snapshot(tmp_path):
    from maxvera.orchestration import Context
    from maxvera.reproduction import restore_upstream

    run = tmp_path / "run"
    prior = run / "stages/opaque-1/candidate_extract/upstream_snapshot"
    prior.mkdir(parents=True)
    (prior / "candidate.csv").write_text("validated")
    workspace = run / "iris_workspace/opaque-1"
    (workspace / "output").mkdir(parents=True)
    (workspace / "output/candidate.csv").write_text("corrupted")
    (workspace / "output/partial-labels.json").write_text("[]")
    ctx = Context(
        tmp_path,
        run,
        run / "stages/opaque-1/llm_specs",
        {"case_id": "opaque-1"},
        {},
        {
            "candidate_extract": {
                "status": "SUCCESS",
                "result": {"upstream_snapshot": "upstream_snapshot"},
                "artifact_hashes": {
                    "upstream_snapshot/candidate.csv": __import__("hashlib")
                    .sha256(b"validated")
                    .hexdigest()
                },
            }
        },
    )
    restore_upstream(ctx, workspace)
    assert (workspace / "output/candidate.csv").read_text() == "validated"
    assert not (workspace / "output/partial-labels.json").exists()


def test_database_checkpoint_covers_relations_and_reference_inventories(tmp_path, monkeypatch):
    from maxvera.orchestration import Context
    from maxvera.reproduction import database_artifacts, reference

    stage = tmp_path / "stage"
    db = stage / "database"
    (db / "db-java/default").mkdir(parents=True)
    (db / "db-java/default/data.rel").write_text("relations")
    (db / "src.zip").write_text("source archive")
    (db / "codeql-database.yml").write_text("metadata")
    paths = database_artifacts(stage, db)
    assert "database/db-java/default/data.rel" in paths
    assert "database/src.zip" in paths
    binary = tmp_path / "codeql"
    binary.write_text("launcher")
    queries = tmp_path / "iris/src/queries"
    queries.mkdir(parents=True)
    for name in ("fetch_class_locs", "fetch_func_locs"):
        (queries / (name + ".ql")).write_text("import java\n")
    cfg = {
        "codeql": {
            "repro_binary": str(binary),
            "reference_suite": "suite-{cwe}",
            "ram_mb": 256,
            "threads": 1,
            "per_query_timeout_s": 10,
        },
        "reproduction": {"iris_root": "iris"},
    }

    def command(args, *, log, **kwargs):
        log.write_text("fixture")
        output = next((a.split("=", 1)[1] for a in args if a.startswith("--output=")), None)
        if output:
            Path(output).write_text(
                '{"runs":[{"results":[]}]}'
                if output.endswith(".sarif")
                else "name,file,start_line,end_line\n"
            )

    monkeypatch.setattr("maxvera.reproduction.command", command)
    ctx = Context(
        tmp_path,
        tmp_path,
        stage,
        {"case_id": "opaque-1", "ground_truth_cwe": "CWE-78"},
        cfg,
        {"codeql_db": {"result": {"database": str(db)}}},
    )
    result = reference(ctx)
    assert {"class_locs_path.csv", "func_locs_path.csv"} <= set(result["artifacts"])


def _evaluation_fixture(root, name, *, source="source-1", file_only=False):
    from maxvera.orchestration import Orchestrator, Stage
    from src.reproduction.common import atomic_jsonl

    candidate = {
        "schema_version": "2.0",
        "run_id": name,
        "case_id": "opaque-1",
        "snapshot_id": source,
        "candidate_id": "c1",
        "rank_pre_llm": 1,
        "graph_path_edge_ids": ["e1"],
        "graph_path_node_ids": ["n1", "n2"],
        "locations": [{"file": "X.java", "start_line": 7, "end_line": 7}],
        "discovery_status": "COMPLETE_CANDIDATE_PATH",
        "origin_generators": ["sink_backward_slice"],
        "verification_status": "NOT_ATTEMPTED",
    }

    def finish(path, cases):
        atomic_jsonl(path / "candidates_pre_llm.jsonl", [candidate])
        atomic_jsonl(path / "candidates_raw.jsonl", [candidate])
        atomic_jsonl(path / "findings.jsonl", [candidate])

    run = Orchestrator(
        root,
        "research",
        name,
        {"dataset": {"track": "dev"}},
        [{"case_id": "opaque-1", "snapshot_content_hash": source}],
        [Stage("extract", lambda ctx: {"artifacts": []})],
        implementation_hash="same-code",
        finalizer=finish,
    )
    run.execute()
    labels = root / "labels.csv"
    labels.write_text("project_id,ground_truth_cwe\nopaque-1,CWE-78\n")
    truth = root / ("file_truth.jsonl" if file_only else "truth.jsonl")
    truth.write_text(
        json.dumps(
            {
                "project_id": "opaque-1",
                "file": "X.java",
                **({} if file_only else {"method_start": 5, "method_end": 9}),
            }
        )
        + "\n"
    )
    return run, labels, truth


def test_file_only_truth_never_inflates_strong_recall(tmp_path):
    from maxvera.evaluation import evaluate

    run, labels, truth = _evaluation_fixture(tmp_path, "file-only", file_only=True)
    output = evaluate(tmp_path, run.path, "zero_hint", labels=labels, truth=truth)
    metric = json.loads((output / "metrics_aggregate.json").read_text())
    row = json.loads((output / "metrics_per_case.jsonl").read_text())
    assert metric["discovery_recall_at_k"]["5"] == 0
    assert row["weak_location_matches"] == 1


def test_equivalent_default_alert_does_not_count_as_novel_graph_discovery():
    from maxvera.candidates import generate, rank
    from maxvera.graph import normalize_graph

    nodes = [
        {
            "key": key,
            "file": file,
            "start_line": "7",
            "end_line": "7",
            "start_column": "1",
            "end_column": "8",
            "kind": "MethodCall",
            "symbol": key,
            "role": role,
        }
        for key, file, role in [("source", "A.java", "source"), ("sink", "B.java", "sink")]
    ]
    graph = normalize_graph(
        "opaque-1",
        "source",
        nodes,
        [{"source": "source", "target": "sink", "kind": "MAY_FLOW"}],
        "query",
    )
    alert = {
        "path_evidence": "CODEQL_FLOW",
        "locations": [
            {"file": file, "start_line": 7, "end_line": 7} for file in ("A.java", "B.java")
        ],
    }
    candidates = rank(generate(graph, [alert]))
    assert len(candidates) == 1
    assert candidates[0]["default_alert_overlap"] is True
    assert set(candidates[0]["origin_generators"]) == {
        "static_alerts",
        "sink_backward_slice",
        "source_forward_slice",
    }


def test_compare_checks_integrity_and_snapshot_identity(tmp_path):
    from maxvera.evaluation import compare, evaluate

    one, labels, truth = _evaluation_fixture(tmp_path, "one")
    a = evaluate(tmp_path, one.path, "zero_hint", labels=labels, truth=truth)
    two, labels, truth = _evaluation_fixture(tmp_path, "two", source="different-source")
    b = evaluate(tmp_path, two.path, "zero_hint", labels=labels, truth=truth)
    with pytest.raises(ValueError, match=r"condition|snapshot|input"):
        compare([a, b], tmp_path / "comparison")
    (a / "metrics_aggregate.json").write_text('{"panel":"zero_hint"}')
    with pytest.raises(ValueError, match="checksum"):
        compare([a, b], tmp_path / "comparison")


def test_real_run_ids_and_ranking_do_not_change_frozen_pool_identity(tmp_path):
    from maxvera.evaluation import candidate_pool_hash, compare, evaluate

    one, labels, truth = _evaluation_fixture(tmp_path, "one")
    a = evaluate(tmp_path, one.path, "zero_hint", labels=labels, truth=truth)
    two, labels, truth = _evaluation_fixture(tmp_path, "two")
    b = evaluate(tmp_path, two.path, "zero_hint", labels=labels, truth=truth)
    assert compare([a, b], tmp_path / "paired", paired_llm=True).exists()
    assert candidate_pool_hash(
        [{"candidate_id": "c", "run_id": "one", "rank_pre_llm": 1}]
    ) == candidate_pool_hash([{"candidate_id": "c", "run_id": "two", "rank_pre_llm": 9}])


def test_evaluator_policy_change_rejects_silent_result_reuse(tmp_path, monkeypatch):
    import maxvera.evaluation as evaluation

    run, labels, truth = _evaluation_fixture(tmp_path, "one")
    evaluation.evaluate(tmp_path, run.path, "zero_hint", labels=labels, truth=truth)
    monkeypatch.setattr(evaluation, "MATCH_POLICY_VERSION", "changed-policy", raising=False)
    with pytest.raises(ValueError, match=r"evaluator|identity|input mismatch"):
        evaluation.evaluate(tmp_path, run.path, "zero_hint", labels=labels, truth=truth)


def test_database_identity_excludes_mutable_query_cache_and_dynamic_pools(tmp_path):
    from maxvera.reproduction import database_artifacts

    db = tmp_path / "database"
    for name in (
        "db-java/default/data.rel",
        "db-java/default/cache/version",
        "db-java/default/pools/max-id#Dynamic-New-Entities",
    ):
        path = db / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("content")
    artifacts = database_artifacts(tmp_path, db)
    assert "database/db-java/default/data.rel" in artifacts
    assert not any("/cache/" in path or "/pools/" in path for path in artifacts)


def test_reproduction_database_build_cannot_mutate_prepared_checkpoint(tmp_path, monkeypatch):
    from maxvera.orchestration import Context
    from maxvera.reproduction import codeql_db

    original = tmp_path / "prepared"
    original.mkdir()
    (original / "X.java").write_text("class X {}")
    binary = tmp_path / "codeql"
    binary.write_text("launcher")
    (tmp_path / "tools.yaml").write_text("build_attempts: []\n")
    stage = tmp_path / "run/stages/opaque-1/codeql_db"
    stage.mkdir(parents=True)

    def build(*args):
        return ["fixture-build"], {}

    monkeypatch.setattr("maxvera.reproduction.build_command_and_env", build)

    def command(args, *, cwd, log, **kwargs):
        log.write_text("fixture")
        if args[1:3] == ["database", "create"]:
            db = Path(args[3])
            db.mkdir()
            (db / "codeql-database.yml").write_text("database")
            (cwd / "X.java").write_text("class X { int analyzed; }")

    monkeypatch.setattr("maxvera.reproduction.command", command)
    config = {
        "reproduction": {"toolchains": "tools.yaml"},
        "budgets": {"timeout_case_s": 10},
        "codeql": {"repro_binary": str(binary), "threads": 1, "ram_mb": 256},
    }
    prep = {
        "source": str(original),
        "source_hash": "initial",
        "selected_build": {"option": {}, "command": ["fixture-build"]},
    }
    ctx = Context(
        tmp_path,
        tmp_path / "run",
        stage,
        {"case_id": "opaque-1"},
        config,
        {"prepare": {"result": prep}},
    )
    result = codeql_db(ctx)
    assert (original / "X.java").read_text() == "class X {}"
    assert (Path(result["source"]) / "X.java").read_text() == "class X { int analyzed; }"


def test_reference_inventory_queries_use_explicit_pinned_library_pack(tmp_path, monkeypatch):
    import yaml

    from maxvera.orchestration import Context
    from maxvera.reproduction import reference

    src = tmp_path / "iris/src/queries"
    src.mkdir(parents=True)
    for name in ("fetch_class_locs", "fetch_func_locs"):
        (src / (name + ".ql")).write_text("import java\n// original inventory semantics\n")
    stage = tmp_path / "stage"
    stage.mkdir()
    binary = tmp_path / "codeql"
    binary.write_text("launcher")

    def command(args, *, log, **kwargs):
        log.write_text("fixture")
        if args[1:3] == ["query", "run"]:
            query = Path(args[3])
            pack = yaml.safe_load((query.parent / "qlpack.yml").read_text())
            assert pack["dependencies"]["codeql/java-all"] == "0.8.3"
            assert query.read_text() == "import java\n// original inventory semantics\n"
        output = next((a.split("=", 1)[1] for a in args if a.startswith("--output=")), None)
        if output:
            Path(output).write_text(
                '{"runs":[{"results":[]}]}'
                if output.endswith(".sarif")
                else "name,file,start_line,end_line\n"
            )

    monkeypatch.setattr("maxvera.reproduction.command", command)
    config = {
        "codeql": {
            "repro_binary": str(binary),
            "reference_suite": "suite-{cwe}",
            "repro_java_all_version": "0.8.3",
            "ram_mb": 256,
            "threads": 1,
            "per_query_timeout_s": 10,
        },
        "reproduction": {"iris_root": "iris"},
    }
    ctx = Context(
        tmp_path,
        tmp_path,
        stage,
        {"case_id": "opaque-1", "ground_truth_cwe": "CWE-78"},
        config,
        {"codeql_db": {"result": {"database": "database"}}},
    )
    reference(ctx)


def test_case_deadline_limits_each_new_command_and_blocks_expired_work(tmp_path, monkeypatch):
    from maxvera.orchestration import Context, StageFailure

    monkeypatch.setattr("maxvera.orchestration.time.monotonic", lambda: 20)
    ctx = Context(tmp_path, tmp_path, tmp_path, {}, {}, {}, deadline=25)
    assert ctx.remaining_seconds(100) == 5
    assert ctx.remaining_seconds(2) == 2
    ctx.deadline = 19
    with pytest.raises(StageFailure, match="deadline"):
        ctx.remaining_seconds(100)


def test_orchestrator_passes_case_deadline_to_real_stage_context(tmp_path):
    import math

    from maxvera.orchestration import Orchestrator, Stage

    seen = []

    def stage(ctx):
        seen.append(ctx.deadline)
        return {"artifacts": []}

    run = Orchestrator(
        tmp_path,
        "reproduction",
        "deadline",
        {"budgets": {"timeout_case_s": 2}},
        [{"case_id": "opaque-1"}],
        [Stage("work", stage)],
        implementation_hash="code",
    )
    assert run.execute() == "COMPLETED"
    assert math.isfinite(seen[0])
