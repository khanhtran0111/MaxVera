"""Contract breaks: unsafe config, corrupt checkpoints and duplicate paid work."""

import json

import pytest


def test_config_validates_budgets_redacts_and_rejects_oracle_keys(tmp_path):
    from maxvera.contracts import PipelineConfig, redact

    path = tmp_path / "pipeline.yaml"
    path.write_text(
        "pipeline: research\nruntime:\n  project_workers: 1\nbudgets:\n  max_calls_per_case: 3\n"
    )
    config = PipelineConfig.load(path)
    assert config.budgets.max_calls_per_case == 3
    assert redact({"api_key": "private", "nested": {"authorization": "Bearer x"}}) == {
        "api_key": "[REDACTED]",
        "nested": {"authorization": "[REDACTED]"},
    }
    path.write_text("pipeline: research\nbudgets:\n  max_calls_per_case: 0\n")
    with pytest.raises(ValueError, match="positive"):
        PipelineConfig.load(path)
    path.write_text("pipeline: research\ndataset:\n  target_cwe: CWE-78\n")
    with pytest.raises(ValueError, match=r"unknown|protected"):
        PipelineConfig.load(path)


def test_resume_reuses_completed_stage_and_retries_failed_stage(tmp_path):
    from maxvera.orchestration import Orchestrator, Stage

    calls = []

    def first(ctx):
        calls.append("first")
        (ctx.stage_dir / "raw.json").write_text('{"ok": true}')
        return {"artifacts": ["raw.json"]}

    def second(ctx):
        calls.append("second")
        if calls.count("second") == 1:
            raise RuntimeError("interrupted query")
        return {"artifacts": []}

    stages = [Stage("first", first), Stage("second", second, ("first",))]
    kwargs = dict(
        root=tmp_path,
        pipeline="reproduction",
        run_id="test",
        config={"budget": 2},
        cases=[{"case_id": "opaque-1"}],
        stages=stages,
        implementation_hash="code-1",
    )
    run = Orchestrator(**kwargs)
    assert run.execute() == "COMPLETED_WITH_CASE_FAILURES"
    assert Orchestrator(**kwargs, resume=True).execute() == "COMPLETED"
    assert calls == ["first", "second", "second"]
    with pytest.raises(ValueError, match=r"exists|immutable"):
        Orchestrator(**kwargs).execute()
    with pytest.raises(ValueError, match="mismatch"):
        Orchestrator(**{**kwargs, "implementation_hash": "changed"}, resume=True).execute()


def test_reference_branch_finishes_after_iris_failure(tmp_path):
    from maxvera.orchestration import Orchestrator, Stage

    def fail(ctx):
        raise RuntimeError("LLM unavailable")

    def reference(ctx):
        (ctx.stage_dir / "reference.sarif").write_text("{}")
        return {"artifacts": ["reference.sarif"]}

    stages = [
        Stage("llm_specs", fail),
        Stage("context_filter", fail, ("llm_specs",)),
        Stage("codeql_reference", reference),
    ]
    run = Orchestrator(
        tmp_path,
        "reproduction",
        "branch",
        {},
        [{"case_id": "opaque-1"}],
        stages,
        implementation_hash="code-1",
    )
    assert run.execute() == "COMPLETED_WITH_CASE_FAILURES"
    records = json.loads((run.path / "cases.jsonl").read_text())
    assert records["stages"]["codeql_reference"] == "SUCCESS"
    assert records["stages"]["context_filter"] == "BLOCKED_BY_DEPENDENCY"


def test_corrupt_stage_is_never_reused_and_uncertain_charge_is_blocked(tmp_path):
    from maxvera.orchestration import Orchestrator, Stage

    def work(ctx):
        (ctx.stage_dir / "result").write_text("actual")
        return {"artifacts": ["result"]}

    kwargs = dict(
        root=tmp_path,
        pipeline="reproduction",
        run_id="corrupt",
        config={},
        cases=[{"case_id": "opaque-1"}],
        stages=[Stage("llm", work, paid=True)],
        implementation_hash="code",
    )
    run = Orchestrator(**kwargs)
    assert run.execute() == "COMPLETED"
    (run.path / "stages/opaque-1/llm/result").write_text("tampered")
    with pytest.raises(ValueError, match=r"checksum|integrity"):
        Orchestrator(**kwargs, resume=True).execute()
    checkpoint = run.path / "stages/opaque-1/llm/stage.json"
    checkpoint.write_text('{"status":"RUNNING"}')
    (run.path / "STATUS").write_text("RUNNING\n")
    (run.path / "checksums.sha256").unlink()
    assert Orchestrator(**kwargs, resume=True).execute() == "COMPLETED_WITH_CASE_FAILURES"
    assert json.loads(checkpoint.read_text())["status"] == "UNCERTAIN_REMOTE_CALL"


def test_legacy_import_is_read_only_and_does_not_create_findings(tmp_path):
    from maxvera.legacy import index_exports

    old = tmp_path / "old.csv"
    old.write_text("projects,detected_projects\n120,36\n")
    before = old.read_bytes()
    result = index_exports([old])
    assert result["entries"][0]["rows"][0]["detected_projects"] == "36"
    assert old.read_bytes() == before
    assert "findings" not in result


def test_interruption_retains_pending_cases_and_run_lock(tmp_path):
    from maxvera.orchestration import Orchestrator, Stage

    def interrupted(ctx):
        raise KeyboardInterrupt()

    run = Orchestrator(
        tmp_path,
        "reproduction",
        "interrupt",
        {},
        [{"case_id": "opaque-1"}, {"case_id": "opaque-2"}],
        [Stage("remote", interrupted, paid=True)],
        implementation_hash="code",
    )
    with pytest.raises(KeyboardInterrupt):
        run.execute()
    rows = [json.loads(line) for line in (run.path / "cases.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    assert rows[1]["status"] == "PENDING"


def test_candidate_schema_is_immutable_and_rejects_unversioned_or_unsafe_output():
    from maxvera.schemas import Candidate

    record = {
        "schema_version": "2.0",
        "case_id": "opaque-1",
        "run_id": "graph-1",
        "snapshot_id": "hash",
        "candidate_id": "cand-1",
        "rank_pre_llm": 1,
        "locations": [{"file": "X.java", "start_line": 7, "end_line": 7}],
        "origin_generators": ["sink_backward_slice"],
        "discovery_status": "SINK_ONLY",
        "verification_status": "NOT_ATTEMPTED",
        "score": 0.2,
        "score_type": "UN-CALIBRATED-RANKING",
    }
    candidate = Candidate(record)
    record["locations"][0]["file"] = "changed.java"
    assert candidate.to_dict()["locations"][0]["file"] == "X.java"
    with pytest.raises(TypeError):
        candidate.document["candidate_id"] = "changed"
    with pytest.raises(ValueError, match="version"):
        Candidate({**candidate.to_dict(), "schema_version": "1.0"})
    with pytest.raises(ValueError, match="path"):
        Candidate(
            {
                **candidate.to_dict(),
                "locations": [{"file": "../secret", "start_line": 1, "end_line": 1}],
            }
        )
