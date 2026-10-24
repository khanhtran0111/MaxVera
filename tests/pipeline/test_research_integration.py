"""Smoke-only research reasoning integration preserves candidates and honest budgets."""

import json

from maxvera.cli import main
from maxvera.orchestration import Context
from src.reproduction.common import atomic_jsonl


def config_fixture(root):
    (root / "cases.csv").write_text("project_id,source_dir\na,projects/a\nb,projects/b\n")
    (root / "variants.yaml").write_text(
        """variants:
  graph_llm_verify:
    graph_enabled: true
    llm_enabled: true
    targeted_verification: true
    candidate_sources: [sink_backward_slice]
    retrieval: minimal_subgraph
"""
    )
    config = root / "research.yaml"
    config.write_text(
        """pipeline: research
dataset:
  analysis_manifest: cases.csv
  expected_cases: 2
variants:
  config: variants.yaml
research:
  graph_signal_approved: false
budgets:
  max_calls_per_case: 3
  max_cost_usd_per_case: 0.1
"""
    )
    return config


def test_llm_smoke_dry_run_reports_nonzero_call_and_cost_ceiling(tmp_path, capsys):
    config = config_fixture(tmp_path)
    result = main(
        [
            "--root",
            str(tmp_path),
            "pipeline",
            "research",
            "--config",
            str(config),
            "--variant",
            "graph_llm_verify",
            "--mode",
            "smoke",
            "--limit",
            "2",
            "--run-id",
            "dry",
            "--dry-run",
        ]
    )
    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["expected_requests_upper_bound"] == 6
    assert report["configured_cost_ceiling_usd"] == 0.2
    assert not (tmp_path / "results").exists()


def test_full_llm_research_without_dev_signal_is_blocked_before_execution(tmp_path, capsys):
    config = config_fixture(tmp_path)
    result = main(
        [
            "--root",
            str(tmp_path),
            "pipeline",
            "research",
            "--config",
            str(config),
            "--variant",
            "graph_llm_verify",
            "--mode",
            "full",
            "--run-id",
            "blocked",
            "--execute",
        ]
    )
    assert result == 2
    assert "development signal" in capsys.readouterr().err
    assert not (tmp_path / "results").exists()


def test_negative_reasoning_and_no_flow_preserve_candidates_and_pre_ranks(tmp_path):
    from maxvera.research import final_rank

    case = {"case_id": "opaque"}
    run = tmp_path / "run"
    base = run / "stages/opaque"
    for name in ["candidate_rank", "llm_reason", "targeted_verify", "final_rank"]:
        (base / name).mkdir(parents=True)
    original = [
        dict(candidate_id="c1", rank_pre_llm=1, score=8.0),
        dict(candidate_id="c2", rank_pre_llm=2, score=7.5),
    ]
    atomic_jsonl(base / "candidate_rank/candidates_ranked.jsonl", original)
    reasoned = [
        {
            **original[0],
            "llm_score_delta": -1,
            "llm_assessment": {"status": "VALID", "verdict": "NOT_SUPPORTED"},
        },
        {
            **original[1],
            "llm_score_delta": 1,
            "llm_assessment": {"status": "VALID", "verdict": "SUPPORTED"},
        },
    ]
    atomic_jsonl(base / "llm_reason/candidates_reasoned.jsonl", reasoned)
    atomic_jsonl(
        base / "targeted_verify/verification.jsonl",
        [
            {"candidate_id": "c1", "status": "NO_FLOW_FOUND"},
            {"candidate_id": "c2", "status": "FLOW_FOUND"},
        ],
    )
    ctx = Context(
        tmp_path,
        run,
        base / "final_rank",
        case,
        {"selected_variant": {"llm_enabled": True, "targeted_verification": True}},
        {"llm_reason": {"status": "SUCCESS"}, "targeted_verify": {"status": "SUCCESS"}},
    )
    final_rank(ctx)
    findings = [
        json.loads(line) for line in (base / "final_rank/findings.jsonl").read_text().splitlines()
    ]
    assert [r["candidate_id"] for r in findings] == ["c2", "c1"]
    c1 = next(r for r in findings if r["candidate_id"] == "c1")
    assert c1["rank_pre_llm"] == 1
    assert c1["verification_status"] == "NO_FLOW_FOUND"
    assert c1["decision"] == "REVIEW"
    assert len(findings) == 2
    assert (
        json.loads((base / "candidate_rank/candidates_ranked.jsonl").read_text().splitlines()[0])
        == original[0]
    )


def test_research_dag_runs_evidence_reasoning_and_verification_in_order():
    from maxvera.research import stages

    dag = {s.name: s for s in stages()}
    assert "evidence_retrieve" in dag["llm_reason"].dependencies
    assert "llm_reason" in dag["targeted_verify"].dependencies
    assert "targeted_verify" in dag["final_rank"].dependencies
    assert dag["llm_reason"].paid is True


def test_variant_catalogue_cannot_inject_oracle_metadata(tmp_path, capsys):
    config = config_fixture(tmp_path)
    variants = tmp_path / "variants.yaml"
    variants.write_text(variants.read_text() + "    target_cwe: CWE-22\n")
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "pipeline",
                "research",
                "--config",
                str(config),
                "--variant",
                "graph_llm_verify",
                "--mode",
                "smoke",
                "--run-id",
                "leak",
                "--dry-run",
            ]
        )
        == 2
    )
    assert "variant" in capsys.readouterr().err


def test_string_false_does_not_approve_full_research(tmp_path, capsys):
    config = config_fixture(tmp_path)
    config.write_text(
        config.read_text().replace("graph_signal_approved: false", 'graph_signal_approved: "false"')
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
                "--variant",
                "graph_llm_verify",
                "--mode",
                "full",
                "--run-id",
                "bad",
                "--execute",
            ]
        )
        == 2
    )
    assert not (tmp_path / "results").exists()


def test_codeql_build_wrapper_preserves_spaces_and_shell_literals(tmp_path):
    import subprocess
    import sys

    from maxvera.research import write_build_script

    output = tmp_path / "arguments.json"
    sentinel = tmp_path / "must-not-exist"
    args = ["two words", "single'quote", "$(touch " + str(sentinel) + ")"]
    code = 'import json,sys;json.dump(sys.argv[2:],open(sys.argv[1],"w"))'
    script = tmp_path / "build command.sh"
    command = write_build_script(script, [sys.executable, "-c", code, str(output), *args])
    assert command.startswith('/bin/sh "')
    subprocess.run(["/bin/sh", str(script)], check=True)
    assert json.loads(output.read_text()) == args
    assert not sentinel.exists()
