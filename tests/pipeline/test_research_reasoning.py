"""Research reasoning must preserve discovery and accept only cited evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maxvera.contracts import digest
from maxvera.orchestration import Context
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def fixture_context(tmp_path: Path, stage: str, count: int = 2) -> Context:
    run = tmp_path / "run"
    base = run / "stages/opaque-case"
    workspace = base / "static_extract/workspace"
    workspace.mkdir(parents=True)
    code = workspace / "App.java"
    code.write_text(
        'class App {\n String input = System.getenv("VALUE");\n'
        " void sink() { System.out.println(input); }\n}\n"
    )
    file_hash = sha256_file(code)
    nodes = [
        {
            "node_id": "source",
            "file": "App.java",
            "start_line": 2,
            "end_line": 2,
            "start_column": 2,
            "end_column": 39,
            "roles": ["source"],
            "kind": "MethodCall",
            "content_hash": file_hash,
        },
        {
            "node_id": "sink",
            "file": "App.java",
            "start_line": 3,
            "end_line": 3,
            "start_column": 16,
            "end_column": 40,
            "roles": ["sink"],
            "kind": "MethodCall",
            "content_hash": file_hash,
        },
    ]
    graph = {
        "snapshot_id": "frozen-snapshot",
        "graph_hash": "frozen-graph",
        "nodes": nodes,
        "edges": [{"edge_id": "edge", "src": "source", "dst": "sink", "kind": "MAY_FLOW"}],
    }
    atomic_json(base / "build_graph/graph.json", graph)
    candidates = [
        {
            "case_id": "opaque-case",
            "snapshot_id": "frozen-snapshot",
            "candidate_id": f"cand-{i}",
            "rank_pre_llm": i,
            "rank_post_llm": None,
            "score": 5 - i,
            "decision": "REVIEW",
            "source_node_id": "source",
            "sink_node_id": "sink",
            "graph_path_node_ids": ["source", "sink"],
            "graph_path_edge_ids": ["edge"],
            "locations": [{"file": "App.java", "start_line": 2, "end_line": 3}],
        }
        for i in range(1, count + 1)
    ]
    atomic_jsonl(base / "candidate_rank/candidates_ranked.jsonl", candidates)
    folder = base / stage
    folder.mkdir(parents=True)
    return Context(
        tmp_path,
        run,
        folder,
        {"case_id": "opaque-case"},
        {
            "selected_variant": {"llm_enabled": True, "targeted_verification": True},
            "evidence": {"max_context_tokens_per_call": 8192, "max_graph_hops": 2},
            "budgets": {},
            "llm": {"model_config": "unused"},
            "codeql": {
                "research_binary": "codeql",
                "per_query_timeout_s": 30,
                "ram_mb": 1024,
                "threads": 1,
            },
        },
        {
            "static_extract": {
                "result": {
                    "analyzed_snapshot_id": "frozen-snapshot",
                    "analyzed_files": {"App.java": file_hash},
                }
            }
        },
    )


def _retrieve(ctx):
    from maxvera.research_reasoning import evidence_retrieve

    ctx.stage_dir = ctx.run_dir / "stages/opaque-case/evidence_retrieve"
    ctx.stage_dir.mkdir(parents=True, exist_ok=True)
    result = evidence_retrieve(ctx)
    ctx.results["evidence_retrieve"] = {"result": result}
    ctx.stage_dir = ctx.run_dir / "stages/opaque-case/llm_reason"
    ctx.stage_dir.mkdir(parents=True, exist_ok=True)
    return read_jsonl(ctx.run_dir / "stages/opaque-case/evidence_retrieve/evidence_bundles.jsonl")


def test_evidence_is_source_backed_and_keeps_frozen_candidate_identity(tmp_path):
    ctx = fixture_context(tmp_path, "evidence_retrieve")
    bundles = _retrieve(ctx)
    assert [b["candidate_id"] for b in bundles] == ["cand-1", "cand-2"]
    assert all(b["evidence_bundle_id"] for b in bundles)
    assert all(b["code_spans"] and b["graph_nodes"] for b in bundles)
    assert 'System.getenv("VALUE")' in bundles[0]["code_spans"][0]["code"]
    assert all(len(json.dumps(b).encode()) <= 8192 for b in bundles)
    assert bundles[0]["evidence_bundle_id"] != bundles[1]["evidence_bundle_id"]


def test_source_mutation_cannot_be_accepted_as_evidence(tmp_path):
    from maxvera.research_reasoning import evidence_retrieve

    ctx = fixture_context(tmp_path, "evidence_retrieve")
    (ctx.run_dir / "stages/opaque-case/static_extract/workspace/App.java").write_text("changed")
    with pytest.raises(ValueError, match=r"hash|snapshot|changed"):
        evidence_retrieve(ctx)


def test_negative_verdicts_rerank_without_removing_any_candidate(tmp_path):
    from maxvera.research_reasoning import llm_reason

    ctx = fixture_context(tmp_path, "llm_reason")
    bundles = _retrieve(ctx)
    original = (
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    ).read_bytes()

    class Client:
        def preflight(self, messages, **kwargs):
            return {}

        def complete(self, messages, **kwargs):
            bundle = json.loads(messages[-1]["content"])
            return json.dumps(
                {
                    "candidate_id": bundle["candidate_id"],
                    "evidence_bundle_id": bundle["evidence_bundle_id"],
                    "verdict": "NOT_SUPPORTED"
                    if bundle["candidate_id"] == "cand-1"
                    else "SUPPORTED",
                    "rationale": "Evidence supports this assessment.",
                    "citations": [bundle["code_spans"][0]["evidence_id"]],
                }
            )

    result = llm_reason(ctx, client=Client())
    rows = read_jsonl(ctx.stage_dir / "candidates_reasoned.jsonl")
    assert len(rows) == 2
    assert {r["candidate_id"] for r in rows} == {"cand-1", "cand-2"}
    assert {r["candidate_id"]: r["rank_pre_llm"] for r in rows} == {"cand-1": 1, "cand-2": 2}
    assert rows[0]["candidate_id"] == "cand-2"
    assert all(r["decision"] == "REVIEW" for r in rows)
    assert (
        ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    ).read_bytes() == original
    assert result["failed_assessments"] == 0
    assert len(bundles) == 2


@pytest.mark.parametrize("citation", [[], ["invented-evidence"]])
def test_missing_or_invented_citations_are_rejected_without_pruning(tmp_path, citation):
    from maxvera.research_reasoning import llm_reason

    ctx = fixture_context(tmp_path, "llm_reason", count=1)
    _retrieve(ctx)

    class Client:
        def preflight(self, messages, **kwargs):
            return {}

        def complete(self, messages, **kwargs):
            bundle = json.loads(messages[-1]["content"])
            return json.dumps(
                {
                    "candidate_id": bundle["candidate_id"],
                    "evidence_bundle_id": bundle["evidence_bundle_id"],
                    "verdict": "SUPPORTED",
                    "rationale": "This claim lacks valid evidence.",
                    "citations": citation,
                }
            )

    result = llm_reason(ctx, client=Client())
    assert result["failed_assessments"] == 1
    rows = read_jsonl(ctx.stage_dir / "candidates_reasoned.jsonl")
    assert len(rows) == 1
    assert rows[0]["llm_assessment"]["status"] == "INVALID_RESPONSE"
    assert rows[0]["llm_assessment"]["verdict"] == "UNCERTAIN"
    assert rows[0]["decision"] == "REVIEW"


def test_uncertain_provider_failure_stops_requests_but_preserves_candidates(tmp_path):
    from maxvera.research_reasoning import llm_reason

    ctx = fixture_context(tmp_path, "llm_reason")
    _retrieve(ctx)

    class Client:
        def preflight(self, messages, **kwargs):
            return {}

        def complete(self, messages, **kwargs):
            raise RuntimeError("remote charge uncertain; inspect journal before retry")

    result = llm_reason(ctx, client=Client())
    assert result["failed_assessments"] == 2
    rows = read_jsonl(ctx.stage_dir / "candidates_reasoned.jsonl")
    assert [r["llm_assessment"]["status"] for r in rows] == [
        "PROVIDER_FAILED",
        "NOT_ATTEMPTED_PROVIDER_STOP",
    ]
    assert all(r["decision"] == "REVIEW" for r in rows)


def test_bundle_hash_tampering_cannot_create_accepted_assessment(tmp_path):
    from maxvera.research_reasoning import validate_assessment

    ctx = fixture_context(tmp_path, "llm_reason", count=1)
    bundle = _retrieve(ctx)[0]
    assessment = {
        "candidate_id": bundle["candidate_id"],
        "evidence_bundle_id": digest("wrong"),
        "verdict": "SUPPORTED",
        "rationale": "claim",
        "citations": [bundle["code_spans"][0]["evidence_id"]],
    }
    with pytest.raises(ValueError, match=r"bundle|identity"):
        validate_assessment(assessment, bundle)


def test_malformed_verdict_is_invalid_response_without_losing_candidate(tmp_path):
    from maxvera.research_reasoning import llm_reason

    ctx = fixture_context(tmp_path, "llm_reason", count=1)
    _retrieve(ctx)

    class Client:
        def preflight(self, messages, **kwargs):
            return {}

        def complete(self, messages, **kwargs):
            bundle = json.loads(messages[-1]["content"])
            return json.dumps(
                {
                    "candidate_id": bundle["candidate_id"],
                    "evidence_bundle_id": bundle["evidence_bundle_id"],
                    "verdict": {"unexpected": "object"},
                    "rationale": "malformed verdict",
                    "citations": [bundle["code_spans"][0]["evidence_id"]],
                }
            )

    result = llm_reason(ctx, client=Client())
    assert result["failed_assessments"] == 1
    rows = read_jsonl(ctx.stage_dir / "candidates_reasoned.jsonl")
    assert len(rows) == 1
    assert rows[0]["llm_assessment"]["status"] == "INVALID_RESPONSE"


def test_tampered_bundle_content_is_rejected_before_paying(tmp_path):
    from maxvera.research_reasoning import llm_reason

    ctx = fixture_context(tmp_path, "llm_reason", count=1)
    bundles = _retrieve(ctx)
    bundles[0]["code_spans"][0]["code"] = "fabricated code"
    atomic_jsonl(
        ctx.run_dir / "stages/opaque-case/evidence_retrieve/evidence_bundles.jsonl", bundles
    )

    class Client:
        def preflight(self, messages, **kwargs):
            pytest.fail("tampered evidence must not reach provider preflight")

    with pytest.raises(ValueError, match=r"bundle|hash|evidence"):
        llm_reason(ctx, client=Client())


def test_large_code_span_keeps_bounded_actual_code_evidence(tmp_path):
    ctx = fixture_context(tmp_path, "evidence_retrieve", count=1)
    path = ctx.run_dir / "stages/opaque-case/static_extract/workspace/App.java"
    path.write_text("\n".join("x" * 600 for _ in range(100)))
    content = sha256_file(path)
    ctx.results["static_extract"]["result"]["analyzed_files"]["App.java"] = content
    graph_file = ctx.run_dir / "stages/opaque-case/build_graph/graph.json"
    graph = json.loads(graph_file.read_text())
    for node in graph["nodes"]:
        node["content_hash"] = content
        node["end_line"] = 90
    atomic_json(graph_file, graph)
    candidate_file = ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    candidates = read_jsonl(candidate_file)
    candidates[0]["locations"][0]["end_line"] = 90
    atomic_jsonl(candidate_file, candidates)
    bundle = _retrieve(ctx)[0]
    assert bundle["code_spans"]
    assert bundle["code_spans"][0]["truncated"] is True
    assert bundle["retrieval_truncated"] is True
    assert len(bundle["code_spans"][0]["code"].encode()) <= 1536


def test_static_path_keeps_both_ends_and_reports_omitted_context(tmp_path):
    ctx = fixture_context(tmp_path, "evidence_retrieve", count=1)
    workspace = ctx.run_dir / "stages/opaque-case/static_extract/workspace"
    locations = []
    for i in range(25):
        path = workspace / f"Step{i}.java"
        path.write_text(f"class Step{i} {{ void step() {{}} }}\n")
        ctx.results["static_extract"]["result"]["analyzed_files"][path.name] = sha256_file(path)
        locations.append({"file": path.name, "start_line": 1, "end_line": 1})
    candidate_file = ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    candidates = read_jsonl(candidate_file)
    candidates[0].update(
        source_node_id=None,
        sink_node_id=None,
        graph_path_node_ids=[],
        graph_path_edge_ids=[],
        locations=locations,
    )
    atomic_jsonl(candidate_file, candidates)
    original = candidate_file.read_bytes()
    bundle = _retrieve(ctx)[0]
    assert [span["file"] for span in bundle["code_spans"][:2]] == ["Step0.java", "Step24.java"]
    assert bundle["retrieval_truncated"] is True
    assert bundle["graph_nodes"] == []
    assert candidate_file.read_bytes() == original


def test_graph_context_cannot_crowd_out_endpoint_code(tmp_path):
    ctx = fixture_context(tmp_path, "evidence_retrieve", count=1)
    graph_file = ctx.run_dir / "stages/opaque-case/build_graph/graph.json"
    graph = json.loads(graph_file.read_text())
    graph["nodes"] += [
        {**graph["nodes"][0], "node_id": f"context-{i}", "kind": "X" * 400} for i in range(23)
    ]
    atomic_json(graph_file, graph)
    candidate_file = ctx.run_dir / "stages/opaque-case/candidate_rank/candidates_ranked.jsonl"
    candidates = read_jsonl(candidate_file)
    candidates[0]["graph_path_node_ids"] += [f"context-{i}" for i in range(23)]
    atomic_jsonl(candidate_file, candidates)
    bundle = _retrieve(ctx)[0]
    assert any('System.getenv("VALUE")' in span["code"] for span in bundle["code_spans"])
    assert any("System.out.println" in span["code"] for span in bundle["code_spans"])
    assert bundle["retrieval_truncated"] is True
    assert len(json.dumps(bundle, ensure_ascii=False).encode()) <= 8192
