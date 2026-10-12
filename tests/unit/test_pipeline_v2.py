"""Regressions for grounding, ambiguous mapping, endpoint resolution and calibration gates."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

from src.graphs.evidence.model import cycle_nodes
from src.pipeline_v2.calibration import accept_policy, eligibility
from src.pipeline_v2.graphs import program_graph, useg_project
from src.pipeline_v2.model import candidates_from_flows, inventory_records, map_endpoint
from src.pipeline_v2.queries import bindings, endpoint_query, resolution_complete
from src.pipeline_v2.runtime import (
    Run,
    development_ids,
    entity_rows,
    source_text_fingerprint,
    unique_inventory_rows,
)
from src.pipeline_v2.specifications import context_plan
from src.pipeline_v2.verification import differential_status, evidence_delta
from src.specification.schema import endpoint_role_allowed


def inventory() -> list[dict[str, Any]]:
    common = {
        "file": "src/A.java",
        "start_column": "5",
        "end_column": "9",
        "end_line": "10",
        "start_line": "10",
        "enclosing_callable": "a.A#run(String)",
        "expression_kind": "VarAccess",
        "dataflow_kind": "expr",
        "slot": "argument:0",
        "target_signature": "a.Service#read(String)",
        "expression": "input",
        "source_text_sha256": "d" * 64,
    }
    rows = [
        {**common, "role": "source", "cwe": "", "basis": "remote-flow-source"},
        {
            **common,
            "start_line": "20",
            "end_line": "20",
            "role": "sink",
            "cwe": "CWE-22",
            "target_signature": "java.io.File#File(String)",
            "expression": "path",
            "basis": "path-injection",
        },
    ]
    return inventory_records(
        "proj_fixture", rows, {"src/A.java": "a" * 64}, {"query_sha256": "b" * 64}
    )


def discovery(
    endpoints: list[dict[str, Any]], kind: str = "GLOBAL_TAINT_CANDIDATE"
) -> dict[str, str]:
    row = {"cwe": "CWE-22", "evidence_kind": kind}
    for role in ("source", "sink"):
        node = next(endpoint for endpoint in endpoints if role in endpoint["roles"])
        descriptor = node["descriptor"]
        for suffix, field in (
            ("file", "file"),
            ("line", "start_line"),
            ("column", "start_column"),
            ("end_line", "end_line"),
            ("end_column", "end_column"),
            ("dataflow_kind", "dataflow_kind"),
        ):
            row[role + "_" + suffix] = str(descriptor[field])
    return row


def graph(
    kind: str = "GLOBAL_TAINT_CANDIDATE",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    endpoints = inventory()
    hypotheses, _ = candidates_from_flows("proj_fixture", endpoints, [discovery(endpoints, kind)])
    program, _ = program_graph(hypotheses)
    return useg_project(hypotheses, program, {"CWE-22": {"node_id": "cwe22"}}, {"run_id": "kg"})


def test_missing_or_ambiguous_endpoint_cannot_become_hypothesis() -> None:
    endpoints = inventory()
    row = discovery(endpoints)
    hypotheses, rejected = candidates_from_flows("proj_fixture", [], [row])
    assert not hypotheses and rejected[0]["reason"] == "AMBIGUOUS_OR_MISSING_BINDING"
    clone = copy.deepcopy(endpoints[0])
    clone["node_id"] = "ambiguous"
    hypotheses, rejected = candidates_from_flows("proj_fixture", [*endpoints, clone], [row])
    assert not hypotheses and rejected[0]["matches"] == 2


def test_stable_semantic_identity_survives_line_shift() -> None:
    before = inventory()
    source = next(node for node in before if "source" in node["roles"])
    shifted = copy.deepcopy(source)
    shifted["descriptor"]["start_line"] += 4
    shifted["descriptor"]["end_line"] += 4
    shifted["descriptor"]["source_sha256"] = "c" * 64
    mapped, record = map_endpoint(source, [shifted], unchanged_line=14)
    assert mapped is shifted and record["strategy"] == "EXACT_LINE_AND_SEMANTICS"


@pytest.mark.parametrize(
    "field,value",
    [
        ("enclosing_callable", "a.A#other(String)"),
        ("expression", "other"),
        ("slot", "argument:1"),
        ("target_signature", "other.Service#read(String)"),
    ],
)
def test_matching_line_never_overrides_changed_semantics(field: str, value: str) -> None:
    source = next(node for node in inventory() if "source" in node["roles"])
    changed = copy.deepcopy(source)
    changed["descriptor"][field] = value
    mapped, record = map_endpoint(source, [changed], unchanged_line=10)
    assert mapped is None and not record["complete"]


def test_rename_requires_unique_semantic_match() -> None:
    source = next(node for node in inventory() if "source" in node["roles"])
    renamed = copy.deepcopy(source)
    renamed["descriptor"]["file"] = "renamed/A.java"
    assert map_endpoint(source, [renamed])[1]["strategy"] == "FILE_RENAME_AND_SEMANTICS"
    duplicate = copy.deepcopy(renamed)
    duplicate["descriptor"]["file"] = "copied/A.java"
    assert map_endpoint(source, [renamed, duplicate])[0] is None
    same_path_duplicate = copy.deepcopy(source)
    same_path_duplicate["descriptor"]["start_line"] = 30
    same_path_duplicate["descriptor"]["end_line"] = 30
    assert map_endpoint(source, [source, same_path_duplicate], unchanged_line=10)[0] is None


def test_source_sink_model_changes_fail_closed() -> None:
    source = next(node for node in inventory() if "source" in node["roles"])
    changed = copy.deepcopy(source)
    changed["models"][0]["basis"] = "unrelated-source"
    assert map_endpoint(source, [changed])[0] is None


def test_same_printed_call_with_changed_argument_is_not_equivalent() -> None:
    source = next(node for node in inventory() if "source" in node["roles"])
    changed = copy.deepcopy(source)
    changed["descriptor"]["source_text_sha256"] = "e" * 64
    assert map_endpoint(source, [changed], unchanged_line=10)[0] is None


def test_stronger_candidate_relation_survives_discovery_duplicates() -> None:
    endpoints = inventory()
    for node in endpoints:
        node["descriptor"]["file"] = "src/test/A.java"
    hypotheses, _ = candidates_from_flows(
        "proj_fixture",
        endpoints,
        [discovery(endpoints), discovery(endpoints, "SAME_CALLABLE_NO_FLOW_PROOF")],
    )
    assert hypotheses[0]["evidence_kind"] == "GLOBAL_TAINT_CANDIDATE"
    assert hypotheses[0]["score"] == 0.6
    assert not hypotheses[0]["application_source_priority"]


def test_direct_source_call_consumed_as_sink_has_distinct_role_bindings() -> None:
    endpoints = inventory()
    source = next(node for node in endpoints if "source" in node["roles"])
    sink = next(node for node in endpoints if "sink" in node["roles"])
    source["descriptor"]["slot"] = "return"
    for field in ("file", "start_line", "start_column", "end_line", "end_column", "expression"):
        sink["descriptor"][field] = source["descriptor"][field]
    hypotheses, rejected = candidates_from_flows("proj_fixture", endpoints, [discovery(endpoints)])
    assert len(hypotheses) == 1 and not rejected
    nodes, edges = program_graph(hypotheses)
    useg, _ = useg_project(hypotheses, nodes, {"CWE-22": {"node_id": "cwe22"}}, {"run_id": "kg"})
    by_id = {node["node_id"]: node for node in useg}
    source_node = next(
        node
        for node in useg
        if node["layer"] == "program" and node["properties"]["endpoint_roles"] == ["source"]
    )
    sink_node = next(
        node
        for node in useg
        if node["layer"] == "program" and node["properties"]["endpoint_roles"] == ["sink"]
    )
    frozen = bindings(
        {
            "sources": [{"node_id": source_node["node_id"]}],
            "sinks": [{"node_id": sink_node["node_id"]}],
        },
        by_id,
    )
    assert len(frozen) == 2 and not cycle_nodes(nodes, edges)


def test_structural_candidate_is_not_a_taint_path() -> None:
    nodes, edges = graph("SAME_CALLABLE_NO_FLOW_PROOF")
    assert not any(node["kind"] == "TAINT_PATH" for node in nodes)
    assert not cycle_nodes(nodes, edges)


@pytest.mark.parametrize("baseline", ["B6", "B7", "B8", "B9"])
def test_each_ablation_retains_resolved_hypothesis_roles(baseline: str) -> None:
    nodes, edges = graph()
    hypothesis = next(node for node in nodes if node["kind"] == "HYPOTHESIS")
    budget = {"max_context_tokens_per_call": 8192}
    text, metadata, by_id, _ = context_plan(nodes, edges, hypothesis, baseline, budget)
    assert text and metadata["request_estimate_tokens"] <= 8192
    choices = metadata["allowed_endpoint_ids_by_role"]
    specification = {
        "specification_id": "spec_fixture",
        "candidate_cwe": "CWE-22",
        "sources": [{"node_id": choices["sources"][0]}],
        "sinks": [{"node_id": choices["sinks"][0]}],
    }
    frozen = bindings(specification, by_id)
    query = endpoint_query(specification, frozen)
    assert "getStartColumn()" in query and "v2TargetSignature(node, role)" in query
    assert len(frozen) == 2
    rows = [{"role": entry["role"], "endpointId": entry["node_id"]} for entry in frozen]
    assert resolution_complete(frozen, rows)
    assert not resolution_complete(frozen, rows[:1])
    assert not resolution_complete(frozen, [*rows, rows[0]])


def test_v2_graph_membership_alone_does_not_allow_endpoint() -> None:
    nodes, _ = graph()
    program = next(node for node in nodes if node["layer"] == "program")
    invalid = copy.deepcopy(program)
    invalid["properties"]["binding_status"] = "UNRESOLVED"
    assert not endpoint_role_allowed("sources", invalid)
    invalid["properties"]["binding_status"] = "RESOLVED_VULNERABLE"
    invalid["properties"]["semantic_descriptor"]["enclosing_callable"] = ""
    assert not endpoint_role_allowed("sources", invalid)


@pytest.mark.parametrize(
    "field,value",
    [
        ("mapping_complete", False),
        ("resolution_complete", False),
        ("query_completed", False),
        ("path_count", None),
        ("path_count", 1),
    ],
)
def test_fixed_zero_or_unresolved_never_implies_verified(field: str, value: object) -> None:
    vulnerable = {"resolution_complete": True, "query_completed": True, "path_count": 1}
    fixed = {
        "mapping_complete": True,
        "resolution_complete": True,
        "query_completed": True,
        "path_count": 0,
        field: value,
    }
    assert differential_status(vulnerable, fixed) != "VERIFIED_DIFFERENTIAL"


def test_only_complete_two_sided_query_is_verified_and_links_remain_acyclic() -> None:
    vulnerable = {
        "resolution_complete": True,
        "query_completed": True,
        "path_count": 1,
        "paths": [[{"file": "src/A.java", "line": 10}, {"file": "src/A.java", "line": 20}]],
    }
    fixed = {
        "mapping_complete": True,
        "resolution_complete": True,
        "query_completed": True,
        "path_count": 0,
    }
    assert differential_status(vulnerable, fixed) == "VERIFIED_DIFFERENTIAL"
    assert differential_status({**vulnerable, "query_completed": False}, fixed).startswith(
        "UNVERIFIED"
    )
    nodes, edges = graph()
    hypothesis = next(node for node in nodes if node["kind"] == "HYPOTHESIS")
    base = {
        "project_id": "proj_fixture",
        "specification_id": "s",
        "candidate_cwe": "CWE-22",
        "hypothesis_id": hypothesis["properties"]["upstream_hypothesis_id"],
        "vulnerable": vulnerable,
    }
    delta_nodes, delta_edges = evidence_delta([{**base, "status": "VERIFIED_DIFFERENTIAL"}], "run")
    assert not cycle_nodes([*nodes, *delta_nodes], [*edges, *delta_edges])
    assert any(edge["kind"] == "VERIFIED_BY" for edge in delta_edges)
    _, unresolved_edges = evidence_delta(
        [{**base, "status": "UNVERIFIED_FIXED_ENDPOINT_MAPPING"}], "run"
    )
    assert not any(edge["kind"] in {"VERIFIED_BY", "CONTRADICTS"} for edge in unresolved_edges)


def test_calibration_requires_two_classes_groups_and_supported_training_folds() -> None:
    policy = {
        "minimum_repository_groups": 8,
        "minimum_records_per_class": 5,
        "minimum_groups_per_class": 2,
        "target": "candidate_cwe_correct_on_v3_verified_findings",
    }
    labels = [0, 1] * 8
    groups = [str(index) for index in range(8) for _ in range(2)]
    assert eligibility(labels, groups, policy)["eligible"]
    assert not eligibility([1] * 16, groups, policy)["eligible"]
    assert not eligibility(labels, ["one"] * 16, policy)["eligible"]
    single_fold = ["negative" if label == 0 else "positive" for label in labels]
    assert "SINGLE_CLASS_TRAINING_FOLD" in eligibility(labels, single_fold, policy)["reasons"]


def test_perfect_probability_does_not_enable_accept_without_support() -> None:
    policy = {
        "minimum_accept_count": 20,
        "minimum_accept_groups": 3,
        "accept_wilson_lower_bound": 0.8,
    }
    assert not accept_policy([1.0] * 2, [1] * 2, ["one", "two"], {"tau_accept": 1.0}, policy)[
        "enabled"
    ]
    assert not accept_policy([1.0] * 30, [1] * 30, ["one"] * 30, {"tau_accept": 1.0}, policy)[
        "enabled"
    ]


def test_run_refuses_overwrite_and_changed_resume_config(tmp_path: Path) -> None:
    split = tmp_path / "data/processed/splits/development.csv"
    split.parent.mkdir(parents=True)
    split.write_text("project_id\nproj_fixture\n")
    pack = tmp_path / "src/static_analysis/queries/v2"
    pack.mkdir(parents=True)
    (pack / "Grounding.qll").write_text("// fixture\n")
    (tmp_path / "model.yaml").write_text("fixture: true\n")
    config = tmp_path / "config.yaml"
    config.write_text("model_config: model.yaml\n")
    run = Run(tmp_path, "results/v2", "example", 6, config, ["proj_fixture"])
    config.write_text("model_config: model.yaml\nchanged: true\n")
    with pytest.raises(ValueError, match="resume"):
        Run(tmp_path, "results/v2", "example", 6, config, ["proj_fixture"], resume=True)
    run.status("proj_fixture", "ANALYSIS_FAILED", "explicit unavailable database")
    final = run.finalize({"hypotheses": 0})
    assert final.is_dir()
    with pytest.raises(FileExistsError, match="immutable"):
        Run(tmp_path, "results/v2", "example", 6, config, ["proj_fixture"])


def test_selection_rejects_ids_outside_development(tmp_path: Path) -> None:
    split = tmp_path / "data/processed/splits/development.csv"
    split.parent.mkdir(parents=True)
    split.write_text("project_id\nproj_development\n")
    with pytest.raises(ValueError, match="outside development"):
        development_ids(tmp_path, project_id="proj_outside")


def test_source_fingerprint_uses_codeql_utf16_columns() -> None:
    line = '"😀" + input'
    row = {"start_line": "1", "end_line": "1", "start_column": "8", "end_column": "12"}
    assert source_text_fingerprint([line], row) == hashlib.sha256(b"input").hexdigest()
    with pytest.raises(ValueError, match="UTF-16 character"):
        source_text_fingerprint(['"😀"'], {**row, "start_column": "2", "end_column": "2"})


def test_entity_decoder_keeps_internal_identity_when_labels_collide() -> None:
    payload = {
        "columns": [{"name": "resolved_node", "kind": "Entity"}],
        "tuples": [
            [{"id": 11, "label": "getProperty(...)"}],
            [{"id": 12, "label": "getProperty(...)"}],
        ],
    }
    rows = entity_rows(payload)
    assert rows[0]["resolved_node"] == rows[1]["resolved_node"]
    assert rows[0]["resolved_node_entity_id"] != rows[1]["resolved_node_entity_id"]
    with pytest.raises(ValueError, match="internal ID"):
        entity_rows({**payload, "tuples": [[{"label": "getProperty(...)"}]]})


def test_inventory_uniqueness_spans_model_bases_without_rejecting_aliases() -> None:
    source = next(node for node in inventory() if "source" in node["roles"])
    row = {key: str(value) for key, value in source["descriptor"].items()}
    row.update({"role": "source", "basis": "remote-flow-source", "resolved_node_entity_id": "11"})
    alias = {**row, "basis": "modeled-remote-source"}
    assert len(unique_inventory_rows([row, alias])[0]) == 2
    collision = {**alias, "resolved_node_entity_id": "12"}
    eligible, ambiguous = unique_inventory_rows([row, alias, collision])
    assert not eligible and len(ambiguous) == 3


@pytest.mark.parametrize("call_budget", [1, 30])
def test_transport_checkpoint_resume_preserves_budget_and_not_grounding_rejection(
    tmp_path: Path,
    monkeypatch: Any,
    call_budget: int,
) -> None:
    import json

    import yaml

    import src.pipeline_v2.specifications as stage
    from src.llm.providers.openrouter import OpenRouterError
    from src.reproduction.common import atomic_jsonl, read_jsonl

    split = tmp_path / "data/processed/splits/development.csv"
    split.parent.mkdir(parents=True)
    split.write_text("project_id\nproj_fixture\n")
    pack = tmp_path / "src/static_analysis/queries/v2"
    pack.mkdir(parents=True)
    (pack / "Grounding.qll").write_text("// fixture\n")
    (tmp_path / "model.yaml").write_text("fixture: true\n")
    config = {
        "model_config": "model.yaml",
        "codeql": {},
        "budget": {
            "max_context_tokens_per_call": 8192,
            "max_output_tokens_per_call": 2048,
            "max_calls_per_project": call_budget,
            "max_total_input_tokens_per_project": 160000,
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    p6 = tmp_path / "p6"
    project = p6 / "projects/proj_fixture"
    project.mkdir(parents=True)
    (project / "database_provenance.json").write_text("{}")
    p9 = tmp_path / "p9"
    nodes, edges = graph()
    atomic_jsonl(p9 / "useg/nodes.jsonl", nodes)
    atomic_jsonl(p9 / "useg/edges.jsonl", edges)
    atomic_jsonl(p9 / "project_status.jsonl", [{"project_id": "proj_fixture", "status": "SUCCESS"}])
    monkeypatch.setattr(
        stage, "dependency", lambda _r, _p, _s, phase: (p6 if phase == 6 else p9, {})
    )
    monkeypatch.setattr(stage, "codeql", lambda *_args: Path("/fixture/codeql"))
    monkeypatch.setattr(stage, "_inventory_unchanged", lambda *_args: tmp_path / "database")
    monkeypatch.setattr(stage.OpenRouterSettings, "load", lambda *_args: object())
    monkeypatch.setattr(stage, "query_csv", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(stage, "resolution_complete", lambda *_args: True)
    calls = []

    def complete(_self: object, _messages: object, **kwargs: Any) -> str:
        calls.append(1)
        if len(calls) == 1:
            raise OpenRouterError("rate limited", retryable=True, http_status=429)
        schema = kwargs["response_schema"]["properties"]["specification"]["properties"]
        result = {
            "hypothesis_id": schema["hypothesis_id"]["enum"][0],
            "candidate_cwe": "CWE-22",
            "sanitizers": [],
            "propagators": [],
            "preconditions": [],
            "summary": "unverified fixture",
        }
        for role in ["sources", "sinks"]:
            result[role] = [
                {
                    "node_id": schema[role]["items"]["properties"]["node_id"]["enum"][0],
                    "rationale": "typed fixture",
                }
            ]
        return json.dumps({"specification": result})

    monkeypatch.setattr(stage.OpenRouterClient, "complete", complete)
    with pytest.raises(stage.RetryableSynthesisError):
        stage.phase10(
            tmp_path,
            config,
            config_path,
            ["proj_fixture"],
            "checkpoint",
            "p6",
            "p9",
            "B6",
            confirm_api_spend=True,
        )
    work = tmp_path / "results/specifications/v2/b6/.checkpoint.inprogress"
    assert read_jsonl(work / "project_status.jsonl")[0]["status"] == "PENDING"
    checkpoint = work / "projects/proj_fixture"
    assert len(read_jsonl(checkpoint / "api_attempts.jsonl")) == 1
    assert read_jsonl(checkpoint / "plans.jsonl")[-1]["status"] == "RETRYABLE_API_ERROR"
    final = stage.phase10(
        tmp_path,
        config,
        config_path,
        ["proj_fixture"],
        "checkpoint",
        "p6",
        "p9",
        "B6",
        confirm_api_spend=True,
        resume=True,
    )
    summary = json.loads((final / "summary.json").read_text())
    if call_budget == 1:
        assert len(calls) == 1
        assert summary["specifications"] == 0
        assert summary["rejected_hypotheses"] == 0
        assert summary["api_budget_exhaustions"] == 1
    else:
        assert len(calls) == 2
        assert summary["specifications"] == 1
        assert summary["rejected_hypotheses"] == 0
        assert len(read_jsonl(final / "projects/proj_fixture/api_attempts.jsonl")) == 2
        monkeypatch.setattr(
            stage,
            "dependency",
            lambda _r, _p, _s, phase: (p6 if phase == 6 else p9 if phase == 9 else final, {}),
        )
        inherited = stage.phase10(
            tmp_path,
            config,
            config_path,
            ["proj_fixture"],
            "inherited",
            "p6",
            "p9",
            "B6",
            confirm_api_spend=True,
            inherit_relative=str(final.relative_to(tmp_path)),
        )
        inherited_summary = json.loads((inherited / "summary.json").read_text())
        assert len(calls) == 2  # No new API call for the previously resolved specification.
        assert inherited_summary["inherited_specifications"] == 1
        assert len(read_jsonl(inherited / "projects/proj_fixture/api_attempts.jsonl")) == 2
        altered = copy.deepcopy(nodes)
        for node in altered:
            if node["kind"] == "HYPOTHESIS":
                node["properties"]["candidate_cwe"] = ["CWE-78"]
        atomic_jsonl(p9 / "useg/nodes.jsonl", altered)
        rejected = stage.phase10(
            tmp_path,
            config,
            config_path,
            ["proj_fixture"],
            "changed",
            "p6",
            "p9",
            "B6",
            confirm_api_spend=True,
            inherit_relative=str(final.relative_to(tmp_path)),
        )
        rejected_summary = json.loads((rejected / "summary.json").read_text())
        assert rejected_summary["analysis_failures"] == 1
        assert rejected_summary["specifications"] == 0
        assert len(calls) == 2


def test_database_extraction_receives_pinned_java_and_maven_on_path(tmp_path: Path) -> None:
    import os
    import shutil

    from src.pipeline_v2.recovery import database_environment

    java = tmp_path / "jdk/bin/java"
    java.parent.mkdir(parents=True)
    java.write_text("#!/bin/sh\nexit 0\n")
    java.chmod(0o755)
    maven = tmp_path / "tools/maven/bin/mvn"
    maven.parent.mkdir(parents=True)
    maven.write_text("#!/bin/sh\nexit 0\n")
    maven.chmod(0o755)
    policy = {
        "install_root": "tools",
        "jdk": {"8u202": {"env_home": "FIXTURE_JAVA"}},
        "maven": {"3.5.0": {"directory": "maven"}},
    }
    row = {"jdk_version": "8u202", "maven_version": "3.5.0"}
    env, recorded = database_environment(
        tmp_path, row, policy, {"FIXTURE_JAVA": str(java.parent.parent)}
    )
    assert shutil.which("java", path=env["PATH"]) == str(java)
    assert shutil.which("mvn", path=env["PATH"]) == str(maven)
    assert env["JAVA_HOME"] == str(java.parent.parent)
    assert recorded["jdk_version"] == "8u202"
    assert env["PATH"].split(os.pathsep)[0] == str(java.parent)
    with pytest.raises(ValueError, match="pinned JDK unavailable"):
        database_environment(tmp_path, row, policy, {})


def test_cancelled_query_terminates_its_process_group(monkeypatch: Any) -> None:
    import src.graphs.program.runner as runner

    class Interrupted:
        def communicate(self, **_kwargs: object) -> tuple[str, str]:
            raise KeyboardInterrupt

    child = Interrupted()
    stopped = []
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: child)
    monkeypatch.setattr(runner, "_terminate_process_group", lambda process: stopped.append(process))
    with pytest.raises(KeyboardInterrupt):
        runner._run_command(["fixture"], timeout=1)
    assert stopped == [child]


def test_readiness_cancellation_stops_running_command() -> None:
    import sys
    import threading

    from src.graphs.program.runner import _run_command

    cancelled = threading.Event()
    timer = threading.Timer(0.1, cancelled.set)
    timer.start()
    try:
        with pytest.raises(RuntimeError, match="command cancelled"):
            _run_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=60,
                cancelled=cancelled,
            )
    finally:
        timer.join()
