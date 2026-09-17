"""Validate Phase 10 retrieval, budget, grounding, and compilation artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import sha256_file
from src.reproduction.common import read_jsonl
from src.retrieval.graph import estimate_tokens, retrieve_context, serialize_context
from src.specification.schema import endpoint_role_allowed, specification_json_schema

REQUIRED_FILES = {
    "STATUS",
    "checksums.sha256",
    "command.txt",
    "compile_attempts.jsonl",
    "config.resolved.yaml",
    "contexts.jsonl",
    "dependency_status.json",
    "environment.json",
    "llm_calls.jsonl",
    "manifest.json",
    "phase10_summary.json",
    "project_status.jsonl",
    "project_summary.jsonl",
    "repair_log.jsonl",
    "resource_usage.jsonl",
    "specifications.jsonl",
    "stderr.log",
    "stdout.log",
}


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _verify_checksums(run_root: Path) -> None:
    indexed: set[str] = set()
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 10 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if indexed != actual:
        raise ValueError("Phase 10 checksum index coverage mismatch")


def _usage(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    successes = [row for row in records if row.get("status") == "SUCCESS"]
    prompt_tokens = 0
    for row in successes:
        usage = row.get("usage")
        if isinstance(usage, Mapping):
            prompt_tokens += int(usage.get("prompt_tokens", 0) or 0)
    return {"calls": len(successes), "input_tokens": prompt_tokens}


def _validate_dry_run(
    run_root: Path,
    manifest: Mapping[str, Any],
    *,
    repo_root: Path,
    experiment: Mapping[str, Any],
    baseline: Mapping[str, Any],
    selected: Sequence[str],
) -> str:
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != "DRY_RUN":
        raise ValueError("Phase 10 dry-run STATUS mismatch")
    if not (run_root / "dry_run_plan.jsonl").is_file():
        raise ValueError("Phase 10 dry-run plan is missing")
    if read_jsonl(run_root / "llm_calls.jsonl"):
        raise ValueError("Phase 10 dry-run unexpectedly contains LLM calls")
    plans = read_jsonl(run_root / "dry_run_plan.jsonl")
    from src.llm.prompts.phase10 import SYSTEM_PROMPT, user_prompt
    from src.specification.runner import (
        _context_for_hypothesis,
        _endpoint_ids_by_role,
        _estimated_request_tokens,
        _hypotheses,
    )

    phase9_config = cast(
        Mapping[str, Any], cast(Mapping[str, Any], experiment["development_dependency"])["phase9"]
    )
    phase9_root = repo_root / str(phase9_config["run_root"])
    nodes = read_jsonl(phase9_root / "useg/nodes.jsonl")
    edges = read_jsonl(phase9_root / "useg/edges.jsonl")
    phase9_statuses = read_jsonl(phase9_root / "project_status.jsonl")
    phase9_by_id = {str(row["project_id"]): row for row in phase9_statuses}
    retrieval = cast(Mapping[str, Any], experiment["retrieval"])
    budget = cast(Mapping[str, Any], experiment["budget"])[str(manifest["budget_mode"])]
    context_budget = (
        int(budget["max_context_tokens_per_call"])
        - estimate_tokens(SYSTEM_PROMPT + user_prompt(""))
        - int(retrieval["prompt_reserve_tokens"])
    )
    strategy = str(baseline["retrieval"])
    spec_config = cast(Mapping[str, Any], experiment["specification"])
    expected_plans: list[dict[str, Any]] = []
    for project_id in selected:
        if phase9_by_id[project_id].get("status") != "SUCCESS":
            expected_plans.append(
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "status": "ANALYSIS_FAILED",
                    "reason": "inherited Phase 9 failure",
                }
            )
            continue
        for hypothesis in _hypotheses(nodes, project_id)[
            : int(retrieval["hypothesis_limit_per_project"])
        ]:
            properties = cast(Mapping[str, Any], hypothesis["properties"])
            hypothesis_id = str(properties["upstream_hypothesis_id"])
            context_text, metadata, by_id = _context_for_hypothesis(
                nodes=nodes,
                edges=edges,
                hypothesis_node=hypothesis,
                strategy=strategy,
                retrieval=retrieval,
                context_budget=context_budget,
                request_budget=int(budget["max_context_tokens_per_call"]),
                max_role_items=int(spec_config["max_role_items"]),
                max_preconditions=int(spec_config["max_preconditions"]),
            )
            endpoint_ids = _endpoint_ids_by_role(
                by_id,
                {
                    str(value)
                    for value in cast(Sequence[Any], metadata["serialized_node_ids"])
                },
            )
            estimated_request_tokens: int | None = None
            within_call_budget = True
            if endpoint_ids["sources"] and endpoint_ids["sinks"]:
                evidence_ids = sorted(
                    node_id
                    for node_id in cast(Sequence[str], metadata["serialized_node_ids"])
                    if by_id[node_id].get("layer") == "evidence"
                )
                response_schema = specification_json_schema(
                    hypothesis_id=hypothesis_id,
                    candidate_cwes=[
                        str(value)
                        for value in cast(Sequence[Any], properties["candidate_cwe"])
                    ],
                    allowed_endpoint_ids_by_role=endpoint_ids,
                    allowed_evidence_ids=evidence_ids,
                    max_role_items=int(spec_config["max_role_items"]),
                    max_preconditions=int(spec_config["max_preconditions"]),
                )
                estimated_request_tokens = _estimated_request_tokens(
                    context_text,
                    response_schema,
                    repair_error="x" * 500,
                )
                within_call_budget = estimated_request_tokens <= int(
                    budget["max_context_tokens_per_call"]
                )
            expected_plans.append(
                {
                    **metadata,
                    "endpoint_candidates": {
                        role: len(endpoint_ids[role]) for role in endpoint_ids
                    },
                    "ready_for_api": bool(
                        endpoint_ids["sources"]
                        and endpoint_ids["sinks"]
                        and within_call_budget
                    ),
                    "estimated_request_tokens": estimated_request_tokens,
                    "within_call_token_budget": within_call_budget,
                }
            )
    if plans != expected_plans:
        raise ValueError("Phase 10 dry-run plan does not reproduce from canonical USEG")
    context_plans = [row for row in plans if "context_id" in row]
    for row in context_plans:
        candidates = row.get("endpoint_candidates")
        if not isinstance(candidates, Mapping):
            raise ValueError("Phase 10 dry-run lacks endpoint preflight counts")
        ready = (
            int(candidates.get("sources", 0)) > 0
            and int(candidates.get("sinks", 0)) > 0
            and row.get("within_call_token_budget") is True
        )
        if row.get("ready_for_api") is not ready:
            raise ValueError("Phase 10 dry-run endpoint readiness mismatch")
        estimated_request_tokens = row.get("estimated_request_tokens")
        if (
            isinstance(estimated_request_tokens, int)
            and estimated_request_tokens > int(budget["max_context_tokens_per_call"])
            and row.get("within_call_token_budget") is not False
        ):
            raise ValueError("Phase 10 dry-run request-token preflight mismatch")
    summary = _json(run_root / "phase10_summary.json")
    if summary.get("dry_run") is not True or summary.get("llm_calls") != 0:
        raise ValueError("Phase 10 dry-run summary is invalid")
    eligible = sum(row.get("ready_for_api") is True for row in context_plans)
    expected = {
        "planned_contexts": len(context_plans),
        "planned_api_eligible_contexts": eligible,
        "planned_fail_closed_contexts": len(context_plans) - eligible,
    }
    if any(summary.get(key) != value for key, value in expected.items()):
        raise ValueError("Phase 10 dry-run preflight summary mismatch")
    _verify_checksums(run_root)
    return (
        f"PASS_DRY_RUN: Phase 10 {manifest['baseline_id']} "
        f"({summary['planned_contexts']} planned contexts; zero API calls)"
    )


def validate(run_root: Path, *, repo_root: Path) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 10 outputs: {', '.join(missing)}")
    manifest = _json(run_root / "manifest.json")
    if (
        manifest.get("phase") != 10
        or manifest.get("protocol_version") != "1.7.0"
        or manifest.get("baseline_id") not in {"B6", "B7", "B8", "B9"}
    ):
        raise ValueError("not a Phase 10 B6-B9 run")
    baseline_record = cast(Mapping[str, Any], manifest["baseline_config"])
    experiment_record = cast(Mapping[str, Any], manifest["experiment_config"])
    baseline_path = repo_root / str(baseline_record["path"])
    experiment_path = repo_root / str(experiment_record["path"])
    if sha256_file(baseline_path) != baseline_record["sha256"]:
        raise ValueError("Phase 10 baseline config checksum mismatch")
    if sha256_file(experiment_path) != experiment_record["sha256"]:
        raise ValueError("Phase 10 experiment config checksum mismatch")
    baseline = _mapping(baseline_path)
    experiment = _mapping(experiment_path)
    from src.specification.runner import dependency_status

    dependency = dependency_status(repo_root, experiment)
    if _json(run_root / "dependency_status.json") != dependency:
        raise ValueError("Phase 10 dependency status mismatch")
    if manifest.get("development_dependency") != dependency:
        raise ValueError("Phase 10 manifest dependency mismatch")
    if manifest.get("retrieval_strategy") != baseline.get("retrieval"):
        raise ValueError("Phase 10 manifest retrieval strategy mismatch")
    selected = [str(value) for value in cast(Sequence[Any], manifest["selected_project_ids"])]
    if len(selected) != manifest.get("selected_project_count") or len(selected) != len(
        set(selected)
    ):
        raise ValueError("Phase 10 selected project manifest is invalid")
    implementation = cast(Mapping[str, Any], manifest["implementation_sha256"])
    for relative, digest in implementation.items():
        if sha256_file(repo_root / str(relative)) != digest:
            raise ValueError(f"Phase 10 implementation checksum mismatch: {relative}")
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() == "DRY_RUN":
        return _validate_dry_run(
            run_root,
            manifest,
            repo_root=repo_root,
            experiment=experiment,
            baseline=baseline,
            selected=selected,
        )

    statuses = read_jsonl(run_root / "project_status.jsonl")
    if [str(row.get("project_id")) for row in statuses] != selected:
        raise ValueError("Phase 10 project status coverage/order mismatch")
    if any(row.get("status") not in {"SUCCESS", "ANALYSIS_FAILED"} for row in statuses):
        raise ValueError("Phase 10 project status is not final")
    failures = [row for row in statuses if row.get("status") != "SUCCESS"]
    expected_status = "FAILED" if failures else "SUCCESS"
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != expected_status:
        raise ValueError("Phase 10 run STATUS does not match project outcomes")
    if manifest.get("mode") == "full":
        if cast(Mapping[str, Any], manifest.get("git", {})).get("dirty") is not False:
            raise ValueError("Phase 10 full run was not created from a clean Git worktree")
        coverage = cast(Mapping[str, Any], experiment["coverage"])
        if len(selected) != int(coverage["expected_full_projects"]):
            raise ValueError("Phase 10 full run does not cover all development projects")
        upstream_failures = sum(row.get("upstream_phase9_status") != "SUCCESS" for row in statuses)
        if upstream_failures != int(coverage["expected_phase9_failures"]):
            raise ValueError("Phase 10 did not preserve Phase 9 failures")

    phase9_config = cast(
        Mapping[str, Any], cast(Mapping[str, Any], experiment["development_dependency"])["phase9"]
    )
    phase9_root = repo_root / str(phase9_config["run_root"])
    nodes = read_jsonl(phase9_root / "useg/nodes.jsonl")
    edges = read_jsonl(phase9_root / "useg/edges.jsonl")
    node_by_id = {str(node["node_id"]): node for node in nodes}
    hypotheses = {
        str(cast(Mapping[str, Any], node["properties"])["upstream_hypothesis_id"]): node
        for node in nodes
        if node.get("kind") == "HYPOTHESIS"
    }
    contexts = read_jsonl(run_root / "contexts.jsonl")
    context_by_id: dict[str, dict[str, Any]] = {}
    retrieval = cast(Mapping[str, Any], experiment["retrieval"])
    strategy = str(baseline["retrieval"])
    from src.llm.prompts.phase10 import SYSTEM_PROMPT, user_prompt

    initial_context_budget = (
        int(cast(Mapping[str, Any], experiment["budget"])[str(manifest["budget_mode"])][
            "max_context_tokens_per_call"
        ])
        - estimate_tokens(SYSTEM_PROMPT + user_prompt(""))
        - int(retrieval["prompt_reserve_tokens"])
    )
    for record in contexts:
        context_id = str(record.get("context_id"))
        hypothesis_id = str(record.get("hypothesis_id"))
        if context_id in context_by_id or hypothesis_id not in hypotheses:
            raise ValueError("Phase 10 context identity is invalid or duplicated")
        if record.get("strategy") != strategy:
            raise ValueError("Phase 10 context strategy mismatch")
        if int(record.get("estimated_tokens", -1)) > int(record.get("token_budget", -1)):
            raise ValueError("Phase 10 compact context exceeds token budget")
        context_text = record.get("context_text")
        if not isinstance(context_text, str) or estimate_tokens(context_text) != record.get(
            "estimated_tokens"
        ):
            raise ValueError("Phase 10 serialized context token accounting mismatch")
        max_nodes = (
            int(retrieval["max_nodes_pruned"])
            if strategy == "unified_graph_pruned"
            else int(retrieval["max_nodes_layer_only"])
        )
        rebuilt = retrieve_context(
            nodes,
            edges,
            hypothesis_id=hypothesis_id,
            strategy=strategy,
            max_hops=int(retrieval["max_hops"]),
            max_nodes=max_nodes,
        )
        rebuilt_text, rebuilt_metadata = serialize_context(
            rebuilt, token_budget=int(record["token_budget"])
        )
        expected_record = {
            **rebuilt_metadata,
            "initial_token_budget": initial_context_budget,
            "request_budget_adapted": int(record["token_budget"])
            < initial_context_budget,
            "context_text": rebuilt_text,
        }
        if record != expected_record:
            raise ValueError("Phase 10 context does not reproduce from canonical USEG")
        context_by_id[context_id] = record

    specifications = read_jsonl(run_root / "specifications.jsonl")
    compile_attempts = read_jsonl(run_root / "compile_attempts.jsonl")
    for attempt in compile_attempts:
        query = attempt.get("query")
        digest = attempt.get("query_sha256")
        if not isinstance(query, str) or not isinstance(digest, str):
            raise ValueError("Phase 10 compile attempt lacks query provenance")
        query_path = run_root / query
        if not query_path.is_file() or sha256_file(query_path) != digest:
            raise ValueError("Phase 10 compile-attempt query checksum mismatch")
    compiled_by_spec = {
        str(row["specification_id"]): row
        for row in compile_attempts
        if row.get("status") == "COMPILED"
    }
    seen_specs: set[str] = set()
    seen_spec_keys: set[tuple[str, str]] = set()
    for spec in specifications:
        spec_id = str(spec.get("specification_id"))
        if spec_id in seen_specs or spec.get("status") != "SYNTHESIZED_UNVERIFIED":
            raise ValueError("Phase 10 specification ID/status is invalid")
        seen_specs.add(spec_id)
        context = context_by_id.get(str(spec.get("context_id")))
        if context is None:
            raise ValueError("Phase 10 specification references an unknown context")
        spec_key = (str(spec.get("project_id")), str(spec.get("hypothesis_id")))
        if spec_key in seen_spec_keys:
            raise ValueError("Phase 10 has duplicate specifications for one hypothesis")
        seen_spec_keys.add(spec_key)
        if (
            spec.get("project_id") != context.get("project_id")
            or spec.get("hypothesis_id") != context.get("hypothesis_id")
            or spec.get("baseline_id") != manifest["baseline_id"]
        ):
            raise ValueError("Phase 10 specification identity does not match its context")
        hypothesis = hypotheses[str(spec["hypothesis_id"])]
        hypothesis_properties = cast(Mapping[str, Any], hypothesis["properties"])
        if spec.get("candidate_cwe") not in cast(
            Sequence[Any], hypothesis_properties["candidate_cwe"]
        ):
            raise ValueError("Phase 10 specification CWE is outside its hypothesis")
        allowed = set(cast(Sequence[str], context["serialized_node_ids"]))
        for role in ("sources", "sinks", "sanitizers", "propagators"):
            entries = spec.get(role)
            if not isinstance(entries, list):
                raise ValueError("Phase 10 specification role is not a list")
            if role in {"sources", "sinks"} and not entries:
                raise ValueError("Phase 10 specification lacks a grounded source/sink")
            for entry in entries:
                if not isinstance(entry, Mapping) or entry.get("node_id") not in allowed:
                    raise ValueError("Phase 10 specification endpoint is outside context")
                if str(entry["node_id"]) not in node_by_id:
                    raise ValueError("Phase 10 specification endpoint is absent from USEG")
                if not endpoint_role_allowed(role, node_by_id[str(entry["node_id"])]):
                    raise ValueError("Phase 10 specification endpoint semantic role mismatch")
        for precondition in cast(Sequence[Mapping[str, Any]], spec.get("preconditions", [])):
            if any(value not in allowed for value in precondition.get("evidence_node_ids", [])):
                raise ValueError("Phase 10 precondition evidence is outside context")
        compile_record = compiled_by_spec.get(spec_id)
        if compile_record is None or compile_record.get("query") != spec.get("query"):
            raise ValueError("Phase 10 final specification lacks a compiled query")
        query_path = run_root / str(spec["query"])
        if not query_path.is_file() or sha256_file(query_path) != spec.get("query_sha256"):
            raise ValueError("Phase 10 generated query checksum mismatch")
        if compile_record.get("query_sha256") != spec.get("query_sha256"):
            raise ValueError("Phase 10 compile/spec query provenance mismatch")

    calls = read_jsonl(run_root / "llm_calls.jsonl")
    known_context_ids = set(context_by_id)
    selected_ids = set(selected)
    for record in calls:
        if record.get("baseline_id") != manifest["baseline_id"]:
            raise ValueError("Phase 10 LLM call baseline identity mismatch")
        if str(record.get("project_id")) not in selected_ids:
            raise ValueError("Phase 10 LLM call project identity mismatch")
        if str(record.get("context_id")) not in known_context_ids:
            raise ValueError("Phase 10 LLM call references an unknown context")
    budget = cast(Mapping[str, Any], experiment["budget"])[str(manifest["budget_mode"])]
    for project_id in selected:
        records = [row for row in calls if row.get("project_id") == project_id]
        usage = _usage(records)
        if usage["calls"] > int(budget["max_calls_per_project"]):
            raise ValueError("Phase 10 per-project call budget exceeded")
        if usage["input_tokens"] > int(budget["max_total_input_tokens_per_project"]):
            raise ValueError("Phase 10 per-project input-token budget exceeded")
        for record in records:
            usage_record = record.get("usage")
            if (
                record.get("status") == "SUCCESS"
                and isinstance(usage_record, Mapping)
                and int(usage_record.get("prompt_tokens", 0) or 0)
                > int(budget["max_context_tokens_per_call"])
            ):
                raise ValueError("Phase 10 per-call input-token budget exceeded")

    validation = cast(Mapping[str, Any], experiment["validation"])
    forbidden = [str(value).casefold() for value in validation["forbidden_output_substrings"]]
    serialized = "\n".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True)
        for record in [*contexts, *specifications]
    ).casefold()
    leaked = [value for value in forbidden if value in serialized]
    if leaked:
        raise ValueError(f"Phase 10 output contains forbidden evaluator material: {leaked}")
    if any(
        word in json.dumps(spec, sort_keys=True).casefold()
        for spec in specifications
        for word in ("verified_vulnerability", "verification_result", "final_finding")
    ):
        raise ValueError("Phase 10 specification makes a forbidden verified/final claim")

    summary = _json(run_root / "phase10_summary.json")
    project_summaries = read_jsonl(run_root / "project_summary.jsonl")
    resources = read_jsonl(run_root / "resource_usage.jsonl")
    for records, label in (
        (project_summaries, "project summary"),
        (resources, "resource usage"),
    ):
        if [str(row.get("project_id")) for row in records] != selected:
            raise ValueError(f"Phase 10 {label} coverage/order mismatch")
    status_by_id = {str(row["project_id"]): row for row in statuses}
    specs_by_project = Counter(str(spec["project_id"]) for spec in specifications)
    for record in project_summaries:
        project_id = str(record["project_id"])
        if record.get("status") != status_by_id[project_id].get("status"):
            raise ValueError("Phase 10 project summary status mismatch")
        if int(record.get("specifications", -1)) != specs_by_project[project_id]:
            raise ValueError("Phase 10 project summary specification count mismatch")
    successes = sum(row.get("status") == "SUCCESS" for row in statuses)
    expected_counts = {
        "projects": len(selected),
        "analysis_successes": successes,
        "analysis_failures": len(selected) - successes,
        "contexts": len(contexts),
        "specifications": len(specifications),
        "compile_attempts": len(compile_attempts),
        "compiled_attempts": sum(row.get("status") == "COMPILED" for row in compile_attempts),
        "final_compiled_specifications": len(specifications),
        "final_findings": 0,
    }
    if any(summary.get(key) != value for key, value in expected_counts.items()):
        raise ValueError("Phase 10 summary count mismatch")
    if summary.get("verification_status") != "DEFERRED_TO_PHASE_11":
        raise ValueError("Phase 10 summary verification boundary mismatch")
    if specifications and summary.get("compile_rate") != 1.0:
        raise ValueError("Phase 10 final specification compile rate mismatch")
    if Counter(str(spec["baseline_id"]) for spec in specifications) not in (
        Counter(),
        Counter({str(manifest["baseline_id"]): len(specifications)}),
    ):
        raise ValueError("Phase 10 specification baseline identity mismatch")

    _verify_checksums(run_root)
    return (
        f"PASS_WITH_ANALYSIS_FAILURES: Phase 10 {manifest['baseline_id']} "
        f"({successes}/{len(selected)} successful; {len(specifications)} grounded specs; "
        "100% final query compile rate)"
        if failures
        else (
            f"PASS: Phase 10 {manifest['baseline_id']} ({successes} projects; "
            f"{len(specifications)} grounded specs; 100% final query compile rate)"
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(validate(args.run_root.resolve(), repo_root=args.repo_root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
