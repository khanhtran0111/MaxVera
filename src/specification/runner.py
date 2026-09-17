"""Run Phase 10 graph retrieval and unverified specification synthesis."""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shlex
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import (
    assert_secret_free,
    collect_environment,
    collect_git,
    redact_secrets,
    sha256_file,
    utc_now,
)
from src.llm.prompts.phase10 import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    prompt_sha256,
    repair_prompt,
    user_prompt,
)
from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums
from src.retrieval.graph import estimate_tokens, retrieve_context, serialize_context
from src.specification.compiler import compile_query, render_query
from src.specification.schema import (
    ROLES,
    endpoint_role_allowed,
    parse_specification,
    specification_json_schema,
)

IMPLEMENTED = {"B6", "B7", "B8", "B9"}
REQUEST_ENVELOPE_TOKEN_RESERVE = 256
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FORBIDDEN_CONFIG_WORDS = {
    "advisory_text",
    "cve_id",
    "fix_commit",
    "fixed_line",
    "ground_truth_cwe",
    "patch_commit",
    "vulnerable_description",
}


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(value), ensure_ascii=False, sort_keys=True) + "\n")


def _safe_config(config: Mapping[str, Any]) -> None:
    filtered = dict(config)
    validation = filtered.get("validation")
    if isinstance(validation, Mapping):
        filtered["validation"] = {
            key: value
            for key, value in validation.items()
            if key != "forbidden_output_substrings"
        }
    serialized = json.dumps(filtered, sort_keys=True).casefold()
    leaked = sorted(value for value in FORBIDDEN_CONFIG_WORDS if value in serialized)
    if leaked:
        raise ValueError(f"Phase 10 analysis config crosses label firewall: {', '.join(leaked)}")


def _validate_config(
    baseline_id: str, baseline: Mapping[str, Any], experiment: Mapping[str, Any]
) -> None:
    expected_status = (
        "implemented_phase_10_synthesis_only" if baseline_id == "B9" else "implemented_phase_10"
    )
    if baseline_id not in IMPLEMENTED or baseline.get("baseline_id") != baseline_id:
        raise ValueError("Phase 10 supports only matching B6-B9 configs")
    if baseline.get("status") != expected_status:
        raise ValueError(f"{baseline_id} is not marked {expected_status}")
    if experiment.get("status") != "frozen_phase_10_development":
        raise ValueError("Phase 10 experiment config is not frozen for development")
    if experiment.get("protocol_version") != "1.7.0":
        raise ValueError("Phase 10 requires protocol 1.7.0")
    strategies = cast(
        Mapping[str, Any],
        cast(Mapping[str, Any], experiment["retrieval"])["strategies"],
    )
    if baseline.get("retrieval") != strategies.get(baseline_id):
        raise ValueError("baseline retrieval strategy does not match Phase 10 experiment")
    if baseline.get("provider_route") != cast(Mapping[str, Any], experiment["llm"])[
        "provider_route"
    ]:
        raise ValueError("baseline and Phase 10 provider routes differ")
    _safe_config(baseline)
    _safe_config(experiment)


def dependency_status(root: Path, experiment: Mapping[str, Any]) -> dict[str, Any]:
    expected = cast(
        Mapping[str, Any], cast(Mapping[str, Any], experiment["development_dependency"])["phase9"]
    )
    run_root = root / str(expected["run_root"])
    files = {
        "manifest_sha256": "manifest.json",
        "useg_summary_sha256": "useg_summary.json",
        "trace_audit_sha256": "trace_audit.json",
        "project_status_sha256": "project_status.jsonl",
        "nodes_sha256": "useg/nodes.jsonl",
        "edges_sha256": "useg/edges.jsonl",
        "checksums_index_sha256": "checksums.sha256",
    }
    actual = {name: sha256_file(run_root / relative) for name, relative in files.items()}
    wanted = {name: str(expected[name]) for name in files}
    if actual != wanted:
        raise ValueError("locked Phase 9 dependency checksum mismatch")
    manifest = _json(run_root / "manifest.json")
    if manifest.get("phase") != 9 or manifest.get("run_id") != expected["run_id"]:
        raise ValueError("locked Phase 9 dependency identity mismatch")
    if cast(Mapping[str, Any], manifest.get("git", {})).get("dirty") is not False:
        raise ValueError("Phase 10 requires the clean canonical Phase 9 run")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    successes = sum(row.get("status") == "SUCCESS" for row in statuses)
    failures = len(statuses) - successes
    coverage = cast(Mapping[str, Any], experiment["coverage"])
    if (
        len(statuses) != int(coverage["expected_full_projects"])
        or successes != int(coverage["expected_phase9_successes"])
        or failures != int(coverage["expected_phase9_failures"])
    ):
        raise ValueError("locked Phase 9 project coverage mismatch")
    return {
        "schema_version": 1,
        "phase9": {"run_id": str(expected["run_id"]), **actual},
        "analysis_successes": successes,
        "analysis_failures": failures,
        "data_access": "canonical Phase 9 development USEG only; evaluator/test data forbidden",
    }


def _selected_projects(
    phase9_statuses: Sequence[Mapping[str, Any]], args: argparse.Namespace
) -> list[str]:
    all_ids = [str(row["project_id"]) for row in phase9_statuses]
    if args.mode == "full":
        if args.limit is not None or args.project_id is not None:
            raise ValueError("--limit/--project-id are forbidden in full mode")
        return all_ids
    if args.project_id:
        if args.project_id not in all_ids:
            raise ValueError("--project-id is not in the locked Phase 9 development set")
        return [str(args.project_id)]
    success_ids = [
        str(row["project_id"]) for row in phase9_statuses if row.get("status") == "SUCCESS"
    ]
    limit = args.limit if args.limit is not None else 1
    if limit < 1:
        raise ValueError("--limit must be positive")
    return success_ids[:limit]


def _initial_statuses(
    selected: Sequence[str], phase9_by_id: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []
    for project_id in selected:
        upstream = phase9_by_id[project_id]
        success = upstream.get("status") == "SUCCESS"
        statuses.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": "PENDING" if success else "ANALYSIS_FAILED",
                "reason": "selected and waiting for Phase 10"
                if success
                else f"inherited Phase 9 failure: {upstream.get('reason', 'unknown')}",
                "upstream_phase9_status": upstream.get("status"),
                "updated_at": utc_now(),
            }
        )
    return statuses


def _usage(records: Sequence[Mapping[str, Any]]) -> dict[str, int | float]:
    successes = [record for record in records if record.get("status") == "SUCCESS"]
    result: dict[str, int | float] = {
        "calls": len(successes),
        "retries": sum(record.get("status") == "RETRY" for record in records),
        "input_tokens": 0,
        "billed_output_tokens": 0,
        "reasoning_tokens": 0,
        "output_tokens": 0,
        "api_cost_usd": 0.0,
    }
    for record in successes:
        usage = record.get("usage")
        if not isinstance(usage, Mapping):
            continue
        prompt = int(usage.get("prompt_tokens", 0) or 0)
        completion = int(usage.get("completion_tokens", 0) or 0)
        details = usage.get("completion_tokens_details")
        reasoning = (
            int(details.get("reasoning_tokens", 0) or 0)
            if isinstance(details, Mapping)
            else 0
        )
        result["input_tokens"] += prompt
        result["billed_output_tokens"] += completion
        result["reasoning_tokens"] += reasoning
        result["output_tokens"] += max(0, completion - reasoning)
        result["api_cost_usd"] += float(usage.get("cost", 0.0) or 0.0)
    return result


def _project_usage(run_root: Path, baseline_id: str, project_id: str) -> dict[str, int | float]:
    return _usage(
        [
            record
            for record in read_jsonl(run_root / "llm_calls.jsonl")
            if record.get("baseline_id") == baseline_id
            and record.get("project_id") == project_id
        ]
    )


def _codeql(root: Path) -> Path:
    configured = effective_env(root / ".env").get("MAXVERA_CODEQL_HOME", "")
    if not configured:
        raise ValueError("MAXVERA_CODEQL_HOME is not configured")
    candidate = Path(configured).expanduser()
    executable = candidate if candidate.is_file() else candidate / "codeql"
    if not executable.is_file():
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return executable


def _prepare_output(root: Path, args: argparse.Namespace, baseline_name: str) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    final = output_root / baseline_name / args.run_id
    work = output_root / baseline_name / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 10 run already exists: {final}")
    if work.exists() and not args.resume:
        raise FileExistsError(f"unfinished Phase 10 run exists; use --resume: {work}")
    work.mkdir(parents=True, exist_ok=True)
    return work, final


def _manifest(
    *,
    root: Path,
    args: argparse.Namespace,
    baseline_path: Path,
    baseline: Mapping[str, Any],
    experiment_path: Path,
    experiment: Mapping[str, Any],
    dependency: Mapping[str, Any],
    selected: Sequence[str],
) -> dict[str, Any]:
    model_path = root / str(cast(Mapping[str, Any], experiment["llm"])["model_config"])
    model = _mapping(model_path)
    implementation = (
        "src/retrieval/graph.py",
        "src/specification/schema.py",
        "src/specification/compiler.py",
        "src/specification/runner.py",
        "src/specification/validate.py",
        "src/llm/prompts/phase10.py",
        "src/llm/providers/openrouter.py",
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "phase": 10,
        "protocol_version": "1.7.0",
        "experiment_id": "phase10_graph_retrieval_specification",
        "baseline_id": args.baseline_id,
        "baseline_name": baseline["name"],
        "retrieval_strategy": baseline["retrieval"],
        "run_id": args.run_id,
        "mode": args.mode,
        "budget_mode": args.budget_mode,
        "created_at": utc_now(),
        "git": collect_git(root),
        "selected_project_ids": list(selected),
        "selected_project_count": len(selected),
        "development_dependency": dict(dependency),
        "data_access": "canonical Phase 9 development USEG only; no evaluator/test labels",
        "baseline_config": {
            "path": baseline_path.relative_to(root).as_posix(),
            "sha256": sha256_file(baseline_path),
        },
        "experiment_config": {
            "path": experiment_path.relative_to(root).as_posix(),
            "sha256": sha256_file(experiment_path),
        },
        "prompt": {"version": PROMPT_VERSION, "sha256": prompt_sha256()},
        "model": {
            "requested_model": model["model_id"],
            "returned_models": [],
            "provider_route": model["provider_route"],
            "provider_metadata_snapshot_date": model["provider_metadata_snapshot_date"],
            "routing": model["routing"],
            "reasoning_effort": model["reasoning_effort"],
            "hosted_model_weight_sha256": None,
        },
        "budget": dict(cast(Mapping[str, Any], experiment["budget"])[args.budget_mode]),
        "implementation_sha256": {
            relative: sha256_file(root / relative) for relative in implementation
        },
    }
    safe = cast(dict[str, Any], redact_secrets(manifest))
    assert_secret_free(safe, effective_env(root / ".env"))
    return safe


def _hypotheses(nodes: Sequence[Mapping[str, Any]], project_id: str) -> list[dict[str, Any]]:
    result = [
        dict(node)
        for node in nodes
        if node.get("project_id") == project_id and node.get("kind") == "HYPOTHESIS"
    ]
    return sorted(
        result,
        key=lambda node: (
            int(cast(Mapping[str, Any], node["properties"]).get("rank", 999)),
            str(node["node_id"]),
        ),
    )


def _context_for_hypothesis(
    *,
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    hypothesis_node: Mapping[str, Any],
    strategy: str,
    retrieval: Mapping[str, Any],
    context_budget: int,
    request_budget: int,
    max_role_items: int,
    max_preconditions: int,
) -> tuple[str, dict[str, Any], dict[str, Mapping[str, Any]]]:
    properties = cast(Mapping[str, Any], hypothesis_node["properties"])
    hypothesis_id = str(properties["upstream_hypothesis_id"])
    max_nodes = (
        int(retrieval["max_nodes_pruned"])
        if strategy == "unified_graph_pruned"
        else int(retrieval["max_nodes_layer_only"])
    )
    context = retrieve_context(
        nodes,
        edges,
        hypothesis_id=hypothesis_id,
        strategy=strategy,
        max_hops=int(retrieval["max_hops"]),
        max_nodes=max_nodes,
    )
    by_id: dict[str, Mapping[str, Any]] = {
        str(node["node_id"]): node for node in context.nodes
    }
    current_budget = context_budget
    for _iteration in range(8):
        serialized, metadata = serialize_context(context, token_budget=current_budget)
        allowed_ids = {
            str(value)
            for value in cast(Sequence[Any], metadata["serialized_node_ids"])
        }
        endpoint_ids = _endpoint_ids_by_role(by_id, allowed_ids)
        if not endpoint_ids["sources"] or not endpoint_ids["sinks"]:
            break
        evidence_ids = sorted(
            node_id
            for node_id in allowed_ids
            if by_id[node_id].get("layer") == "evidence"
        )
        response_schema = specification_json_schema(
            hypothesis_id=hypothesis_id,
            candidate_cwes=[
                str(value) for value in cast(Sequence[Any], properties["candidate_cwe"])
            ],
            allowed_endpoint_ids_by_role=endpoint_ids,
            allowed_evidence_ids=evidence_ids,
            max_role_items=max_role_items,
            max_preconditions=max_preconditions,
        )
        estimated_request_tokens = _estimated_request_tokens(
            serialized,
            response_schema,
            repair_error="x" * 500,
        )
        if estimated_request_tokens <= request_budget:
            break
        reduction = max(128, estimated_request_tokens - request_budget + 128)
        reduced_budget = max(1, current_budget - reduction)
        if reduced_budget == current_budget:
            break
        current_budget = reduced_budget
    metadata = {
        **metadata,
        "initial_token_budget": context_budget,
        "request_budget_adapted": current_budget < context_budget,
    }
    return serialized, metadata, by_id


def _endpoint_ids_by_role(
    context_nodes: Mapping[str, Mapping[str, Any]], allowed_ids: set[str]
) -> dict[str, list[str]]:
    endpoint_ids = sorted(
        node_id
        for node_id in allowed_ids
        if node_id in context_nodes
        and (
            context_nodes[node_id].get("layer") in {"program", "security"}
            or (
                context_nodes[node_id].get("layer") == "evidence"
                and context_nodes[node_id].get("kind") == "ASSERTION"
                and isinstance(context_nodes[node_id].get("properties"), Mapping)
                and cast(Mapping[str, Any], context_nodes[node_id]["properties"]).get(
                    "assertion_type"
                )
                == "source_location"
            )
        )
    )
    return {
        role: [
            node_id
            for node_id in endpoint_ids
            if endpoint_role_allowed(role, context_nodes[node_id])
        ]
        for role in ROLES
    }


def _estimated_request_tokens(
    context_text: str,
    response_schema: Mapping[str, Any],
    *,
    repair_error: str | None = None,
) -> int:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt(context_text)},
    ]
    if repair_error is not None:
        messages.append({"role": "user", "content": repair_prompt(repair_error)})
    request_material = json.dumps(
        {
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "phase10_vulnerability_specification",
                    "strict": True,
                    "schema": response_schema,
                },
            },
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return estimate_tokens(request_material) + REQUEST_ENVELOPE_TOKEN_RESERVE


def _synthesize(
    *,
    root: Path,
    work: Path,
    args: argparse.Namespace,
    experiment: Mapping[str, Any],
    budget: Mapping[str, Any],
    project_id: str,
    hypothesis_node: Mapping[str, Any],
    context_text: str,
    context_metadata: Mapping[str, Any],
    context_nodes: Mapping[str, Mapping[str, Any]],
    codeql: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    properties = cast(Mapping[str, Any], hypothesis_node["properties"])
    hypothesis_id = str(properties["upstream_hypothesis_id"])
    candidate_cwes = [str(value) for value in cast(Sequence[Any], properties["candidate_cwe"])]
    allowed_ids = {
        str(value)
        for value in cast(Sequence[Any], context_metadata["serialized_node_ids"])
    }
    endpoint_ids_by_role = _endpoint_ids_by_role(context_nodes, allowed_ids)
    for required_role in ("sources", "sinks"):
        if not endpoint_ids_by_role[required_role]:
            raise ValueError(
                f"context has no grounded {required_role} candidate; refusing ungrounded LLM call"
            )
    evidence_ids = sorted(
        node_id
        for node_id in allowed_ids
        if node_id in context_nodes and context_nodes[node_id].get("layer") == "evidence"
    )
    spec_config = cast(Mapping[str, Any], experiment["specification"])
    response_schema = specification_json_schema(
        hypothesis_id=hypothesis_id,
        candidate_cwes=candidate_cwes,
        allowed_endpoint_ids_by_role=endpoint_ids_by_role,
        allowed_evidence_ids=evidence_ids,
        max_role_items=int(spec_config["max_role_items"]),
        max_preconditions=int(spec_config["max_preconditions"]),
    )
    model_path = root / str(cast(Mapping[str, Any], experiment["llm"])["model_config"])
    settings = OpenRouterSettings.load(root, model_path)
    maximum_attempts = min(
        1 + int(spec_config["max_repair_attempts"]), int(budget["max_calls_per_project"])
    )
    base_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt(context_text)},
    ]
    last_error = "no synthesis attempt"
    compilation = cast(dict[str, Any], {})
    for attempt in range(1, maximum_attempts + 1):
        usage_before = _project_usage(work, args.baseline_id, project_id)
        if int(usage_before["calls"]) >= int(budget["max_calls_per_project"]):
            raise RuntimeError("per-project call budget exhausted before repair")
        if int(usage_before["input_tokens"]) >= int(
            budget["max_total_input_tokens_per_project"]
        ):
            raise RuntimeError("per-project input-token budget exhausted before repair")
        messages = list(base_messages)
        if attempt > 1:
            messages.append({"role": "user", "content": repair_prompt(last_error)})
        estimated_request_tokens = _estimated_request_tokens(
            context_text,
            response_schema,
            repair_error=last_error if attempt > 1 else None,
        )
        if estimated_request_tokens > int(budget["max_context_tokens_per_call"]):
            raise ValueError(
                "estimated prompt/schema request exceeds the per-call input-token budget"
            )
        client = OpenRouterClient(
            settings,
            work / "llm_calls.jsonl",
            {
                "phase": 10,
                "baseline_id": args.baseline_id,
                "project_id": project_id,
                "hypothesis_id": hypothesis_id,
                "context_id": context_metadata["context_id"],
                "synthesis_attempt": attempt,
            },
        )
        response = client.complete(
            messages,
            expect_json=True,
            max_tokens=int(budget["max_output_tokens_per_call"]),
            response_schema=response_schema,
            response_schema_name="phase10_vulnerability_specification",
        )
        try:
            specification = parse_specification(
                response,
                project_id=project_id,
                hypothesis_id=hypothesis_id,
                candidate_cwes=candidate_cwes,
                context_id=str(context_metadata["context_id"]),
                context_nodes=context_nodes,
                allowed_node_ids=allowed_ids,
                baseline_id=args.baseline_id,
                attempt=attempt,
                max_role_items=int(spec_config["max_role_items"]),
                max_preconditions=int(spec_config["max_preconditions"]),
            )
            query = render_query(specification, context_nodes)
            query_path = (
                work
                / "generated_queries"
                / project_id
                / f"{specification['specification_id']}_attempt_{attempt}.ql"
            )
            _write_text(query_path, query)
            compile_config = cast(Mapping[str, Any], experiment["compilation"])
            compilation = compile_query(
                codeql=codeql,
                query_path=query_path,
                timeout_seconds=int(compile_config["timeout_seconds"]),
                ram_mb=int(compile_config["ram_mb"]),
            )
            compilation.update(
                {
                    "schema_version": 1,
                    "baseline_id": args.baseline_id,
                    "project_id": project_id,
                    "hypothesis_id": hypothesis_id,
                    "context_id": context_metadata["context_id"],
                    "specification_id": specification["specification_id"],
                    "attempt": attempt,
                    "query": query_path.relative_to(work).as_posix(),
                    "query_sha256": sha256_file(query_path),
                }
            )
            _append_jsonl(work / "compile_attempts.jsonl", compilation)
            if compilation["status"] != "COMPILED":
                raise ValueError(
                    "CodeQL compile failed: "
                    + str(compilation.get("stderr") or compilation.get("stdout"))[-500:]
                )
            specification["query"] = compilation["query"]
            specification["query_sha256"] = compilation["query_sha256"]
            specification["compile_status"] = "COMPILED"
            return specification, compilation
        except (OSError, ValueError) as error:
            last_error = str(error)[:500]
            _append_jsonl(
                work / "repair_log.jsonl",
                {
                    "schema_version": 1,
                    "baseline_id": args.baseline_id,
                    "project_id": project_id,
                    "hypothesis_id": hypothesis_id,
                    "context_id": context_metadata["context_id"],
                    "attempt": attempt,
                    "status": "REPAIR_REQUIRED" if attempt < maximum_attempts else "FAILED",
                    "error": last_error,
                },
            )
    raise ValueError(f"specification failed after {maximum_attempts} attempt(s): {last_error}")


def _summary(
    *,
    baseline_id: str,
    statuses: Sequence[Mapping[str, Any]],
    contexts: Sequence[Mapping[str, Any]],
    specifications: Sequence[Mapping[str, Any]],
    compilations: Sequence[Mapping[str, Any]],
    calls: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    selected = len(statuses)
    successes = sum(row.get("status") == "SUCCESS" for row in statuses)
    compile_successes = sum(row.get("status") == "COMPILED" for row in compilations)
    final_compiles = len(specifications)
    usage = _usage(calls)
    return {
        "schema_version": 1,
        "phase": 10,
        "baseline_id": baseline_id,
        "projects": selected,
        "analysis_successes": successes,
        "analysis_failures": selected - successes,
        "contexts": len(contexts),
        "specifications": len(specifications),
        "compile_attempts": len(compilations),
        "compiled_attempts": compile_successes,
        "final_compiled_specifications": final_compiles,
        "compile_rate": final_compiles / len(specifications) if specifications else 0.0,
        "context_estimated_tokens": sum(int(row.get("estimated_tokens", 0)) for row in contexts),
        **usage,
        "final_findings": 0,
        "verification_status": "DEFERRED_TO_PHASE_11",
    }


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if os.environ.get("MAXVERA_DATA_ROLE") == "evaluator":
        raise RuntimeError("refusing Phase 10 analysis while MAXVERA_DATA_ROLE=evaluator")
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid Phase 10 run ID")
    baseline_path = args.config if args.config.is_absolute() else root / args.config
    experiment_path = args.experiment if args.experiment.is_absolute() else root / args.experiment
    baseline = _mapping(baseline_path)
    experiment = _mapping(experiment_path)
    _validate_config(args.baseline_id, baseline, experiment)
    dependency = dependency_status(root, experiment)
    phase9_config = cast(
        Mapping[str, Any], cast(Mapping[str, Any], experiment["development_dependency"])["phase9"]
    )
    phase9_root = root / str(phase9_config["run_root"])
    phase9_statuses = read_jsonl(phase9_root / "project_status.jsonl")
    phase9_by_id = {str(row["project_id"]): row for row in phase9_statuses}
    selected = _selected_projects(phase9_statuses, args)
    if args.mode == "full" and collect_git(root).get("dirty") is not False:
        raise ValueError("Phase 10 full mode requires a clean Git worktree")
    work, final = _prepare_output(root, args, str(baseline["name"]))
    manifest_path = work / "manifest.json"
    if not manifest_path.exists():
        atomic_json(
            manifest_path,
            _manifest(
                root=root,
                args=args,
                baseline_path=baseline_path,
                baseline=baseline,
                experiment_path=experiment_path,
                experiment=experiment,
                dependency=dependency,
                selected=selected,
            ),
        )
        atomic_json(work / "environment.json", collect_environment(root))
        atomic_json(work / "dependency_status.json", dependency)
        _write_text(work / "command.txt", shlex.join(sys.argv) + "\n")
        resolved_args = {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        }
        _write_text(
            work / "config.resolved.yaml",
            yaml.safe_dump(
                cast(
                    dict[str, Any],
                    redact_secrets(
                        {"arguments": resolved_args, "baseline": baseline, "experiment": experiment}
                    ),
                ),
                sort_keys=True,
            ),
        )
        for name in (
            "contexts.jsonl",
            "specifications.jsonl",
            "compile_attempts.jsonl",
            "repair_log.jsonl",
            "llm_calls.jsonl",
            "project_summary.jsonl",
            "resource_usage.jsonl",
            "stdout.log",
            "stderr.log",
        ):
            (work / name).touch()
        initial_statuses = _initial_statuses(selected, phase9_by_id)
        atomic_jsonl(work / "project_status.jsonl", initial_statuses)
        inherited_summaries = [
            {
                "schema_version": 1,
                "project_id": row["project_id"],
                "status": "ANALYSIS_FAILED",
                "hypotheses": 0,
                "specifications": 0,
                "errors": 1,
                "calls": 0,
                "retries": 0,
                "input_tokens": 0,
                "billed_output_tokens": 0,
                "reasoning_tokens": 0,
                "output_tokens": 0,
                "api_cost_usd": 0.0,
            }
            for row in initial_statuses
            if row["status"] == "ANALYSIS_FAILED"
        ]
        atomic_jsonl(work / "project_summary.jsonl", inherited_summaries)
        atomic_jsonl(
            work / "resource_usage.jsonl",
            [
                {
                    "schema_version": 1,
                    "project_id": row["project_id"],
                    "wall_seconds": 0.0,
                    "peak_rss_kb": 0,
                    "calls": 0,
                    "retries": 0,
                    "input_tokens": 0,
                    "billed_output_tokens": 0,
                    "reasoning_tokens": 0,
                    "output_tokens": 0,
                    "api_cost_usd": 0.0,
                }
                for row in initial_statuses
                if row["status"] == "ANALYSIS_FAILED"
            ],
        )
        _write_text(
            work / "generated_queries/qlpack.yml",
            "name: maxvera/phase10-generated\n"
            "version: 0.0.0\n"
            "library: false\n"
            "dependencies:\n"
            "  codeql/java-all: 9.2.2\n",
        )

    statuses = read_jsonl(work / "project_status.jsonl")
    if [str(row["project_id"]) for row in statuses] != selected:
        raise ValueError("resume project selection does not match Phase 10 manifest")
    nodes = read_jsonl(phase9_root / "useg/nodes.jsonl")
    edges = read_jsonl(phase9_root / "useg/edges.jsonl")
    retrieval = cast(Mapping[str, Any], experiment["retrieval"])
    budget = cast(Mapping[str, Any], experiment["budget"])[args.budget_mode]
    spec_config = cast(Mapping[str, Any], experiment["specification"])
    strategy = str(baseline["retrieval"])
    overhead = estimate_tokens(SYSTEM_PROMPT + user_prompt(""))
    context_budget = (
        int(budget["max_context_tokens_per_call"])
        - overhead
        - int(retrieval["prompt_reserve_tokens"])
    )
    if context_budget < 1:
        raise ValueError("Phase 10 prompt reserve leaves no context budget")

    if args.dry_run:
        plans: list[dict[str, Any]] = []
        for project_id in selected:
            if phase9_by_id[project_id].get("status") != "SUCCESS":
                plans.append(
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
                allowed_ids = {
                    str(value)
                    for value in cast(Sequence[Any], metadata["serialized_node_ids"])
                }
                endpoint_ids = _endpoint_ids_by_role(by_id, allowed_ids)
                estimated_request_tokens: int | None = None
                within_call_budget = True
                if endpoint_ids["sources"] and endpoint_ids["sinks"]:
                    properties = cast(Mapping[str, Any], hypothesis["properties"])
                    evidence_ids = sorted(
                        node_id
                        for node_id in allowed_ids
                        if node_id in by_id and by_id[node_id].get("layer") == "evidence"
                    )
                    response_schema = specification_json_schema(
                        hypothesis_id=str(properties["upstream_hypothesis_id"]),
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
                plans.append(
                    {
                        **metadata,
                        "endpoint_candidates": {
                            role: len(endpoint_ids[role]) for role in ROLES
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
        planned_contexts = sum("context_id" in row for row in plans)
        planned_api_eligible = sum(row.get("ready_for_api") is True for row in plans)
        atomic_jsonl(work / "dry_run_plan.jsonl", plans)
        atomic_json(
            work / "phase10_summary.json",
            {
                "schema_version": 1,
                "phase": 10,
                "baseline_id": args.baseline_id,
                "dry_run": True,
                "selected_projects": len(selected),
                "planned_contexts": planned_contexts,
                "planned_api_eligible_contexts": planned_api_eligible,
                "planned_fail_closed_contexts": planned_contexts - planned_api_eligible,
                "network_calls": 0,
                "llm_calls": 0,
            },
        )
        _write_text(work / "STATUS", "DRY_RUN\n")
        write_checksums(work)
        os.replace(work, final)
        print(f"Phase 10 dry-run created without API calls: {final.relative_to(root)}")
        return 0

    if not args.confirm_api_spend:
        raise ValueError("Phase 10 LLM synthesis requires --confirm-api-spend")
    settings = OpenRouterSettings.load(
        root, root / str(cast(Mapping[str, Any], experiment["llm"])["model_config"])
    )
    if settings.provider != cast(Mapping[str, Any], experiment["llm"])["provider_route"]:
        raise ValueError("OpenRouter provider route differs from Phase 10 lock")
    codeql = _codeql(root)

    status_by_id = {str(row["project_id"]): row for row in statuses}
    contexts = read_jsonl(work / "contexts.jsonl")
    specifications = read_jsonl(work / "specifications.jsonl")
    project_summaries = read_jsonl(work / "project_summary.jsonl")
    resources = read_jsonl(work / "resource_usage.jsonl")
    context_keys = {(str(row["project_id"]), str(row["hypothesis_id"])) for row in contexts}
    spec_keys = {
        (str(row["project_id"]), str(row["hypothesis_id"])) for row in specifications
    }
    for position, project_id in enumerate(selected, start=1):
        status = status_by_id[project_id]
        if status["status"] in {"SUCCESS", "ANALYSIS_FAILED"}:
            print(
                f"[{position}/{len(selected)}] {project_id}: "
                f"{status['status']} (resume/upstream)"
            )
            continue
        started = time.monotonic()
        hypotheses = _hypotheses(nodes, project_id)[
            : int(retrieval["hypothesis_limit_per_project"])
        ]
        project_errors: list[str] = []
        completed = 0
        try:
            if not hypotheses:
                raise ValueError("Phase 9 success has no hypothesis nodes")
            for hypothesis in hypotheses:
                properties = cast(Mapping[str, Any], hypothesis["properties"])
                hypothesis_id = str(properties["upstream_hypothesis_id"])
                if (project_id, hypothesis_id) in spec_keys:
                    completed += 1
                    continue
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
                if (project_id, hypothesis_id) not in context_keys:
                    context_record = {**metadata, "context_text": context_text}
                    contexts.append(context_record)
                    atomic_jsonl(work / "contexts.jsonl", contexts)
                    context_keys.add((project_id, hypothesis_id))
                try:
                    specification, _compilation = _synthesize(
                        root=root,
                        work=work,
                        args=args,
                        experiment=experiment,
                        budget=budget,
                        project_id=project_id,
                        hypothesis_node=hypothesis,
                        context_text=context_text,
                        context_metadata=metadata,
                        context_nodes=by_id,
                        codeql=codeql,
                    )
                    specifications.append(specification)
                    atomic_jsonl(work / "specifications.jsonl", specifications)
                    spec_keys.add((project_id, hypothesis_id))
                    completed += 1
                except Exception as error:  # preserve a per-hypothesis final failure
                    project_errors.append(f"{hypothesis_id}: {type(error).__name__}: {error}"[:700])
                    _append_jsonl(
                        work / "stderr.log",
                        {
                            "project_id": project_id,
                            "hypothesis_id": hypothesis_id,
                            "error_type": type(error).__name__,
                            "error": str(error)[:500],
                        },
                    )
            if project_errors:
                raise ValueError(f"{len(project_errors)} hypothesis synthesis failure(s)")
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "all selected hypotheses produced grounded, compiling specs",
                    "specifications": completed,
                    "updated_at": utc_now(),
                }
            )
        except Exception as error:
            status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": f"{type(error).__name__}: {str(error)[:500]}",
                    "specifications": completed,
                    "updated_at": utc_now(),
                }
            )
        usage = _project_usage(work, args.baseline_id, project_id)
        if int(usage["calls"]) > int(budget["max_calls_per_project"]):
            raise RuntimeError("per-project call budget exceeded")
        if int(usage["input_tokens"]) > int(budget["max_total_input_tokens_per_project"]):
            raise RuntimeError("per-project input-token budget exceeded")
        project_summaries = [
            row for row in project_summaries if row.get("project_id") != project_id
        ]
        project_summaries.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": status["status"],
                "hypotheses": len(hypotheses),
                "specifications": completed,
                "errors": len(project_errors),
                **usage,
            }
        )
        resources = [row for row in resources if row.get("project_id") != project_id]
        resources.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "wall_seconds": round(time.monotonic() - started, 3),
                "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                **usage,
            }
        )
        atomic_jsonl(work / "project_status.jsonl", statuses)
        atomic_jsonl(
            work / "project_summary.jsonl",
            sorted(
                project_summaries,
                key=lambda row: selected.index(str(row["project_id"])),
            ),
        )
        atomic_jsonl(
            work / "resource_usage.jsonl",
            sorted(resources, key=lambda row: selected.index(str(row["project_id"]))),
        )
        print(f"[{position}/{len(selected)}] {project_id}: {status['status']}", flush=True)

    calls = read_jsonl(work / "llm_calls.jsonl")
    compilations = read_jsonl(work / "compile_attempts.jsonl")
    summary = _summary(
        baseline_id=args.baseline_id,
        statuses=statuses,
        contexts=contexts,
        specifications=specifications,
        compilations=compilations,
        calls=calls,
    )
    atomic_json(work / "phase10_summary.json", summary)
    manifest = _json(manifest_path)
    manifest["model"]["returned_models"] = sorted(
        {
            str(row["returned_model"])
            for row in calls
            if row.get("status") == "SUCCESS" and row.get("returned_model")
        }
    )
    manifest["openrouter_request_ids"] = [
        str(row["request_id"])
        for row in calls
        if row.get("status") == "SUCCESS" and row.get("request_id")
    ]
    atomic_json(manifest_path, manifest)
    failed = [row for row in statuses if row.get("status") != "SUCCESS"]
    _write_text(work / "STATUS", "FAILED\n" if failed else "SUCCESS\n")
    write_checksums(work)
    os.replace(work, final)
    from src.specification.validate import validate

    print(validate(final, repo_root=root))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-id", choices=tuple(sorted(IMPLEMENTED)), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--experiment",
        type=Path,
        default=Path("configs/experiments/phase10_retrieval_specification.yaml"),
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument(
        "--budget-mode", choices=("budget_matched", "best_effort"), default="budget_matched"
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--project-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--output-root", type=Path, default=Path("results/specifications/phase10")
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
