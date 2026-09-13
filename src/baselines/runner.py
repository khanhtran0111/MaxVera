"""Run the Phase 5 B3-B5 controlled baselines without evaluator-label access."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import resource
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.baselines.context import (
    chunk_inventory,
    estimate_tokens,
    select_raw,
    select_text_rag,
    serialize_context,
    source_chunks,
    static_hypotheses,
)
from src.baselines.schema import findings_sarif, hypotheses_json_schema, parse_hypotheses
from src.common.envfile import effective_env
from src.common.provenance import (
    assert_secret_free,
    collect_environment,
    collect_git,
    redact_secrets,
    sha256_file,
    utc_now,
)
from src.llm.prompts.phase5 import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    prompt_sha256,
    repair_prompt,
    user_prompt,
)
from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums

IMPLEMENTED = {"B3", "B4", "B5"}
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FORBIDDEN_CONFIG_WORDS = {
    "advisory_text",
    "buggy_commit_id",
    "cve_id",
    "fix_commit",
    "fixed_line",
    "ground_truth_cwe",
    "project_slug",
}


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _assert_analysis_config_safe(config: Mapping[str, Any]) -> None:
    serialized = json.dumps(config, sort_keys=True).casefold()
    leaked = sorted(field for field in FORBIDDEN_CONFIG_WORDS if field in serialized)
    if leaked:
        raise ValueError(f"analysis config crosses the label firewall: {', '.join(leaked)}")


def _load_project_rows(
    root: Path, experiment: Mapping[str, Any], split: Path
) -> list[dict[str, str]]:
    analysis_manifest = root / str(experiment["dataset"]["analysis_manifest"])
    projects = read_csv(analysis_manifest)
    allowed_columns = {
        "project_id",
        "source_dir",
        "source_required",
        "jdk_version",
        "maven_version",
        "gradle_version",
        "use_gradlew",
    }
    if any(set(row) - allowed_columns for row in projects):
        raise ValueError("analysis manifest contains non-analysis columns")
    selected_ids = {row["project_id"] for row in read_csv(split)}
    known_ids = {row["project_id"] for row in projects}
    unknown = selected_ids - known_ids
    if unknown:
        raise ValueError(f"split contains {len(unknown)} unknown project IDs")
    return [row for row in projects if row["project_id"] in selected_ids]


def _all_project_rows(root: Path, experiment: Mapping[str, Any]) -> list[dict[str, str]]:
    return read_csv(root / str(experiment["dataset"]["analysis_manifest"]))


def _source_root(root: Path, experiment: Mapping[str, Any], row: Mapping[str, str]) -> Path:
    configured = root / str(experiment["dataset"]["source_root"])
    return configured / row["project_id"]


def _initial_statuses(
    all_projects: Sequence[Mapping[str, str]], selected: set[str], mode: str
) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": 1,
            "project_id": row["project_id"],
            "status": "PENDING" if row["project_id"] in selected else "EXCLUDED_WITH_REASON",
            "reason": "selected and waiting for analysis"
            if row["project_id"] in selected
            else f"not selected by {mode} split",
            "updated_at": utc_now(),
        }
        for row in all_projects
    ]


def _save_statuses(run_root: Path, statuses: Sequence[Mapping[str, Any]]) -> None:
    atomic_jsonl(run_root / "project_status.jsonl", statuses)
    counts = Counter(str(row["status"]) for row in statuses)
    atomic_json(
        run_root / "status_summary.json",
        {"schema_version": 1, "total": len(statuses), "counts": dict(sorted(counts.items()))},
    )


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(value), sort_keys=True, ensure_ascii=False) + "\n")


def _usage(records: Sequence[Mapping[str, Any]]) -> dict[str, int | float]:
    successes = [record for record in records if record.get("status") == "SUCCESS"]
    retries = sum(record.get("status") == "RETRY" for record in records)
    totals: dict[str, int | float] = {
        "calls": len(successes),
        "retries": retries,
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "billed_output_tokens": 0,
        "cached_tokens": 0,
        "api_cost_usd": 0.0,
    }
    for record in successes:
        usage = record.get("usage", {})
        if not isinstance(usage, Mapping):
            continue
        totals["input_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
        billed_output = int(usage.get("completion_tokens", 0) or 0)
        details = usage.get("completion_tokens_details", {})
        reasoning = 0
        if isinstance(details, Mapping):
            reasoning = int(details.get("reasoning_tokens", 0) or 0)
        totals["billed_output_tokens"] += billed_output
        totals["reasoning_tokens"] += reasoning
        totals["output_tokens"] += max(0, billed_output - reasoning)
        prompt_details = usage.get("prompt_tokens_details", {})
        if isinstance(prompt_details, Mapping):
            totals["cached_tokens"] += int(prompt_details.get("cached_tokens", 0) or 0)
        totals["api_cost_usd"] += float(usage.get("cost", 0.0) or 0.0)
    return totals


def _resource_row(
    project_id: str,
    wall_seconds: float,
    usage: Mapping[str, int | float],
) -> dict[str, str]:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "project_id": project_id,
        "wall_seconds": f"{wall_seconds:.3f}",
        "peak_rss_kb": str(peak),
        **{key: str(value) for key, value in usage.items()},
    }


def _write_resource_usage(path: Path, rows: Sequence[Mapping[str, str]]) -> None:
    fields = (
        "project_id",
        "wall_seconds",
        "peak_rss_kb",
        "calls",
        "retries",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "billed_output_tokens",
        "cached_tokens",
        "api_cost_usd",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _manifest(
    root: Path,
    args: argparse.Namespace,
    config_path: Path,
    config: Mapping[str, Any],
    experiment_path: Path,
    experiment: Mapping[str, Any],
    split: Path,
    selected_ids: Sequence[str],
) -> dict[str, Any]:
    model_path = root / str(config["model_config"]) if config.get("llm_enabled") else None
    model = _mapping(model_path) if model_path else None
    machine = effective_env(root / ".env")
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "phase": 5,
        "protocol_version": str(experiment["protocol_version"]),
        "baseline_id": args.baseline_id,
        "baseline_name": str(config["name"]),
        "run_id": args.run_id,
        "mode": args.mode,
        "budget_mode": args.budget_mode,
        "seed": args.seed,
        "device": args.device,
        "parent_run_id": args.parent_run_id,
        "created_at": utc_now(),
        "git": collect_git(root),
        "dataset": {
            "id": str(experiment["dataset"]["id"]),
            "analysis_manifest": str(experiment["dataset"]["analysis_manifest"]),
            "analysis_manifest_sha256": sha256_file(
                root / str(experiment["dataset"]["analysis_manifest"])
            ),
            "split": split.relative_to(root).as_posix(),
            "split_sha256": sha256_file(split),
        },
        "selected_project_count": len(selected_ids),
        "selected_project_ids": list(selected_ids),
        "data_access": "opaque analysis_input and Java source only; evaluator labels forbidden",
        "baseline_config": {
            "path": config_path.relative_to(root).as_posix(),
            "sha256": sha256_file(config_path),
        },
        "experiment_config": {
            "path": experiment_path.relative_to(root).as_posix(),
            "sha256": sha256_file(experiment_path),
        },
        "prompt": {"version": PROMPT_VERSION, "sha256": prompt_sha256()},
        "budget": dict(
            cast(Mapping[str, Any], cast(Mapping[str, Any], experiment["budget"])[args.budget_mode])
        ),
        "implementation_sha256": {
            relative: sha256_file(root / relative)
            for relative in (
                "src/baselines/context.py",
                "src/baselines/runner.py",
                "src/baselines/schema.py",
                "src/llm/prompts/phase5.py",
                "src/llm/providers/openrouter.py",
            )
        },
    }
    if model:
        manifest["model"] = {
            "requested_model": model["model_id"],
            "returned_models": [],
            "backend": model["backend"],
            "provider_route": model["provider_route"],
            "provider_metadata_snapshot_date": model["provider_metadata_snapshot_date"],
            "authentication_variable_name": model["api_key_env"],
            "routing": model["routing"],
            "reasoning_effort": model["reasoning_effort"],
            "hosted_model_weight_sha256": None,
        }
    redacted = cast(dict[str, Any], redact_secrets(manifest))
    assert_secret_free(redacted, machine)
    return redacted


def _validate_config(
    baseline_id: str, config: Mapping[str, Any], experiment: Mapping[str, Any]
) -> None:
    if baseline_id not in IMPLEMENTED or config.get("baseline_id") != baseline_id:
        raise ValueError("Phase 5 runner supports only matching B3, B4, or B5 config")
    if config.get("status") != "implemented_phase_5":
        raise ValueError("baseline is not marked implemented_phase_5")
    _assert_analysis_config_safe(config)
    if experiment.get("status") != "frozen_phase_5":
        raise ValueError("Phase 5 experiment config must be frozen_phase_5")
    if config.get("llm_enabled"):
        llm = experiment.get("llm", {})
        if not isinstance(llm, Mapping):
            raise ValueError("Phase 5 experiment LLM configuration is missing")
        expected_provider = str(llm.get("provider_route", ""))
        if not expected_provider or config.get("provider_route") != expected_provider:
            raise ValueError("baseline and experiment provider routes do not match")
    for name in ("budget_matched", "best_effort"):
        budget = experiment.get("budget", {}).get(name)
        if not isinstance(budget, Mapping):
            raise ValueError(f"missing {name} budget")
        for key in (
            "max_context_tokens_per_call",
            "max_output_tokens_per_call",
            "max_calls_per_project",
            "max_total_input_tokens_per_project",
        ):
            if int(budget.get(key, 0)) < 1:
                raise ValueError(f"invalid {name}.{key}")


def _select_context(
    baseline_id: str,
    chunks: Sequence[Any],
    token_budget: int,
) -> list[Any]:
    if baseline_id == "B3":
        return select_raw(chunks, token_budget)
    if baseline_id == "B4":
        return select_text_rag(chunks, token_budget)
    return list(chunks)


def _llm_hypotheses(
    root: Path,
    run_root: Path,
    baseline_id: str,
    project_id: str,
    source: Path,
    context: str,
    top_k: int,
    budget: Mapping[str, Any],
    model_config_path: Path,
    allowed_files: Sequence[str],
) -> tuple[list[dict[str, object]], dict[str, int | float]]:
    settings = OpenRouterSettings.load(root, model_config_path)
    call_log = run_root / "llm_calls.jsonl"
    client = OpenRouterClient(
        settings,
        call_log,
        {"baseline_id": baseline_id, "project_id": project_id},
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt(context, top_k=top_k)},
    ]
    model_config = _mapping(model_config_path)
    json_policy = cast(Mapping[str, Any], model_config["json_policy"])
    maximum_calls = min(
        int(budget["max_calls_per_project"]),
        1 + int(json_policy["max_repair_attempts"]),
    )
    errors: list[str] = []
    result: list[dict[str, object]] | None = None
    response_schema = hypotheses_json_schema(allowed_files, top_k=top_k)
    for repair in range(maximum_calls):
        if repair:
            messages = [
                *messages[:2],
                {
                    "role": "user",
                    "content": repair_prompt(errors[-1]),
                },
            ]
        response = client.complete(
            messages,
            expect_json=True,
            max_tokens=int(budget["max_output_tokens_per_call"]),
            response_schema=response_schema,
        )
        try:
            result = parse_hypotheses(
                response,
                project_id=project_id,
                source_root=source,
                top_k=top_k,
                generator="raw_context_llm" if baseline_id == "B3" else "text_rag_llm",
            )
            break
        except (OSError, ValueError) as error:
            errors.append(str(error)[:500])
            _append_jsonl(
                run_root / "schema_errors.jsonl",
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "attempt": repair + 1,
                    "error": str(error)[:500],
                },
            )
    records = [
        row
        for row in read_jsonl(call_log)
        if row.get("project_id") == project_id and row.get("baseline_id") == baseline_id
    ]
    usage = _usage(records)
    if int(usage["calls"]) > int(budget["max_calls_per_project"]):
        raise RuntimeError("per-project call budget exceeded")
    if int(usage["input_tokens"]) > int(budget["max_total_input_tokens_per_project"]):
        raise RuntimeError("per-project input-token budget exceeded")
    if result is None:
        raise ValueError(f"model schema validation failed {len(errors)} time(s)")
    return result, usage


def _prepare_output(
    root: Path,
    args: argparse.Namespace,
    baseline_name: str,
) -> tuple[Path, Path]:
    output_root = args.output_root
    if not output_root.is_absolute():
        output_root = root / output_root
    final = output_root / baseline_name / args.run_id
    work = output_root / baseline_name / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable result already exists: {final}")
    if work.exists() and not args.resume:
        raise FileExistsError(f"unfinished run exists; use --resume: {work}")
    work.mkdir(parents=True, exist_ok=True)
    return work, final


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if os.environ.get("MAXVERA_DATA_ROLE") == "evaluator":
        raise RuntimeError("refusing to run analysis while MAXVERA_DATA_ROLE=evaluator")
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("run ID must be 1-80 safe filename characters")
    config_path = args.config if args.config.is_absolute() else root / args.config
    experiment_path = args.experiment if args.experiment.is_absolute() else root / args.experiment
    split = args.split if args.split.is_absolute() else root / args.split
    config = _mapping(config_path)
    experiment = _mapping(experiment_path)
    _validate_config(args.baseline_id, config, experiment)
    _assert_analysis_config_safe(experiment)
    dataset_config = cast(Mapping[str, Any], experiment["dataset"])
    analysis_manifest = (root / str(dataset_config["analysis_manifest"])).resolve()
    source_directory = (root / str(dataset_config["source_root"])).resolve()
    if not analysis_manifest.is_relative_to((root / "data/processed/analysis_input").resolve()):
        raise ValueError("analysis manifest must stay inside analysis_input")
    if not source_directory.is_relative_to((root / "data/interim/project_sources").resolve()):
        raise ValueError("source root must stay inside the prepared project source directory")
    allowed_split_roots = (
        (root / "data/processed/analysis_input").resolve(),
        (root / "data/processed/splits").resolve(),
    )
    if not any(split.resolve().is_relative_to(directory) for directory in allowed_split_roots):
        raise ValueError("split must come from the analysis_input or splits directory")
    all_projects = _all_project_rows(root, experiment)
    selected = _load_project_rows(root, experiment, split)
    if args.limit is not None:
        if args.mode == "full":
            raise ValueError("--limit is only allowed for pilot/dry-run")
        selected = selected[: args.limit]
    selected_ids = [row["project_id"] for row in selected]
    if config.get("llm_enabled") and not args.dry_run:
        if not args.confirm_api_spend:
            raise ValueError("LLM baseline requires explicit --confirm-api-spend")
        model_config_path = root / str(config["model_config"])
        settings = OpenRouterSettings.load(root, model_config_path)
        expected_provider = str(cast(Mapping[str, Any], experiment["llm"])["provider_route"])
        if settings.provider != expected_provider:
            raise ValueError(
                f"Phase 5 requires provider route {expected_provider}, got {settings.provider}"
            )
    work, final = _prepare_output(root, args, str(config["name"]))
    _write_text(work / "STATUS", "RUNNING\n")
    _write_text(work / "command.txt", " ".join(sys.argv) + "\n")
    atomic_json(work / "environment.json", collect_environment(root))
    resolved_arguments = {
        key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()
    }
    resolved = {"baseline": config, "experiment": experiment, "arguments": resolved_arguments}
    safe_resolved = cast(dict[str, Any], redact_secrets(resolved))
    _write_text(work / "config.resolved.yaml", yaml.safe_dump(safe_resolved, sort_keys=True))
    manifest_path = work / "manifest.json"
    if not manifest_path.exists():
        atomic_json(
            manifest_path,
            _manifest(
                root,
                args,
                config_path,
                config,
                experiment_path,
                experiment,
                split,
                selected_ids,
            ),
        )
    statuses_path = work / "project_status.jsonl"
    statuses = (
        read_jsonl(statuses_path)
        if statuses_path.exists()
        else _initial_statuses(all_projects, set(selected_ids), args.mode)
    )
    _save_statuses(work, statuses)
    for name in (
        "findings.jsonl",
        "hypotheses.jsonl",
        "specifications.jsonl",
        "llm_calls.jsonl",
        "timings.jsonl",
        "schema_errors.jsonl",
        "stdout.log",
        "stderr.log",
    ):
        (work / name).touch(exist_ok=True)
    if args.dry_run:
        estimates: list[dict[str, Any]] = []
        context_config = cast(Mapping[str, Any], config["context"])
        budget = cast(Mapping[str, Any], experiment["budget"])[args.budget_mode]
        for row in selected:
            source = _source_root(root, experiment, row)
            chunks = source_chunks(
                source,
                chunk_lines=int(context_config["chunk_lines"]),
                overlap_lines=int(context_config["overlap_lines"]),
                max_file_bytes=int(context_config["max_file_bytes"]),
            )
            prompt_overhead = estimate_tokens(
                SYSTEM_PROMPT + user_prompt("", top_k=int(config["top_k"]))
            )
            available = max(1, int(budget["max_context_tokens_per_call"]) - prompt_overhead - 512)
            chosen = _select_context(args.baseline_id, chunks, available)
            estimated_input = (
                0
                if args.baseline_id == "B5"
                else prompt_overhead + estimate_tokens(serialize_context(chosen))
            )
            estimates.append(
                {
                    "project_id": row["project_id"],
                    "java_chunks": len(chunks),
                    "selected_chunks": len(chosen),
                    "estimated_input_tokens": estimated_input,
                }
            )
        atomic_jsonl(work / "dry_run_plan.jsonl", estimates)
        _write_text(work / "STATUS", "DRY_RUN\n")
        write_checksums(work)
        os.replace(work, final)
        print(f"Dry-run plan created without API calls: {_display_path(final, root)}")
        return 0
    status_by_id = {str(row["project_id"]): row for row in statuses}
    existing_hypotheses = read_jsonl(work / "hypotheses.jsonl")
    by_project: dict[str, list[dict[str, Any]]] = {}
    for item in existing_hypotheses:
        by_project.setdefault(str(item["project_id"]), []).append(item)
    resources: list[dict[str, str]] = []
    resource_path = work / "resource_usage.csv"
    if resource_path.is_file() and resource_path.stat().st_size:
        resources = read_csv(resource_path)
    context_config = cast(Mapping[str, Any], config["context"])
    budget = cast(Mapping[str, Any], experiment["budget"])[args.budget_mode]
    for position, row in enumerate(selected, start=1):
        project_id = row["project_id"]
        status = status_by_id[project_id]
        if status["status"] == "SUCCESS":
            print(f"[{position}/{len(selected)}] {project_id}: SUCCESS (resume)")
            continue
        started = time.monotonic()
        source = _source_root(root, experiment, row)
        try:
            if not source.is_dir():
                raise FileNotFoundError(f"source directory is missing: {source}")
            chunks = source_chunks(
                source,
                chunk_lines=int(context_config["chunk_lines"]),
                overlap_lines=int(context_config["overlap_lines"]),
                max_file_bytes=int(context_config["max_file_bytes"]),
            )
            if not chunks:
                raise ValueError("no eligible Java source chunks")
            if args.baseline_id == "B5":
                hypotheses = static_hypotheses(
                    chunks, project_id=project_id, top_k=int(config["top_k"])
                )
                usage: dict[str, int | float] = _usage([])
                selected_chunks = chunks
            else:
                overhead = estimate_tokens(
                    SYSTEM_PROMPT + user_prompt("", top_k=int(config["top_k"]))
                )
                available = max(1, int(budget["max_context_tokens_per_call"]) - overhead - 512)
                selected_chunks = _select_context(args.baseline_id, chunks, available)
                if not selected_chunks:
                    raise ValueError("no source chunk fits the context budget")
                hypotheses, usage = _llm_hypotheses(
                    root,
                    work,
                    args.baseline_id,
                    project_id,
                    source,
                    serialize_context(selected_chunks),
                    int(config["top_k"]),
                    budget,
                    root / str(config["model_config"]),
                    [chunk.path for chunk in selected_chunks],
                )
            by_project[project_id] = [dict(item) for item in hypotheses]
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "analysis completed with schema-valid output",
                    "finding_count": len(hypotheses),
                    "updated_at": utc_now(),
                }
            )
            _append_jsonl(
                work / "timings.jsonl",
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "stage": "analysis",
                    "seconds": round(time.monotonic() - started, 3),
                    "source_chunks": len(chunks),
                    "selected_chunks": len(selected_chunks),
                },
            )
            atomic_json(
                work / "projects" / project_id / "context_inventory.json",
                {
                    "schema_version": 1,
                    "strategy": str(config["retrieval"]),
                    "chunks": chunk_inventory(selected_chunks),
                },
            )
        except Exception as error:  # project failures remain explicit and resumable
            usage = _usage(
                [
                    record
                    for record in read_jsonl(work / "llm_calls.jsonl")
                    if record.get("project_id") == project_id
                ]
            )
            status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": f"{type(error).__name__}: {str(error)[:500]}",
                    "updated_at": utc_now(),
                }
            )
            _append_jsonl(
                work / "stderr.log",
                {"project_id": project_id, "error_type": type(error).__name__},
            )
        elapsed = time.monotonic() - started
        resources = [item for item in resources if item["project_id"] != project_id]
        resources.append(_resource_row(project_id, elapsed, usage))
        _write_resource_usage(resource_path, resources)
        flattened = [item for key in selected_ids for item in by_project.get(key, [])]
        atomic_jsonl(work / "hypotheses.jsonl", flattened)
        atomic_jsonl(work / "findings.jsonl", flattened)
        _save_statuses(work, statuses)
        print(f"[{position}/{len(selected)}] {project_id}: {status['status']}", flush=True)

    flattened = [item for key in selected_ids for item in by_project.get(key, [])]
    atomic_json(work / "findings.sarif", findings_sarif(flattened))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if config.get("llm_enabled"):
        returned = sorted(
            {
                str(row["returned_model"])
                for row in read_jsonl(work / "llm_calls.jsonl")
                if row.get("status") == "SUCCESS" and row.get("returned_model")
            }
        )
        manifest["model"]["returned_models"] = returned
        manifest["openrouter_request_ids"] = [
            str(row["request_id"])
            for row in read_jsonl(work / "llm_calls.jsonl")
            if row.get("status") == "SUCCESS" and row.get("request_id")
        ]
        atomic_json(manifest_path, manifest)
    failed = [
        row
        for row in statuses
        if row["project_id"] in set(selected_ids) and row["status"] != "SUCCESS"
    ]
    _write_text(work / "STATUS", "FAILED\n" if failed else "SUCCESS\n")
    write_checksums(work)
    os.replace(work, final)
    print(f"Run completed with {len(failed)} selected failure(s): {_display_path(final, root)}")
    if failed:
        return 1
    from src.baselines.validate import validate

    print(validate(final, require_metrics=False))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-id", choices=tuple(sorted(IMPLEMENTED)), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--experiment", type=Path, default=Path("configs/experiments/phase5_baselines.yaml")
    )
    parser.add_argument(
        "--split", type=Path, default=Path("data/processed/analysis_input/D_repro_v1_projects.csv")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument(
        "--budget-mode", choices=("budget_matched", "best_effort"), default="budget_matched"
    )
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--device", default="client")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--parent-run-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("results/baselines"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.limit is not None and args.limit < 1:
        print("ERROR: --limit must be positive", file=sys.stderr)
        return 64
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
