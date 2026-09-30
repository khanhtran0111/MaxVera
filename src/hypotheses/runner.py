"""Run the development-only Phase 6 zero-hint hypothesis generator."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import resource
import shlex
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.baselines.context import estimate_tokens
from src.common.analysis_scope import analysis_scope, selected_rows, split_paths
from src.common.envfile import effective_env
from src.common.provenance import (
    assert_secret_free,
    collect_environment,
    collect_git,
    redact_secrets,
    sha256_file,
    utc_now,
)
from src.hypotheses.signals import (
    PATTERN_VERSION,
    RANKING_VERSION,
    generate_candidates,
    scan_project,
    select_top_k,
)
from src.llm.prompts.phase6 import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    parse_ranking,
    prompt_sha256,
    ranking_schema,
    user_prompt,
)
from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FINAL_PROJECT_STATUSES = {"SUCCESS", "ANALYSIS_FAILED"}
FORBIDDEN_ANALYSIS_WORDS = {
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


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _save_statuses(run_root: Path, statuses: Sequence[Mapping[str, Any]]) -> None:
    atomic_jsonl(run_root / "project_status.jsonl", statuses)
    counts = Counter(str(row["status"]) for row in statuses)
    atomic_json(
        run_root / "status_summary.json",
        {"schema_version": 1, "total": len(statuses), "counts": dict(sorted(counts.items()))},
    )


def _usage(records: Sequence[Mapping[str, Any]]) -> dict[str, int | float]:
    successes = [record for record in records if record.get("status") == "SUCCESS"]
    totals: dict[str, int | float] = {
        "calls": len(successes),
        "retries": sum(record.get("status") == "RETRY" for record in records),
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
        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        billed_output = int(usage.get("completion_tokens", 0) or 0)
        completion_details = usage.get("completion_tokens_details", {})
        reasoning = (
            int(completion_details.get("reasoning_tokens", 0) or 0)
            if isinstance(completion_details, Mapping)
            else 0
        )
        prompt_details = usage.get("prompt_tokens_details", {})
        cached = (
            int(prompt_details.get("cached_tokens", 0) or 0)
            if isinstance(prompt_details, Mapping)
            else 0
        )
        totals["input_tokens"] += prompt_tokens
        totals["billed_output_tokens"] += billed_output
        totals["reasoning_tokens"] += reasoning
        totals["output_tokens"] += max(0, billed_output - reasoning)
        totals["cached_tokens"] += cached
        totals["api_cost_usd"] += float(usage.get("cost", 0.0) or 0.0)
    return totals


def _resource_row(
    project_id: str, wall_seconds: float, usage: Mapping[str, int | float]
) -> dict[str, str]:
    return {
        "project_id": project_id,
        "wall_seconds": f"{wall_seconds:.3f}",
        "peak_rss_kb": str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        **{key: str(value) for key, value in usage.items()},
    }


def _write_resources(path: Path, rows: Sequence[Mapping[str, str]]) -> None:
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


def _validate_config(config: Mapping[str, Any]) -> None:
    serialized = json.dumps(config, sort_keys=True).casefold()
    leaked = sorted(word for word in FORBIDDEN_ANALYSIS_WORDS if word in serialized)
    if leaked:
        raise ValueError(f"Phase 6 analysis config crosses the label firewall: {leaked}")
    scope = analysis_scope(config)
    expected_status = (
        "frozen_phase_6_development"
        if scope == "development"
        else "frozen_phase_13_test_analysis"
    )
    if config.get("status") != expected_status:
        raise ValueError(f"Phase 6 experiment config is not frozen for {scope}")
    if config.get("dataset", {}).get("id") != "D_extended":
        raise ValueError("Phase 6 requires D_extended")
    generator = config.get("generator", {})
    if not isinstance(generator, Mapping) or generator.get("pattern_version") != PATTERN_VERSION:
        raise ValueError("Phase 6 signal-pattern version mismatch")
    if generator.get("ranking_version") != RANKING_VERSION:
        raise ValueError("Phase 6 ranking version mismatch")
    if int(generator.get("top_k", 0)) != 10:
        raise ValueError("Phase 6 development gate requires top_k=10")
    llm = config.get("llm", {})
    if not isinstance(llm, Mapping):
        raise ValueError("Phase 6 LLM configuration is missing")
    if llm.get("model_id") != "openai/gpt-oss-20b" or llm.get("provider_route") != "akashml":
        raise ValueError("Phase 6 hybrid route must be GPT-OSS 20B via AkashML")
    if llm.get("allow_fallbacks") is not False:
        raise ValueError("Phase 6 provider fallback must be disabled")


def _development_rows(root: Path, config: Mapping[str, Any]) -> list[dict[str, str]]:
    rows, _, _ = selected_rows(root, config)
    return rows


def _resolved_config(args: argparse.Namespace, config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "arguments": {
            "run_id": args.run_id,
            "mode": args.mode,
            "limit": args.limit,
            "generator": args.generator,
            "dry_run": args.dry_run,
            "resume": args.resume,
            "confirm_api_spend": args.confirm_api_spend,
        },
        "experiment": dict(config),
    }


def _manifest(
    root: Path,
    args: argparse.Namespace,
    config_path: Path,
    config: Mapping[str, Any],
    selected_ids: Sequence[str],
) -> dict[str, Any]:
    dataset = cast(Mapping[str, Any], config["dataset"])
    selected_split, holdout_split = split_paths(config)
    development_path = root / selected_split
    test_path = root / holdout_split
    scope = analysis_scope(config)
    preparation = root / str(dataset["source_preparation_manifest"])
    model_config_path = root / str(cast(Mapping[str, Any], config["llm"])["model_config"])
    model = _mapping(model_config_path)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "phase": 6,
        "protocol_version": str(config["protocol_version"]),
        "experiment_id": str(config["experiment_id"]),
        "run_id": args.run_id,
        "mode": args.mode,
        "analysis_scope": scope,
        "generator": args.generator,
        "created_at": utc_now(),
        "git": collect_git(root),
        "dataset": {
            "id": str(dataset["id"]),
            "analysis_manifest": str(dataset["analysis_manifest"]),
            "analysis_manifest_sha256": sha256_file(root / str(dataset["analysis_manifest"])),
            "split": selected_split,
            "split_sha256": sha256_file(development_path),
            "holdout_split": holdout_split,
            "holdout_split_sha256": sha256_file(test_path),
            "locked_test_sha256": sha256_file(test_path) if scope == "development" else None,
            "source_preparation_sha256": sha256_file(preparation)
            if preparation.is_file()
            else None,
        },
        "selected_project_count": len(selected_ids),
        "selected_project_ids": list(selected_ids),
        "data_access": f"opaque {scope} IDs and vulnerable Java source only; no labels",
        "top_k": int(cast(Mapping[str, Any], config["generator"])["top_k"]),
        "pattern_version": PATTERN_VERSION,
        "ranking_version": RANKING_VERSION,
        "experiment_config": {
            "path": config_path.relative_to(root).as_posix(),
            "sha256": sha256_file(config_path),
        },
        "implementation_sha256": {
            relative: sha256_file(root / relative)
            for relative in (
                "src/hypotheses/runner.py",
                "src/hypotheses/signals.py",
                "src/llm/prompts/phase6.py",
                "src/llm/providers/openrouter.py",
            )
        },
    }
    if args.generator == "hybrid":
        manifest["prompt"] = {"version": PROMPT_VERSION, "sha256": prompt_sha256()}
        manifest["model"] = {
            "requested_model": model["model_id"],
            "returned_models": [],
            "provider_route": model["provider_route"],
            "routing": model["routing"],
            "reasoning_effort": model["reasoning_effort"],
        }
    machine = effective_env(root / ".env")
    redacted = cast(dict[str, Any], redact_secrets(manifest))
    assert_secret_free(redacted, machine)
    return redacted


def _fit_rerank_candidates(
    candidates: Sequence[Mapping[str, Any]], *, maximum: int, token_budget: int
) -> list[Mapping[str, Any]]:
    selected = list(candidates[:maximum])
    while selected and estimate_tokens(SYSTEM_PROMPT + user_prompt(selected)) > token_budget:
        selected.pop()
    return selected


def _rerank(
    root: Path,
    run_root: Path,
    project_id: str,
    candidates: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int | float]]:
    generator = cast(Mapping[str, Any], config["generator"])
    llm = cast(Mapping[str, Any], config["llm"])
    selected = _fit_rerank_candidates(
        candidates,
        maximum=int(generator["llm_rerank_candidates"]),
        token_budget=int(llm["max_context_tokens_per_call"]),
    )
    if not selected:
        return [], _usage([])
    model_config_path = root / str(llm["model_config"])
    client = OpenRouterClient(
        OpenRouterSettings.load(root, model_config_path),
        run_root / "llm_calls.jsonl",
        {"phase": 6, "project_id": project_id, "operation": "hypothesis_rerank"},
    )
    candidate_ids = [str(item["hypothesis_id"]) for item in selected]
    response = client.complete(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt(selected)},
        ],
        expect_json=True,
        max_tokens=int(llm["max_output_tokens_per_call"]),
        response_schema=ranking_schema(candidate_ids),
        response_schema_name="phase6_hypothesis_ranking",
    )
    ranked_ids = parse_ranking(response, candidate_ids)
    by_id = {str(item["hypothesis_id"]): item for item in selected}
    reranked: list[dict[str, Any]] = []
    for rank, hypothesis_id in enumerate(ranked_ids, start=1):
        item = dict(by_id[hypothesis_id])
        item["rank"] = rank
        item["generator"] = "static_rules+llm_rerank"
        item["provenance"] = [
            *cast(list[dict[str, Any]], item["provenance"]),
            {
                "kind": "llm_rerank",
                "prompt_version": PROMPT_VERSION,
                "prompt_sha256": prompt_sha256(),
                "model": "openai/gpt-oss-20b",
                "provider_route": "akashml",
            },
        ]
        reranked.append(item)
    records = [
        row
        for row in read_jsonl(run_root / "llm_calls.jsonl")
        if row.get("project_id") == project_id
    ]
    usage = _usage(records)
    if int(usage["calls"]) > int(llm["max_calls_per_project"]):
        raise RuntimeError("Phase 6 per-project call budget exceeded")
    if int(usage["input_tokens"]) > int(llm["max_total_input_tokens_per_project"]):
        raise RuntimeError("Phase 6 per-project input-token budget exceeded")
    return reranked, usage


def _output_paths(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    parent = output_root / args.generator
    final = parent / args.run_id
    work = parent / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 6 run already exists: {final}")
    if args.resume:
        if not work.is_dir():
            raise FileNotFoundError(f"no Phase 6 in-progress run to resume: {work}")
    elif work.exists():
        raise FileExistsError(f"in-progress run exists; use --resume: {work}")
    else:
        work.mkdir(parents=True)
    return work, final


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else root / args.config
    config = _mapping(config_path)
    _validate_config(config)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid Phase 6 run ID")
    if args.mode == "full" and args.limit is not None:
        raise ValueError("--limit is forbidden in full mode")
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be positive")
    if args.generator == "hybrid" and not args.dry_run and not args.confirm_api_spend:
        raise ValueError("hybrid Phase 6 requires --confirm-api-spend")
    development = _development_rows(root, config)
    selected = development[: args.limit] if args.mode == "pilot" and args.limit else development
    selected_ids = [row["project_id"] for row in selected]
    work, final = _output_paths(root, args)
    resolved = cast(dict[str, Any], redact_secrets(_resolved_config(args, config)))
    assert_secret_free(resolved, effective_env(root / ".env"))
    if not args.resume:
        (work / "config.resolved.yaml").write_text(
            yaml.safe_dump(resolved, sort_keys=True), encoding="utf-8", newline="\n"
        )
        atomic_json(
            work / "manifest.json", _manifest(root, args, config_path, config, selected_ids)
        )
        atomic_json(work / "environment.json", collect_environment(root))
        _write_text(work / "command.txt", shlex.join(sys.argv) + "\n")
        _write_text(work / "stdout.log", "")
        _write_text(work / "stderr.log", "")
        _write_text(work / "llm_calls.jsonl", "")
        statuses = [
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": "PENDING",
                "reason": f"selected {analysis_scope(config)} project waiting for analysis",
                "updated_at": utc_now(),
            }
            for project_id in selected_ids
        ]
        _save_statuses(work, statuses)
        atomic_jsonl(work / "signals.jsonl", [])
        atomic_jsonl(work / "candidates.jsonl", [])
        atomic_jsonl(work / "hypotheses.jsonl", [])
        _write_resources(work / "resource_usage.csv", [])
    else:
        statuses = read_jsonl(work / "project_status.jsonl")
        manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("selected_project_ids") != selected_ids:
            raise ValueError("resume selection differs from the in-progress manifest")
        if sha256_file(config_path) != manifest["experiment_config"]["sha256"]:
            raise ValueError("resume config differs from the in-progress manifest")
    if args.dry_run:
        atomic_json(
            work / "dry_run_plan.json",
            {
                "schema_version": 1,
                "network_called": False,
                "generator": args.generator,
                "selected_projects": len(selected_ids),
                "split": analysis_scope(config),
            },
        )
        _write_text(work / "STATUS", "DRY_RUN\n")
        write_checksums(work)
        os.replace(work, final)
        print(f"Phase 6 dry-run created without network access: {final.relative_to(root)}")
        return 0
    dataset = cast(Mapping[str, Any], config["dataset"])
    generator = cast(Mapping[str, Any], config["generator"])
    source_base = root / str(dataset["source_root"])
    preparation = root / str(dataset["source_preparation_manifest"])
    if not preparation.is_file():
        raise FileNotFoundError("run scripts/tools/prepare_phase6_sources.sh first")
    signals_all = read_jsonl(work / "signals.jsonl")
    candidates_all = read_jsonl(work / "candidates.jsonl")
    hypotheses_all = read_jsonl(work / "hypotheses.jsonl")
    resources: list[dict[str, str]] = []
    resource_path = work / "resource_usage.csv"
    if resource_path.is_file():
        with resource_path.open(encoding="utf-8", newline="") as handle:
            resources = [dict(row) for row in csv.DictReader(handle)]
    status_by_id = {str(row["project_id"]): row for row in statuses}
    for position, row in enumerate(selected, start=1):
        project_id = row["project_id"]
        status = status_by_id[project_id]
        if status.get("status") in FINAL_PROJECT_STATUSES:
            continue
        started = time.monotonic()
        usage = _usage([])
        signals_all = [item for item in signals_all if item.get("project_id") != project_id]
        candidates_all = [item for item in candidates_all if item.get("project_id") != project_id]
        hypotheses_all = [item for item in hypotheses_all if item.get("project_id") != project_id]
        try:
            source_root = source_base / project_id
            if not source_root.is_dir():
                raise FileNotFoundError(f"opaque Phase 6 source is missing: {project_id}")
            scanned_signals = scan_project(
                source_root,
                project_id=project_id,
                max_file_bytes=int(generator["max_file_bytes"]),
            )
            project_candidates = generate_candidates(
                scanned_signals,
                project_id=project_id,
                source_window_lines=int(generator["source_window_lines"]),
                sanitizer_window_lines=int(generator["sanitizer_window_lines"]),
                max_candidates=int(generator["max_static_candidates"]),
            )
            referenced_signal_ids = {
                str(entry["signal_id"])
                for candidate in project_candidates
                for entry in candidate["provenance"]
                if entry.get("kind") == "source_signal"
            }
            project_signals = [
                signal
                for signal in scanned_signals
                if str(signal["signal_id"]) in referenced_signal_ids
            ]
            if args.generator == "hybrid":
                reranked, usage = _rerank(root, work, project_id, project_candidates, config)
                project_hypotheses = select_top_k(reranked, int(generator["top_k"]))
            else:
                project_hypotheses = select_top_k(project_candidates, int(generator["top_k"]))
            signals_all.extend(project_signals)
            candidates_all.extend(project_candidates)
            hypotheses_all.extend(project_hypotheses)
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "zero-hint hypothesis generation completed",
                    "signal_count": len(project_signals),
                    "raw_signal_count": len(scanned_signals),
                    "candidate_count": len(project_candidates),
                    "hypothesis_count": len(project_hypotheses),
                    "updated_at": utc_now(),
                }
            )
        except Exception as error:  # every selected project receives a final status
            usage = _usage(
                [
                    item
                    for item in read_jsonl(work / "llm_calls.jsonl")
                    if item.get("project_id") == project_id
                ]
            )
            status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": f"{type(error).__name__}: {str(error)[:500]}",
                    "updated_at": utc_now(),
                }
            )
            with (work / "stderr.log").open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(
                        {"project_id": project_id, "error_type": type(error).__name__},
                        sort_keys=True,
                    )
                    + "\n"
                )
        resources = [item for item in resources if item["project_id"] != project_id]
        resources.append(_resource_row(project_id, time.monotonic() - started, usage))
        atomic_jsonl(work / "signals.jsonl", signals_all)
        atomic_jsonl(work / "candidates.jsonl", candidates_all)
        atomic_jsonl(work / "hypotheses.jsonl", hypotheses_all)
        _write_resources(resource_path, resources)
        _save_statuses(work, statuses)
        print(f"[{position}/{len(selected)}] {project_id}: {status['status']}", flush=True)
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    if args.generator == "hybrid":
        successful_calls = [
            row for row in read_jsonl(work / "llm_calls.jsonl") if row.get("status") == "SUCCESS"
        ]
        manifest["model"]["returned_models"] = sorted(
            {str(row["returned_model"]) for row in successful_calls}
        )
        manifest["openrouter_request_ids"] = [
            str(row["request_id"]) for row in successful_calls if row.get("request_id")
        ]
        atomic_json(work / "manifest.json", manifest)
    failures = [row for row in statuses if row.get("status") != "SUCCESS"]
    _write_text(work / "STATUS", "FAILED\n" if failures else "SUCCESS\n")
    write_checksums(work)
    os.replace(work, final)
    from src.hypotheses.validate import validate

    print(validate(final, repo_root=root, require_metrics=False))
    return 1 if failures else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase6_hypotheses.yaml")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--generator", choices=("static", "hybrid"), default="static")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("results/hypotheses"))
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
