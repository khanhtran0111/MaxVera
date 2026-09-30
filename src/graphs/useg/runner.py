"""Run the deterministic development-only Phase 9 Evidence Graph/USEG builder."""

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

from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.graphs.evidence.model import EDGE_KINDS, EVIDENCE_NODE_KINDS, USEG_VERSION
from src.graphs.useg.builder import build_useg
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


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


def _validate_config(config: Mapping[str, Any]) -> None:
    scope = str(config.get("analysis_scope", "development"))
    expected_status = (
        "frozen_phase_9_development"
        if scope == "development"
        else "frozen_phase_13_test_analysis"
    )
    if scope not in {"development", "test_locked"} or config.get("status") != expected_status:
        raise ValueError(f"Phase 9 experiment config is not frozen for {scope}")
    if config.get("protocol_version") != "1.6.0":
        raise ValueError("Phase 9 requires protocol 1.6.0")
    if config.get("useg_version") != USEG_VERSION or config.get("analysis_iteration") != 0:
        raise ValueError("Phase 9 USEG version/analysis iteration mismatch")
    schema = config.get("schema")
    if not isinstance(schema, Mapping):
        raise ValueError("Phase 9 schema config is missing")
    if set(schema.get("evidence_node_kinds", [])) != EVIDENCE_NODE_KINDS:
        raise ValueError("Phase 9 evidence node-kind schema mismatch")
    if set(schema.get("edge_kinds", [])) != EDGE_KINDS:
        raise ValueError("Phase 9 edge-kind schema mismatch")
    execution = config.get("execution")
    if not isinstance(execution, Mapping):
        raise ValueError("Phase 9 execution policy is missing")
    if int(execution.get("network_calls", -1)) != 0 or int(
        execution.get("llm_calls", -1)
    ) != 0:
        raise ValueError("Phase 9 iteration 0 must use zero network/LLM calls")


def _actual_checksums(run_root: Path, expected: Mapping[str, Any]) -> dict[str, str]:
    return {
        key: sha256_file(run_root / filename)
        for key, filename in (
            ("manifest_sha256", "manifest.json"),
            ("hypotheses_sha256", "hypotheses.jsonl"),
            ("project_status_sha256", "project_status.jsonl"),
            ("checksums_index_sha256", "checksums.sha256"),
            ("graph_summary_sha256", "graph_summary.json"),
            ("kg_summary_sha256", "kg_summary.json"),
            ("audit_sample_sha256", "audit_sample.json"),
            ("nodes_sha256", "deterministic/nodes.jsonl"),
            ("edges_sha256", "deterministic/edges.jsonl"),
        )
        if key in expected
    }


def dependency_status(root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    locks = cast(Mapping[str, Any], config["development_dependencies"])
    result: dict[str, Any] = {
        "schema_version": 1,
        "data_access": (
            f"canonical {config.get('analysis_scope', 'development')} hypotheses/program "
            "graph/security KG only; no evaluator labels, advisory, or patch content"
        ),
    }
    for phase_number, key in ((6, "phase6"), (7, "phase7"), (8, "phase8")):
        expected = cast(Mapping[str, Any], locks[key])
        run_root = root / str(expected["run_root"])
        manifest = _json(run_root / "manifest.json")
        actual = _actual_checksums(run_root, expected)
        wanted = {name: str(expected[name]) for name in actual}
        if actual != wanted:
            raise ValueError(f"locked Phase {phase_number} dependency checksum mismatch")
        if manifest.get("phase") != phase_number or manifest.get("run_id") != expected["run_id"]:
            raise ValueError(f"locked Phase {phase_number} dependency identity mismatch")
        result[key] = {"run_id": str(expected["run_id"]), **actual}

    phase6_root = root / str(cast(Mapping[str, Any], locks["phase6"])["run_root"])
    phase6_manifest = _json(phase6_root / "manifest.json")
    selected = phase6_manifest.get("selected_project_ids")
    expected_projects = int(cast(Mapping[str, Any], config["coverage"])["expected_full_projects"])
    if (
        not isinstance(selected, list)
        or len(selected) != expected_projects
        or len(set(selected)) != expected_projects
    ):
        raise ValueError("locked Phase 6 project selection does not match configured coverage")
    phase7_root = root / str(cast(Mapping[str, Any], locks["phase7"])["run_root"])
    phase7_statuses = read_jsonl(phase7_root / "project_status.jsonl")
    if {str(row["project_id"]) for row in phase7_statuses} != set(selected):
        raise ValueError("Phase 6/7 development project coverage mismatch")
    successes = sum(row.get("status") == "SUCCESS" for row in phase7_statuses)
    failures = len(phase7_statuses) - successes
    coverage = cast(Mapping[str, Any], config["coverage"])
    if successes != int(coverage["expected_phase7_successes"]) or failures != int(
        coverage["expected_phase7_failures"]
    ):
        raise ValueError("locked Phase 7 success/failure coverage mismatch")
    result["phase7"]["analysis_successes"] = successes
    result["phase7"]["analysis_failures"] = failures
    return result


def _selected_projects(
    root: Path, config: Mapping[str, Any], args: argparse.Namespace
) -> list[str]:
    locks = cast(Mapping[str, Any], config["development_dependencies"])
    phase6_root = root / str(cast(Mapping[str, Any], locks["phase6"])["run_root"])
    manifest = _json(phase6_root / "manifest.json")
    development = [str(value) for value in cast(Sequence[Any], manifest["selected_project_ids"])]
    if args.mode == "full":
        if args.limit is not None or args.project_id is not None:
            raise ValueError("--limit/--project-id are forbidden in full mode")
        return development
    if args.project_id is not None:
        if args.project_id not in development:
            raise ValueError("--project-id is not in the locked analysis selection")
        return [str(args.project_id)]
    phase7_root = root / str(cast(Mapping[str, Any], locks["phase7"])["run_root"])
    success_ids = {
        str(row["project_id"])
        for row in read_jsonl(phase7_root / "project_status.jsonl")
        if row.get("status") == "SUCCESS"
    }
    limit = args.limit if args.limit is not None else 1
    if limit < 1:
        raise ValueError("--limit must be positive")
    return [project_id for project_id in development if project_id in success_ids][:limit]


def _checksum_index(run_root: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        index[relative] = digest
    return index


def _validate_selected_inputs(
    root: Path, config: Mapping[str, Any], selected: Sequence[str]
) -> None:
    locks = cast(Mapping[str, Any], config["development_dependencies"])
    phase7_root = root / str(cast(Mapping[str, Any], locks["phase7"])["run_root"])
    statuses = {
        str(row["project_id"]): str(row["status"])
        for row in read_jsonl(phase7_root / "project_status.jsonl")
    }
    index = _checksum_index(phase7_root)
    for project_id in selected:
        if statuses[project_id] != "SUCCESS":
            continue
        for name in ("nodes.jsonl", "edges.jsonl", "graph_summary.json"):
            relative = f"graphs/{project_id}/{name}"
            if relative not in index or sha256_file(phase7_root / relative) != index[relative]:
                raise ValueError(f"Phase 7 selected graph checksum mismatch: {relative}")


def _output_paths(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    final = output_root / args.run_id
    work = output_root / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 9 run already exists: {final}")
    if work.exists():
        raise FileExistsError(f"in-progress Phase 9 run already exists: {work}")
    work.mkdir(parents=True)
    return work, final


def _manifest(
    *,
    root: Path,
    args: argparse.Namespace,
    config_path: Path,
    config: Mapping[str, Any],
    dependencies: Mapping[str, Any],
    selected: Sequence[str],
) -> dict[str, Any]:
    implementation = (
        "src/graphs/evidence/model.py",
        "src/graphs/useg/builder.py",
        "src/graphs/useg/runner.py",
        "src/graphs/useg/validate.py",
        "src/graphs/useg/query.py",
    )
    return {
        "schema_version": 1,
        "phase": 9,
        "protocol_version": "1.6.0",
        "experiment_id": "phase9_evidence_graph_useg",
        "run_id": args.run_id,
        "mode": args.mode,
        "analysis_scope": str(config.get("analysis_scope", "development")),
        "created_at": utc_now(),
        "git": collect_git(root),
        "useg_version": USEG_VERSION,
        "analysis_iteration": 0,
        "selected_project_ids": list(selected),
        "selected_project_count": len(selected),
        "data_access": "canonical Phase 6/7/8 analysis artifacts only; no labels",
        "network_calls": 0,
        "llm_calls": 0,
        "development_dependencies": dict(dependencies),
        "experiment_config": {
            "path": config_path.relative_to(root).as_posix(),
            "sha256": sha256_file(config_path),
        },
        "implementation_sha256": {
            relative: sha256_file(root / relative) for relative in implementation
        },
    }


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else root / args.config
    config = _mapping(config_path)
    _validate_config(config)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid Phase 9 run ID")
    dependencies = dependency_status(root, config)
    selected = _selected_projects(root, config, args)
    _validate_selected_inputs(root, config, selected)
    work, final = _output_paths(root, args)
    arguments = {
        key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()
    }
    (work / "config.resolved.yaml").write_text(
        yaml.safe_dump({"arguments": arguments, "experiment": config}, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    atomic_json(
        work / "manifest.json",
        _manifest(
            root=root,
            args=args,
            config_path=config_path,
            config=config,
            dependencies=dependencies,
            selected=selected,
        ),
    )
    atomic_json(work / "environment.json", collect_environment(root))
    atomic_json(work / "dependency_status.json", dependencies)
    (work / "command.txt").write_text(shlex.join(sys.argv) + "\n", encoding="utf-8")
    (work / "stdout.log").write_text("", encoding="utf-8")
    (work / "stderr.log").write_text("", encoding="utf-8")
    if args.dry_run:
        atomic_json(
            work / "dry_run_plan.json",
            {
                "schema_version": 1,
                "selected_project_ids": selected,
                "dependencies_validated": True,
                "network_calls": 0,
                "llm_calls": 0,
            },
        )
        (work / "STATUS").write_text("DRY_RUN\n", encoding="utf-8")
        write_checksums(work)
        os.replace(work, final)
        print(f"Phase 9 dry-run created: {final.relative_to(root)}")
        return 0

    started = time.monotonic()
    locks = cast(Mapping[str, Any], config["development_dependencies"])
    graph = build_useg(
        phase6_root=root / str(cast(Mapping[str, Any], locks["phase6"])["run_root"]),
        phase7_root=root / str(cast(Mapping[str, Any], locks["phase7"])["run_root"]),
        phase8_root=root / str(cast(Mapping[str, Any], locks["phase8"])["run_root"]),
        experiment=config,
        config_sha256=sha256_file(config_path),
        selected_project_ids=selected,
    )
    atomic_jsonl(work / "useg/nodes.jsonl", cast(Sequence[Mapping[str, Any]], graph["nodes"]))
    atomic_jsonl(work / "useg/edges.jsonl", cast(Sequence[Mapping[str, Any]], graph["edges"]))
    atomic_jsonl(
        work / "project_status.jsonl", cast(Sequence[Mapping[str, Any]], graph["statuses"])
    )
    atomic_jsonl(
        work / "project_summary.jsonl",
        cast(Sequence[Mapping[str, Any]], graph["project_summaries"]),
    )
    atomic_json(work / "useg_summary.json", cast(Mapping[str, Any], graph["summary"]))
    atomic_json(work / "trace_audit.json", cast(Mapping[str, Any], graph["trace_audit"]))
    atomic_json(
        work / "resource_usage.json",
        {
            "schema_version": 1,
            "wall_seconds": round(time.monotonic() - started, 3),
            "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "network_calls": 0,
            "llm_calls": 0,
        },
    )
    if cast(Mapping[str, Any], graph["trace_audit"])["status"] != "PASS":
        raise ValueError("Phase 9 trace/cycle/round-trip audit failed")
    statuses = cast(Sequence[Mapping[str, Any]], graph["statuses"])
    failed = any(row.get("status") != "SUCCESS" for row in statuses)
    (work / "STATUS").write_text("FAILED\n" if failed else "SUCCESS\n", encoding="utf-8")
    write_checksums(work)
    os.replace(work, final)
    from src.graphs.useg.validate import validate

    print(validate(final, repo_root=root))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase9_useg.yaml")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--project-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("results/graphs/useg"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
