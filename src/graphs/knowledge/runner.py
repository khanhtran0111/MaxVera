"""Run the offline, global Phase 8 Security Knowledge Graph builder."""

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
from src.graphs.knowledge.builder import build_security_kg
from src.graphs.knowledge.model import BUILDER_VERSION, EDGE_KINDS, NODE_KINDS
from src.graphs.knowledge.prepare import validate_source_bundle
from src.reproduction.common import atomic_json, atomic_jsonl, write_checksums

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _validate_config(config: Mapping[str, Any]) -> None:
    if config.get("status") != "frozen_phase_8_development":
        raise ValueError("Phase 8 experiment config is not frozen for development")
    if config.get("protocol_version") != "1.5.0":
        raise ValueError("Phase 8 requires protocol 1.5.0")
    schema = config.get("schema")
    if not isinstance(schema, Mapping) or schema.get("version") != BUILDER_VERSION:
        raise ValueError("Phase 8 builder/schema version mismatch")
    if set(schema.get("node_kinds", [])) != NODE_KINDS:
        raise ValueError("Phase 8 node-kind schema mismatch")
    if set(schema.get("edge_kinds", [])) != EDGE_KINDS:
        raise ValueError("Phase 8 edge-kind schema mismatch")
    scope = config.get("scope")
    if not isinstance(scope, Mapping) or scope.get("graph_scope") != "global":
        raise ValueError("Phase 8 must build a global knowledge graph")
    if scope.get("root_cwes") != ["CWE-22", "CWE-78", "CWE-79", "CWE-94"]:
        raise ValueError("Phase 8 root CWE scope changed without a protocol decision")
    execution = config.get("execution")
    if not isinstance(execution, Mapping) or execution.get("network_during_build") is not False:
        raise ValueError("Phase 8 analysis build must be offline")
    if int(execution.get("llm_calls", -1)) != 0:
        raise ValueError("Phase 8 deterministic builder must make zero LLM calls")


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def dependency_status(root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    locks = cast(Mapping[str, Any], config["development_dependencies"])
    phase6 = cast(Mapping[str, Any], locks["phase6"])
    phase6_root = root / str(phase6["run_root"])
    phase6_manifest = _json(phase6_root / "manifest.json")
    phase6_actual = {
        "run_id": str(phase6_manifest.get("run_id")),
        "manifest_sha256": sha256_file(phase6_root / "manifest.json"),
        "metrics_aggregate_sha256": sha256_file(phase6_root / "metrics_aggregate.json"),
    }
    phase6_expected = {
        "run_id": str(phase6["run_id"]),
        "manifest_sha256": str(phase6["manifest_sha256"]),
        "metrics_aggregate_sha256": str(phase6["metrics_aggregate_sha256"]),
    }
    if phase6_actual != phase6_expected or phase6_manifest.get("phase") != 6:
        raise ValueError("locked Phase 6 dependency mismatch")

    phase7 = cast(Mapping[str, Any], locks["phase7"])
    phase7_root = root / str(phase7["run_root"])
    phase7_manifest = _json(phase7_root / "manifest.json")
    phase7_actual = {
        "run_id": str(phase7_manifest.get("run_id")),
        "manifest_sha256": sha256_file(phase7_root / "manifest.json"),
        "graph_summary_sha256": sha256_file(phase7_root / "graph_summary.json"),
        "project_status_sha256": sha256_file(phase7_root / "project_status.jsonl"),
        "checksums_index_sha256": sha256_file(phase7_root / "checksums.sha256"),
    }
    phase7_expected = {
        "run_id": str(phase7["run_id"]),
        "manifest_sha256": str(phase7["manifest_sha256"]),
        "graph_summary_sha256": str(phase7["graph_summary_sha256"]),
        "project_status_sha256": str(phase7["project_status_sha256"]),
        "checksums_index_sha256": str(phase7["checksums_index_sha256"]),
    }
    if phase7_actual != phase7_expected or phase7_manifest.get("phase") != 7:
        raise ValueError("locked Phase 7 dependency mismatch")
    summary = _json(phase7_root / "graph_summary.json")
    if int(summary.get("projects", -1)) != 96 or int(summary.get("analysis_successes", -1)) != 81:
        raise ValueError("locked Phase 7 development coverage mismatch")
    return {
        "schema_version": 1,
        "data_access": "checksums and aggregate manifests only; no project labels or advisories",
        "phase6": phase6_actual,
        "phase7": {**phase7_actual, "analysis_successes": 81, "analysis_failures": 15},
    }


def _output_paths(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    final = output_root / args.run_id
    work = output_root / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 8 run already exists: {final}")
    if work.exists():
        raise FileExistsError(f"in-progress Phase 8 run already exists: {work}")
    work.mkdir(parents=True)
    return work, final


def _manifest(
    *,
    root: Path,
    args: argparse.Namespace,
    config_path: Path,
    source_config_path: Path,
    source_manifest: Mapping[str, Any],
    dependencies: Mapping[str, Any],
) -> dict[str, Any]:
    implementation = (
        "src/graphs/knowledge/model.py",
        "src/graphs/knowledge/prepare.py",
        "src/graphs/knowledge/builder.py",
        "src/graphs/knowledge/runner.py",
        "src/graphs/knowledge/validate.py",
    )
    return {
        "schema_version": 1,
        "phase": 8,
        "protocol_version": "1.5.0",
        "experiment_id": "phase8_security_knowledge_graph",
        "run_id": args.run_id,
        "mode": args.mode,
        "created_at": utc_now(),
        "git": collect_git(root),
        "builder_version": BUILDER_VERSION,
        "graph_scope": "global",
        "root_cwes": ["CWE-22", "CWE-78", "CWE-79", "CWE-94"],
        "data_access": "pinned public knowledge; locked dependency checksums only",
        "network_called": False,
        "llm_calls": 0,
        "inferred_layer_policy": "separate and empty for canonical Phase 8",
        "development_dependencies": dict(dependencies),
        "source_bundle": {
            "source_bundle_id": source_manifest["source_bundle_id"],
            "source_manifest_sha256": sha256_file(
                root / str(_mapping(source_config_path)["raw_root"]) / "source_manifest.json"
            ),
            "source_config": source_config_path.relative_to(root).as_posix(),
            "source_config_sha256": sha256_file(source_config_path),
        },
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
        raise ValueError("invalid Phase 8 run ID")
    source_config_path = root / str(config["source_config"])
    source_config = _mapping(source_config_path)
    source_manifest = validate_source_bundle(root, source_config_path, source_config)
    dependencies = dependency_status(root, config)
    work, final = _output_paths(root, args)
    arguments = {
        key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()
    }
    (work / "config.resolved.yaml").write_text(
        yaml.safe_dump(
            {"arguments": arguments, "experiment": config, "sources": source_config},
            sort_keys=True,
        ),
        encoding="utf-8",
        newline="\n",
    )
    atomic_json(
        work / "manifest.json",
        _manifest(
            root=root,
            args=args,
            config_path=config_path,
            source_config_path=source_config_path,
            source_manifest=source_manifest,
            dependencies=dependencies,
        ),
    )
    atomic_json(work / "environment.json", collect_environment(root))
    atomic_json(work / "dependency_status.json", dependencies)
    atomic_json(work / "source_manifest.json", source_manifest)
    (work / "command.txt").write_text(shlex.join(sys.argv) + "\n", encoding="utf-8")
    (work / "stdout.log").write_text("", encoding="utf-8")
    (work / "stderr.log").write_text("", encoding="utf-8")
    if args.dry_run:
        atomic_json(
            work / "dry_run_plan.json",
            {
                "schema_version": 1,
                "network_called": False,
                "llm_calls": 0,
                "root_cwes": cast(Mapping[str, Any], config["scope"])["root_cwes"],
                "source_bundle_validated": True,
                "phase6_phase7_locks_validated": True,
            },
        )
        (work / "STATUS").write_text("DRY_RUN\n", encoding="utf-8")
        write_checksums(work)
        os.replace(work, final)
        print(f"Phase 8 dry-run created: {final.relative_to(root)}")
        return 0

    started = time.monotonic()
    raw_root = root / str(source_config["raw_root"])
    graph = build_security_kg(
        raw_root=raw_root, source_config=source_config, experiment=config
    )
    atomic_jsonl(work / "deterministic/nodes.jsonl", graph["nodes"])
    atomic_jsonl(work / "deterministic/edges.jsonl", graph["edges"])
    atomic_jsonl(work / "llm_inferred/nodes.jsonl", [])
    atomic_jsonl(work / "llm_inferred/edges.jsonl", [])
    atomic_json(work / "audit_sample.json", cast(Mapping[str, Any], graph["audit"]))
    atomic_json(work / "kg_summary.json", cast(Mapping[str, Any], graph["summary"]))
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
    if cast(Mapping[str, Any], graph["audit"])["status"] != "PASS":
        raise ValueError("Phase 8 per-CWE audit gate failed")
    (work / "STATUS").write_text("SUCCESS\n", encoding="utf-8")
    write_checksums(work)
    os.replace(work, final)
    from src.graphs.knowledge.validate import validate

    print(validate(final, repo_root=root))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase8_security_kg.yaml")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("results/graphs/knowledge"))
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
