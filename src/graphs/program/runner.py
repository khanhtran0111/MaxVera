"""Run the development-only Phase 7 CodeQL program-graph extractor."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.graphs.program.model import EXTRACTOR_VERSION, graph_digest, normalize_graph
from src.hypotheses.validate import validate as validate_phase6
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FINAL_STATUSES = {"SUCCESS", "ANALYSIS_FAILED"}


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _codeql_binary(root: Path) -> Path:
    configured = effective_env(root / ".env").get("MAXVERA_CODEQL_HOME", "")
    if not configured:
        raise ValueError("MAXVERA_CODEQL_HOME is not configured")
    home = Path(configured).expanduser().resolve()
    candidates = (home, home / "codeql", home / "bin/codeql")
    binary = next((candidate for candidate in candidates if candidate.is_file()), None)
    if binary is None:
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return binary


def _codeql_version(binary: Path) -> str:
    process = subprocess.run(
        [str(binary), "version", "--format=terse"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if process.returncode != 0:
        raise RuntimeError("could not read the configured CodeQL version")
    return process.stdout.strip()


def _validate_config(config: Mapping[str, Any]) -> None:
    if config.get("status") != "frozen_phase_7_development":
        raise ValueError("Phase 7 experiment config is not frozen for development")
    if config.get("dataset", {}).get("id") != "D_extended":
        raise ValueError("Phase 7 requires D_extended")
    phase6 = config.get("phase6_lock", {})
    if not isinstance(phase6, Mapping) or phase6.get("ranking_version") != (
        "phase6-family-balanced-v2"
    ):
        raise ValueError("Phase 7 requires the locked Phase 6 v2 ranking")
    if int(phase6.get("top_k", 0)) != 10:
        raise ValueError("Phase 7 requires the locked Phase 6 Top-k=10")
    extractor = config.get("extractor", {})
    if not isinstance(extractor, Mapping) or extractor.get("version") != EXTRACTOR_VERSION:
        raise ValueError("Phase 7 extractor version mismatch")


def _development_rows(root: Path, config: Mapping[str, Any]) -> list[dict[str, str]]:
    dataset = cast(Mapping[str, Any], config["dataset"])
    analysis_rows = read_csv(root / str(dataset["analysis_manifest"]))
    allowed_columns = {
        "project_id",
        "source_dir",
        "source_required",
        "jdk_version",
        "maven_version",
        "gradle_version",
        "use_gradlew",
    }
    if any(set(row) - allowed_columns for row in analysis_rows):
        raise ValueError("Phase 7 analysis manifest contains protected columns")
    development_ids = [
        row["project_id"] for row in read_csv(root / str(dataset["development_split"]))
    ]
    locked_ids = {
        row["project_id"] for row in read_csv(root / str(dataset["forbidden_test_split"]))
    }
    if set(development_ids) & locked_ids:
        raise ValueError("Phase 7 development and locked-test splits overlap")
    by_id = {row["project_id"]: row for row in analysis_rows}
    if set(development_ids) - set(by_id):
        raise ValueError("Phase 7 development split contains unknown projects")
    return [by_id[project_id] for project_id in development_ids]


def _select_rows(
    development: Sequence[dict[str, str]], args: argparse.Namespace
) -> list[dict[str, str]]:
    if args.mode == "full":
        if args.limit is not None or args.project_id is not None:
            raise ValueError("--limit/--project-id are forbidden in full mode")
        return list(development)
    if args.project_id is not None:
        selected = [row for row in development if row["project_id"] == args.project_id]
        if not selected:
            raise ValueError("--project-id is not in the development split")
        return selected
    limit = args.limit if args.limit is not None else 1
    if limit < 1:
        raise ValueError("--limit must be positive")
    return list(development[:limit])


def _phase6_dependency(root: Path, config: Mapping[str, Any]) -> dict[str, str]:
    phase6 = cast(Mapping[str, Any], config["phase6_lock"])
    run_root = root / str(phase6["run_root"])
    validate_phase6(run_root, repo_root=root, require_metrics=True)
    manifest_sha = sha256_file(run_root / "manifest.json")
    metrics_sha = sha256_file(run_root / "metrics_aggregate.json")
    if (
        manifest_sha != phase6["manifest_sha256"]
        or metrics_sha != phase6["metrics_aggregate_sha256"]
    ):
        raise ValueError("locked Phase 6 dependency checksum mismatch")
    return {
        "run_id": str(phase6["run_id"]),
        "manifest_sha256": manifest_sha,
        "metrics_aggregate_sha256": metrics_sha,
    }


def _run_query(
    *,
    codeql: Path,
    database: Path,
    query: Path,
    output_name: str,
    temporary_root: Path,
    log_path: Path,
    threads: int,
    ram_mb: int,
    timeout: int,
    seed_files: set[str],
) -> list[dict[str, str]]:
    bqrs = temporary_root / f"{output_name}.bqrs"
    decoded = temporary_root / f"{output_name}.csv"
    command = [
        str(codeql),
        "query",
        "run",
        f"--threads={threads}",
        f"--ram={ram_mb}",
        f"--database={database}",
        f"--output={bqrs}",
        str(query),
    ]
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        f"command={shlex.join(command)}\nexit_code={process.returncode}\n"
        f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}",
        encoding="utf-8",
        newline="\n",
    )
    if process.returncode != 0:
        raise RuntimeError(f"CodeQL {output_name} query failed with exit {process.returncode}")
    decode = subprocess.run(
        [str(codeql), "bqrs", "decode", "--format=csv", f"--output={decoded}", str(bqrs)],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if decode.returncode != 0:
        raise RuntimeError(
            f"CodeQL {output_name} result decode failed with exit {decode.returncode}"
        )
    with decoded.open(encoding="utf-8", newline="") as handle:
        rows: list[dict[str, str]] = []
        for row in csv.DictReader(handle):
            if output_name == "nodes":
                retain = row.get("node_file") in seed_files
            else:
                retain = (
                    row.get("source_file") in seed_files or row.get("target_file") in seed_files
                )
            if retain:
                rows.append(dict(row))
        return rows


def _write_resources(path: Path, rows: Sequence[Mapping[str, str]]) -> None:
    fields = ("project_id", "wall_seconds", "peak_rss_kb", "nodes", "edges")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _save_statuses(work: Path, statuses: Sequence[Mapping[str, Any]]) -> None:
    atomic_jsonl(work / "project_status.jsonl", statuses)
    counts = Counter(str(row["status"]) for row in statuses)
    atomic_json(
        work / "status_summary.json",
        {"schema_version": 1, "total": len(statuses), "counts": dict(sorted(counts.items()))},
    )


def _output_paths(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    final = output_root / args.run_id
    work = output_root / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 7 run already exists: {final}")
    if args.resume:
        if not work.is_dir():
            raise FileNotFoundError(f"no Phase 7 in-progress run to resume: {work}")
    elif work.exists():
        raise FileExistsError(f"in-progress Phase 7 run exists; use --resume: {work}")
    else:
        work.mkdir(parents=True)
    return work, final


def _manifest(
    root: Path,
    args: argparse.Namespace,
    config_path: Path,
    config: Mapping[str, Any],
    selected_ids: Sequence[str],
    codeql: Path,
    phase6: Mapping[str, str],
) -> dict[str, Any]:
    dataset = cast(Mapping[str, Any], config["dataset"])
    extractor = cast(Mapping[str, Any], config["extractor"])
    node_query = root / str(extractor["node_query"])
    edge_query = root / str(extractor["edge_query"])
    preparation = root / str(dataset["database_preparation_manifest"])
    build_status = root / str(dataset["database_build_status"])
    return {
        "schema_version": 1,
        "phase": 7,
        "protocol_version": str(config["protocol_version"]),
        "experiment_id": str(config["experiment_id"]),
        "run_id": args.run_id,
        "mode": args.mode,
        "created_at": utc_now(),
        "git": collect_git(root),
        "dataset": {
            "id": str(dataset["id"]),
            "split": str(dataset["development_split"]),
            "split_sha256": sha256_file(root / str(dataset["development_split"])),
            "locked_test_sha256": sha256_file(root / str(dataset["forbidden_test_split"])),
            "database_preparation_sha256": sha256_file(preparation),
            "database_build_status_sha256": sha256_file(build_status)
            if build_status.is_file()
            else None,
        },
        "selected_project_count": len(selected_ids),
        "selected_project_ids": list(selected_ids),
        "data_access": (
            "opaque development IDs, source-backed CodeQL database, locked Phase 6 output"
        ),
        "phase6_dependency": dict(phase6),
        "extractor": {
            "version": EXTRACTOR_VERSION,
            "scope": extractor["scope"],
            "codeql_version": _codeql_version(codeql),
            "java_library_pack": extractor["java_library_pack"],
            "node_query": str(extractor["node_query"]),
            "node_query_sha256": sha256_file(node_query),
            "edge_query": str(extractor["edge_query"]),
            "edge_query_sha256": sha256_file(edge_query),
            "query_library_sha256": sha256_file(node_query.parent / "Phase7Graph.qll"),
            "edge_kinds": list(extractor["edge_kinds"]),
        },
        "experiment_config": {
            "path": config_path.relative_to(root).as_posix(),
            "sha256": sha256_file(config_path),
        },
        "implementation_sha256": {
            relative: sha256_file(root / relative)
            for relative in (
                "src/graphs/program/model.py",
                "src/graphs/program/runner.py",
                "src/graphs/program/query.py",
                "src/graphs/program/validate.py",
            )
        },
    }


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else root / args.config
    config = _mapping(config_path)
    _validate_config(config)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid Phase 7 run ID")
    development = _development_rows(root, config)
    selected = _select_rows(development, args)
    selected_ids = [row["project_id"] for row in selected]
    dataset = cast(Mapping[str, Any], config["dataset"])
    extractor = cast(Mapping[str, Any], config["extractor"])
    preparation = root / str(dataset["database_preparation_manifest"])
    if not preparation.is_file():
        raise FileNotFoundError("run scripts/tools/prepare_phase7_databases.sh first")
    phase6 = _phase6_dependency(root, config)
    codeql = _codeql_binary(root)
    if not _codeql_version(codeql).startswith(str(extractor["codeql_version"])):
        raise ValueError("configured CodeQL does not match the Phase 7 pin")
    work, final = _output_paths(root, args)
    if not args.resume:
        arguments = {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        }
        resolved: dict[str, Any] = {"arguments": arguments, "experiment": dict(config)}
        (work / "config.resolved.yaml").write_text(
            yaml.safe_dump(resolved, sort_keys=True), encoding="utf-8", newline="\n"
        )
        atomic_json(
            work / "manifest.json",
            _manifest(root, args, config_path, config, selected_ids, codeql, phase6),
        )
        atomic_json(work / "environment.json", collect_environment(root))
        (work / "command.txt").write_text(
            shlex.join(sys.argv) + "\n", encoding="utf-8", newline="\n"
        )
        (work / "stdout.log").write_text("", encoding="utf-8")
        (work / "stderr.log").write_text("", encoding="utf-8")
        statuses = [
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": "PENDING",
                "reason": "selected development project waiting for graph extraction",
                "updated_at": utc_now(),
            }
            for project_id in selected_ids
        ]
        _save_statuses(work, statuses)
        _write_resources(work / "resource_usage.csv", [])
    else:
        statuses = read_jsonl(work / "project_status.jsonl")
        manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("selected_project_ids") != selected_ids:
            raise ValueError("resume selection differs from the Phase 7 manifest")
        if manifest.get("experiment_config", {}).get("sha256") != sha256_file(config_path):
            raise ValueError("resume config differs from the Phase 7 manifest")
        recorded_extractor = manifest.get("extractor", {})
        if not isinstance(recorded_extractor, Mapping) or (
            recorded_extractor.get("node_query_sha256")
            != sha256_file(root / str(extractor["node_query"]))
            or recorded_extractor.get("edge_query_sha256")
            != sha256_file(root / str(extractor["edge_query"]))
            or recorded_extractor.get("query_library_sha256")
            != sha256_file((root / str(extractor["node_query"])).parent / "Phase7Graph.qll")
        ):
            raise ValueError("resume query implementation differs from the Phase 7 manifest")
        current_implementation = {
            relative: sha256_file(root / relative)
            for relative in cast(Mapping[str, Any], manifest["implementation_sha256"])
        }
        if manifest.get("implementation_sha256") != current_implementation:
            raise ValueError("resume Python implementation differs from the Phase 7 manifest")
    if args.dry_run:
        atomic_json(
            work / "dry_run_plan.json",
            {
                "schema_version": 1,
                "network_called": False,
                "selected_projects": len(selected_ids),
                "database_available": sum(
                    (root / str(dataset["database_root"]) / project_id).is_dir()
                    for project_id in selected_ids
                ),
            },
        )
        (work / "STATUS").write_text("DRY_RUN\n", encoding="utf-8")
        write_checksums(work)
        os.replace(work, final)
        print(f"Phase 7 dry-run created: {final.relative_to(root)}")
        return 0
    resources: list[dict[str, str]] = []
    resource_path = work / "resource_usage.csv"
    if resource_path.is_file():
        with resource_path.open(encoding="utf-8", newline="") as handle:
            resources = [dict(row) for row in csv.DictReader(handle)]
    status_by_id = {str(row["project_id"]): row for row in statuses}
    database_root = root / str(dataset["database_root"])
    node_query = root / str(extractor["node_query"])
    edge_query = root / str(extractor["edge_query"])
    phase6_run_root = root / str(cast(Mapping[str, Any], config["phase6_lock"])["run_root"])
    seed_files_by_project: dict[str, set[str]] = {}
    for hypothesis in read_jsonl(phase6_run_root / "hypotheses.jsonl"):
        project_id = str(hypothesis["project_id"])
        files = seed_files_by_project.setdefault(project_id, set())
        for location in cast(Sequence[Mapping[str, Any]], hypothesis.get("locations", [])):
            file = location.get("file")
            if isinstance(file, str):
                files.add(file.replace("\\", "/").lstrip("./"))
    for position, row in enumerate(selected, start=1):
        project_id = row["project_id"]
        status = status_by_id[project_id]
        if status.get("status") in FINAL_STATUSES:
            continue
        started = time.monotonic()
        node_count = 0
        edge_count = 0
        project_output = work / "graphs" / project_id
        if project_output.is_dir():
            shutil.rmtree(project_output)
        try:
            database = database_root / project_id
            if not (database / "codeql-database.yml").is_file():
                raise FileNotFoundError("opaque Phase 7 CodeQL database is unavailable")
            source_root = root / str(dataset["source_root"]) / project_id
            if not source_root.is_dir():
                raise FileNotFoundError("opaque Phase 7 source tree is unavailable")
            seed_files = seed_files_by_project.get(project_id, set())
            if not seed_files:
                raise ValueError("locked Phase 6 hypotheses contain no source seed file")
            with tempfile.TemporaryDirectory(prefix=f"phase7-{project_id}-") as temporary:
                temporary_root = Path(temporary)
                node_rows = _run_query(
                    codeql=codeql,
                    database=database,
                    query=node_query,
                    output_name="nodes",
                    temporary_root=temporary_root,
                    log_path=work / "logs" / f"{project_id}_nodes.log",
                    threads=int(extractor["threads"]),
                    ram_mb=int(extractor["ram_mb"]),
                    timeout=int(extractor["timeout_seconds_per_query"]),
                    seed_files=seed_files,
                )
                edge_rows = _run_query(
                    codeql=codeql,
                    database=database,
                    query=edge_query,
                    output_name="edges",
                    temporary_root=temporary_root,
                    log_path=work / "logs" / f"{project_id}_edges.log",
                    threads=int(extractor["threads"]),
                    ram_mb=int(extractor["ram_mb"]),
                    timeout=int(extractor["timeout_seconds_per_query"]),
                    seed_files=seed_files,
                )
            provenance_base = {
                "tool": "CodeQL",
                "tool_version": _codeql_version(codeql),
                "extractor_version": EXTRACTOR_VERSION,
            }
            nodes, edges = normalize_graph(
                project_id,
                node_rows,
                edge_rows,
                node_provenance={
                    **provenance_base,
                    "query": str(extractor["node_query"]),
                    "query_sha256": sha256_file(node_query),
                },
                edge_provenance={
                    **provenance_base,
                    "query": str(extractor["edge_query"]),
                    "query_sha256": sha256_file(edge_query),
                },
            )
            node_count = len(nodes)
            edge_count = len(edges)
            if node_count > int(extractor["max_nodes_per_project"]):
                raise RuntimeError("Phase 7 node cap exceeded")
            if edge_count > int(extractor["max_edges_per_project"]):
                raise RuntimeError("Phase 7 edge cap exceeded")
            if project_output.exists():
                raise FileExistsError("Phase 7 project graph output already exists")
            project_output.mkdir(parents=True)
            atomic_jsonl(project_output / "nodes.jsonl", nodes)
            atomic_jsonl(project_output / "edges.jsonl", edges)
            atomic_json(
                project_output / "graph_summary.json",
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "nodes": node_count,
                    "edges": edge_count,
                    "seed_files": sorted(seed_files),
                    "edge_references_resolved": edge_count,
                    "edge_reference_ratio": 1.0,
                    "edge_kinds": dict(
                        sorted(Counter(str(item["kind"]) for item in edges).items())
                    ),
                    "graph_sha256": graph_digest(nodes, edges),
                },
            )
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "source-backed CodeQL program graph extracted",
                    "nodes": node_count,
                    "edges": edge_count,
                    "seed_file_count": len(seed_files),
                    "graph_sha256": graph_digest(nodes, edges),
                    "updated_at": utc_now(),
                }
            )
        except (KeyError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            if project_output.is_dir():
                shutil.rmtree(project_output)
            status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": f"{type(error).__name__}: {str(error)[:500]}",
                    "updated_at": utc_now(),
                }
            )
        resources = [item for item in resources if item["project_id"] != project_id]
        resources.append(
            {
                "project_id": project_id,
                "wall_seconds": f"{time.monotonic() - started:.3f}",
                "peak_rss_kb": str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
                "nodes": str(node_count),
                "edges": str(edge_count),
            }
        )
        _write_resources(resource_path, resources)
        _save_statuses(work, statuses)
        print(f"[{position}/{len(selected)}] {project_id}: {status['status']}", flush=True)
    successes = [row for row in statuses if row.get("status") == "SUCCESS"]
    failures = len(statuses) - len(successes)
    atomic_json(
        work / "graph_summary.json",
        {
            "schema_version": 1,
            "projects": len(statuses),
            "analysis_successes": len(successes),
            "analysis_failures": failures,
            "nodes": sum(int(str(row.get("nodes", 0))) for row in successes),
            "edges": sum(int(str(row.get("edges", 0))) for row in successes),
            "edge_references_resolved": sum(int(str(row.get("edges", 0))) for row in successes),
            "edge_reference_ratio": 1.0,
        },
    )
    (work / "STATUS").write_text("FAILED\n" if failures else "SUCCESS\n", encoding="utf-8")
    write_checksums(work)
    os.replace(work, final)
    from src.graphs.program.validate import validate

    print(validate(final, repo_root=root))
    return 1 if failures else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase7_program_graph.yaml")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--project-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("results/graphs/program"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
