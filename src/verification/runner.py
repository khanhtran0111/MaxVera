"""Run Phase 11 static path verification over frozen Phase 10 specifications."""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.graphs.evidence.model import evidence_node, sort_edges, sort_nodes, useg_edge
from src.reproduction.common import (
    atomic_json,
    atomic_jsonl,
    read_jsonl,
    sarif_paths,
    write_checksums,
)
from src.verification.query import query_id, render_endpoint_query, render_path_query
from src.verification.remap import remap_nodes_for_fixed

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
FINAL_SPEC_STATUSES = {
    "VERIFIED_DIFFERENTIAL",
    "UNVERIFIED_FIXED_NOT_RUN",
    "UNVERIFIED_NO_VULNERABLE_PATH",
    "UNVERIFIED_PERSISTS_FIXED",
    "UNVERIFIED_FIXED_ENDPOINT_MAPPING",
    "UNVERIFIED_FIXED_ENDPOINT_RESOLUTION",
    "UNVERIFIED_UNRESOLVED_SOURCE",
    "UNVERIFIED_UNRESOLVED_SINK",
    "ANALYSIS_FAILED",
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


def _verified_vulnerable_evidence(
    repo_root: Path,
    source_root: Path,
    config_path: Path,
    selected_projects: Sequence[str],
) -> tuple[dict[str, Any], dict[tuple[str, str], Mapping[str, Any]]]:
    """Load vulnerable results from an immutable compatible verification artifact."""

    source_root = source_root.resolve()
    manifest = _json(source_root / "manifest.json")
    if (
        manifest.get("phase") != 11
        or manifest.get("verification_mode") != "differential"
        or manifest.get("mode") != "full"
        or cast(Mapping[str, Any], manifest.get("config", {})).get("sha256")
        != sha256_file(config_path)
    ):
        raise ValueError("reused vulnerable evidence is not a compatible full verification run")
    parent_projects = {
        str(value) for value in cast(Sequence[Any], manifest.get("selected_project_ids", []))
    }
    if not set(selected_projects).issubset(parent_projects):
        raise ValueError("reused vulnerable evidence does not cover selected projects")
    indexed: set[str] = set()
    for line in (source_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = source_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"reused vulnerable evidence checksum mismatch: {relative}")
        indexed.add(relative)
    if "verification_results.jsonl" not in indexed or "manifest.json" not in indexed:
        raise ValueError("reused vulnerable evidence checksum coverage is incomplete")
    results: dict[tuple[str, str], Mapping[str, Any]] = {}
    for result in read_jsonl(source_root / "verification_results.jsonl"):
        vulnerable = result.get("vulnerable")
        if not isinstance(vulnerable, Mapping):
            continue
        key = (str(result.get("project_id")), str(result.get("specification_id")))
        if key in results:
            raise ValueError("reused vulnerable evidence contains duplicate specifications")
        results[key] = vulnerable
    try:
        path = source_root.relative_to(repo_root).as_posix()
    except ValueError:
        path = source_root.as_posix()
    record = {
        "path": path,
        "run_id": manifest["run_id"],
        "checksums_sha256": sha256_file(source_root / "checksums.sha256"),
        "verification_results_sha256": sha256_file(source_root / "verification_results.jsonl"),
    }
    return record, results


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _codeql(root: Path) -> Path:
    configured = effective_env(root / ".env").get("MAXVERA_CODEQL_HOME", "")
    if not configured:
        raise ValueError("MAXVERA_CODEQL_HOME is not configured")
    home = Path(configured).expanduser().resolve()
    binary = next(
        (path for path in (home, home / "codeql", home / "bin/codeql") if path.is_file()), None
    )
    if binary is None:
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return binary


def _run_command(command: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from error
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _validate_config(config: Mapping[str, Any]) -> None:
    test = config.get("analysis_scope") == "test_locked"
    status = "frozen_phase_13_test_verification" if test else "frozen_phase_11_development"
    protocol = "1.9.0" if test else "1.8.0"
    if config.get("status") != status or config.get("protocol_version") != protocol:
        raise ValueError("verification config is not frozen for the requested scope/protocol")
    if test and not config.get("analyzer_snapshot_sha256"):
        raise ValueError("test verification requires a sealed analyzer snapshot")
    policy = config.get("verification")
    if not isinstance(policy, Mapping):
        raise ValueError("Phase 11 verification policy is missing")
    if int(policy.get("max_iterations", 0)) != 1:
        raise ValueError("Phase 11 v1 requires one deterministic verification iteration")
    if int(policy.get("max_paths_per_specification", 0)) < 1:
        raise ValueError("Phase 11 max path budget must be positive")
    serialized = json.dumps(config, sort_keys=True).casefold()
    forbidden = ["advisory_text", "ground_truth_cwe"]
    if not test:
        forbidden.append("test_locked")
    leaked = [word for word in forbidden if word in serialized]
    if leaked:
        raise ValueError(f"Phase 11 analyzer config crosses label firewall: {', '.join(leaked)}")


def _dependency_status(root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    dependencies = cast(Mapping[str, Any], config["development_dependencies"])
    checked: dict[str, Any] = {"schema_version": 1}
    test = config.get("analysis_scope") == "test_locked"
    if test:
        from src.experiments.phase13_snapshot import validate_snapshot

        snapshot = validate_snapshot(
            root, root / str(config["analyzer_snapshot"]),
            str(config["analyzer_snapshot_sha256"]),
        )
        template = _mapping(root / "configs/experiments/phase11_static_verification.yaml")
        for key in ("verification", "execution", "useg_update"):
            if config.get(key) != template[key]:
                raise ValueError(f"test verification changed the frozen policy: {key}")
        for key, name in (("phase9", "phase9"), ("phase10", "B9")):
            lock = cast(Mapping[str, Any], dependencies[key])
            sealed = snapshot["analysis_runs"][name]
            if lock["run_root"] != sealed["run_root"] or lock["run_id"] != sealed["run_id"]:
                raise ValueError(f"test verification dependency is outside the snapshot: {key}")
        checked["analyzer_snapshot_sha256"] = config["analyzer_snapshot_sha256"]
    for key in ("phase9", "phase10"):
        expected = cast(Mapping[str, Any], dependencies[key])
        run_root = root / str(expected["run_root"])
        files = cast(Mapping[str, Any], expected["files"])
        actual = {
            str(name): sha256_file(run_root / str(relative)) for name, relative in files.items()
        }
        wanted = {
            str(name): str(value)
            for name, value in cast(Mapping[str, Any], expected["sha256"]).items()
        }
        if actual != wanted:
            raise ValueError(f"locked {key} dependency checksum mismatch")
        manifest = _json(run_root / "manifest.json")
        if manifest.get("run_id") != expected["run_id"]:
            raise ValueError(f"locked {key} run identity mismatch")
        checked[key] = {"run_id": expected["run_id"], **actual}
    databases = cast(Mapping[str, Any], config["databases"])
    database_files = {
        "preparation_manifest_sha256": str(databases["preparation_manifest"]),
        "build_status_sha256": str(databases["build_status"]),
    }
    database_actual = {
        name: sha256_file(root / relative) for name, relative in database_files.items()
    }
    database_wanted = {name: str(databases[name]) for name in database_files}
    if database_actual != database_wanted:
        raise ValueError("locked vulnerable CodeQL database preparation checksum mismatch")
    if test:
        run_id = str(snapshot["run_id"])
        expected_databases = {
            "vulnerable_root": f"data/interim/phase13_codeql_databases/{run_id}",
            "preparation_manifest": f"data/interim/phase13_database_manifests/{run_id}.json",
            "build_status": f"data/interim/phase13_database_status/{run_id}.jsonl",
            "fixed_root": f"data/interim/phase13_fixed_codeql_databases/{run_id}",
        }
        if any(databases.get(key) != value for key, value in expected_databases.items()):
            raise ValueError("test verification database roots are outside the sealed run")
    checked["vulnerable_databases"] = database_actual
    checked["data_access"] = (
        "sealed Phase 13 test artifacts and opaque CodeQL databases only"
        if test else "frozen Phase 9/10 development artifacts and opaque CodeQL databases only"
    )
    return checked


def _select_projects(statuses: Sequence[Mapping[str, Any]], args: argparse.Namespace) -> list[str]:
    project_ids = [str(row["project_id"]) for row in statuses]
    if args.mode == "full":
        if args.project_id is not None or args.limit is not None:
            raise ValueError("--project-id/--limit are forbidden in full mode")
        if args.verification_mode != "differential":
            raise ValueError("Phase 11 full mode requires --verification-mode differential")
        return project_ids
    if args.project_id:
        if args.project_id not in project_ids:
            raise ValueError("--project-id is not in the frozen Phase 10 run")
        return [str(args.project_id)]
    successful = [str(row["project_id"]) for row in statuses if row.get("status") == "SUCCESS"]
    limit = args.limit if args.limit is not None else 1
    if limit < 1:
        raise ValueError("--limit must be positive")
    return successful[:limit]


def _validate_fixed_manifest(
    manifest: Mapping[str, Any], status_path: Path,
    analysis_scope: str = "development", snapshot_sha256: str | None = None,
) -> None:
    test = analysis_scope == "test_locked"
    if (
        manifest.get("development_only") is not (not test)
        or manifest.get("locked_test_prepared") is not test
        or manifest.get("identity_mapping_persisted") is not False
        or manifest.get("status_sha256") != sha256_file(status_path)
        or (test and (
            not snapshot_sha256 or manifest.get("analyzer_snapshot_sha256") != snapshot_sha256
            or manifest.get("analysis_scope") != "test_locked"
        ))
    ):
        raise ValueError("fixed database preparation violates the opaque scope contract")


def _fixed_database_status(
    fixed_root: Path,
    selected: Sequence[str],
    phase10_statuses: Sequence[Mapping[str, Any]],
    analysis_scope: str = "development", snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    manifest_path = fixed_root / "preparation_manifest.json"
    status_path = fixed_root / "build_status.jsonl"
    if not manifest_path.is_file() or not status_path.is_file():
        raise FileNotFoundError("run the evaluator-only Phase 11 fixed database preparer first")
    manifest = _json(manifest_path)
    _validate_fixed_manifest(manifest, status_path, analysis_scope, snapshot_sha256)
    phase10_by_id = {str(row["project_id"]): row for row in phase10_statuses}
    required = [
        project_id
        for project_id in selected
        if phase10_by_id[project_id].get("status") == "SUCCESS"
    ]
    status_by_id = {str(row["project_id"]): row for row in read_jsonl(status_path)}
    unavailable = [
        project_id
        for project_id in required
        if status_by_id.get(project_id, {}).get("status") != "SUCCESS"
        or not (fixed_root / project_id / "codeql-database.yml").is_file()
    ]
    return {
        "preparation_manifest_sha256": sha256_file(manifest_path),
        "build_status_sha256": sha256_file(status_path),
        "required_databases": len(required),
        "available_databases": len(required) - len(unavailable),
        "unavailable_databases": len(unavailable),
    }


def _prepare_output(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    output_root = args.output_root if args.output_root.is_absolute() else root / args.output_root
    final = output_root / args.run_id
    work = output_root / f".{args.run_id}.inprogress"
    if final.exists():
        raise FileExistsError(f"immutable Phase 11 run already exists: {final}")
    if work.exists() and not args.resume:
        raise FileExistsError(f"unfinished Phase 11 run exists; use --resume: {work}")
    work.mkdir(parents=True, exist_ok=True)
    return work, final


def _run_query(
    *,
    codeql: Path,
    database: Path,
    query: Path,
    bqrs: Path,
    log: Path,
    timeout: int,
    threads: int,
    ram_mb: int,
    attempts_path: Path,
    project_id: str,
    specification_id: str,
    version: str,
    query_kind: str,
) -> None:
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
    started = time.monotonic()
    status = "ANALYSIS_FAILED"
    exit_code: int | None = None
    try:
        result = _run_command(command, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, str) else ""
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        _write_text(
            log,
            f"command={shlex.join(command)}\nstatus=TIMEOUT\nstdout:\n{stdout}\nstderr:\n{stderr}",
        )
        attempts = read_jsonl(attempts_path)
        attempts.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "specification_id": specification_id,
                "version": version,
                "query_kind": query_kind,
                "status": "TIMEOUT",
                "exit_code": None,
                "seconds": round(time.monotonic() - started, 3),
            }
        )
        atomic_jsonl(attempts_path, attempts)
        raise
    exit_code = result.returncode
    status = "SUCCESS" if result.returncode == 0 else "ANALYSIS_FAILED"
    _write_text(
        log,
        f"command={shlex.join(command)}\n"
        f"exit_code={result.returncode}\n"
        f"seconds={time.monotonic() - started:.3f}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
    )
    attempts = read_jsonl(attempts_path)
    attempts.append(
        {
            "schema_version": 1,
            "project_id": project_id,
            "specification_id": specification_id,
            "version": version,
            "query_kind": query_kind,
            "status": status,
            "exit_code": exit_code,
            "seconds": round(time.monotonic() - started, 3),
        }
    )
    atomic_jsonl(attempts_path, attempts)
    if result.returncode != 0:
        raise RuntimeError(f"CodeQL query failed with exit {result.returncode}")


def _endpoint_counts(codeql: Path, bqrs: Path, output: Path) -> dict[str, int]:
    result = _run_command(
        [str(codeql), "bqrs", "decode", "--format=csv", f"--output={output}", "--", str(bqrs)],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"endpoint BQRS decode failed: {result.stderr[-500:]}")
    counts = {"source": 0, "sink": 0}
    with output.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if row and row[0] in counts:
                counts[row[0]] += 1
    return counts


def _interpret_paths(
    codeql: Path, bqrs: Path, sarif: Path, *, specification_id: str, max_paths: int
) -> list[list[tuple[str, int]]]:
    result = _run_command(
        [
            str(codeql),
            "bqrs",
            "interpret",
            "--format=sarifv2.1.0",
            f"--output={sarif}",
            "-t=kind=path-problem",
            f"-t=id={query_id(specification_id)}",
            "-t=name=MaxVera Phase 11 static verification",
            "-t=problem.severity=warning",
            f"--max-paths={max_paths}",
            "--no-sarif-add-file-contents",
            "--no-sarif-add-snippets",
            "--sarif-include-query-help=never",
            "--",
            str(bqrs),
        ],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"path BQRS interpretation failed: {result.stderr[-500:]}")
    unique = sorted(set(tuple(path) for path in sarif_paths(sarif)))
    return [list(path) for path in unique]


def _analyze_version(
    *,
    codeql: Path,
    database: Path,
    work: Path,
    project_id: str,
    version: str,
    specification: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    timeout: int,
    threads: int,
    ram_mb: int,
    max_paths: int,
    query_variant: str | None = None,
) -> dict[str, Any]:
    spec_id = str(specification["specification_id"])
    query_dir = work / "generated_queries" / project_id
    result_dir = work / "query_results" / version / project_id / spec_id
    log_dir = work / "query_logs" / version / project_id
    query_dir.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    variant = f"_{query_variant}" if query_variant else ""
    endpoint_query = query_dir / f"{spec_id}{variant}_endpoints.ql"
    path_query = query_dir / f"{spec_id}{variant}_path.ql"
    if not endpoint_query.exists():
        _write_text(endpoint_query, render_endpoint_query(specification, nodes))
        _write_text(path_query, render_path_query(specification, nodes))
    endpoint_bqrs = result_dir / "endpoints.bqrs"
    path_bqrs = result_dir / "paths.bqrs"
    _run_query(
        codeql=codeql,
        database=database,
        query=endpoint_query,
        bqrs=endpoint_bqrs,
        log=log_dir / f"{spec_id}_endpoints.log",
        timeout=timeout,
        threads=threads,
        ram_mb=ram_mb,
        attempts_path=work / "query_attempts.jsonl",
        project_id=project_id,
        specification_id=spec_id,
        version=version,
        query_kind="endpoint_inventory",
    )
    endpoint_csv = result_dir / "endpoints.csv"
    endpoints = _endpoint_counts(codeql, endpoint_bqrs, endpoint_csv)
    if not endpoints["source"] or not endpoints["sink"]:
        return {
            "database": database.as_posix(),
            "source_endpoints": endpoints["source"],
            "sink_endpoints": endpoints["sink"],
            "paths": [],
            "path_count": 0,
            "sarif": None,
            "sarif_sha256": None,
        }
    _run_query(
        codeql=codeql,
        database=database,
        query=path_query,
        bqrs=path_bqrs,
        log=log_dir / f"{spec_id}_path.log",
        timeout=timeout,
        threads=threads,
        ram_mb=ram_mb,
        attempts_path=work / "query_attempts.jsonl",
        project_id=project_id,
        specification_id=spec_id,
        version=version,
        query_kind="taint_path",
    )
    sarif = result_dir / "paths.sarif"
    paths = _interpret_paths(
        codeql, path_bqrs, sarif, specification_id=spec_id, max_paths=max_paths
    )
    return {
        "database": database.as_posix(),
        "source_endpoints": endpoints["source"],
        "sink_endpoints": endpoints["sink"],
        "paths": [
            [{"file": file_name, "line": line} for file_name, line in path] for path in paths
        ],
        "path_count": len(paths),
        "sarif": sarif.relative_to(work).as_posix(),
        "sarif_sha256": sha256_file(sarif),
    }


def _needs_fixed_verification(vulnerable: Mapping[str, Any]) -> bool:
    return (
        int(vulnerable["source_endpoints"]) > 0
        and int(vulnerable["sink_endpoints"]) > 0
        and int(vulnerable["path_count"]) > 0
    )


def _status(vulnerable: Mapping[str, Any], fixed: Mapping[str, Any] | None) -> tuple[str, str]:
    if int(vulnerable["source_endpoints"]) == 0:
        return (
            "UNVERIFIED_UNRESOLVED_SOURCE",
            "source descriptor did not resolve in vulnerable database",
        )
    if int(vulnerable["sink_endpoints"]) == 0:
        return (
            "UNVERIFIED_UNRESOLVED_SINK",
            "sink descriptor did not resolve in vulnerable database",
        )
    if int(vulnerable["path_count"]) == 0:
        return (
            "UNVERIFIED_NO_VULNERABLE_PATH",
            "endpoints resolved but no vulnerable-version taint path exists",
        )
    if fixed is None:
        return (
            "UNVERIFIED_FIXED_NOT_RUN",
            "vulnerable path exists but fixed-version differential was not run",
        )
    mapping = fixed.get("endpoint_mapping")
    if isinstance(mapping, Mapping) and mapping.get("complete") is not True:
        return (
            "UNVERIFIED_FIXED_ENDPOINT_MAPPING",
            "one or more frozen location descriptors could not be mapped exactly "
            "to unchanged fixed-version source",
        )
    if isinstance(mapping, Mapping) and (
        int(fixed["source_endpoints"]) == 0 or int(fixed["sink_endpoints"]) == 0
    ):
        return (
            "UNVERIFIED_FIXED_ENDPOINT_RESOLUTION",
            "remapped source or sink descriptor did not resolve in the fixed database",
        )
    if int(fixed["path_count"]) > 0:
        return (
            "UNVERIFIED_PERSISTS_FIXED",
            "the same specification still has a path in the fixed database",
        )
    return (
        "VERIFIED_DIFFERENTIAL",
        "vulnerable path exists and the same specification has no fixed-version path",
    )


def _id(prefix: str, value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:24]}"


def _useg_delta(
    *, result: Mapping[str, Any], hypothesis_node_id: str, run_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    project_id = str(result["project_id"])
    spec_id = str(result["specification_id"])
    provenance = [
        {
            "source_phase": 11,
            "source_run_id": run_id,
            "producer": str(result["verification_version"]),
            "artifact": "verification_results.jsonl",
            "record_id": spec_id,
        }
    ]
    verification = evidence_node(
        kind="VERIFICATION_RESULT",
        project_id=project_id,
        identity=spec_id,
        properties={
            "specification_id": spec_id,
            "candidate_cwe": result["candidate_cwe"],
            "status": result["status"],
            "reason": result["reason"],
            "verification_mode": result["verification_mode"],
        },
        confidence_components=[],
        provenance=provenance,
        analysis_iteration=1,
    )
    nodes = [verification]
    edges: list[dict[str, Any]] = []
    vulnerable = cast(Mapping[str, Any], result["vulnerable"])
    if cast(Sequence[Any], vulnerable["paths"]):
        edges.append(
            useg_edge(
                kind="VERIFIED_BY",
                source_id=hypothesis_node_id,
                target_id=str(verification["node_id"]),
                project_id=project_id,
                properties={"specification_id": spec_id, "status": result["status"]},
                provenance=provenance,
                analysis_iteration=1,
            )
        )
    for index, path in enumerate(cast(Sequence[Any], vulnerable["paths"])):
        path_identity = _id("path", {"specification_id": spec_id, "path": path})
        path_node = evidence_node(
            kind="TAINT_PATH",
            project_id=project_id,
            identity=path_identity,
            properties={"specification_id": spec_id, "version": "vulnerable", "path": path},
            confidence_components=[],
            provenance=provenance,
            analysis_iteration=1,
        )
        nodes.append(path_node)
        edges.append(
            useg_edge(
                kind="SUPPORTS",
                source_id=str(path_node["node_id"]),
                target_id=hypothesis_node_id,
                project_id=project_id,
                properties={"specification_id": spec_id, "path_index": index},
                provenance=provenance,
                analysis_iteration=1,
            )
        )
    if not cast(Sequence[Any], vulnerable["paths"]):
        edges.append(
            useg_edge(
                kind="CONTRADICTS",
                source_id=str(verification["node_id"]),
                target_id=hypothesis_node_id,
                project_id=project_id,
                properties={"specification_id": spec_id, "negative_evidence": result["status"]},
                provenance=provenance,
                analysis_iteration=1,
            )
        )
    return nodes, edges


def run(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("invalid Phase 11 run ID")
    config_path = args.config if args.config.is_absolute() else root / args.config
    config = _mapping(config_path)
    _validate_config(config)
    test = config.get("analysis_scope") == "test_locked"
    role = os.environ.get("MAXVERA_DATA_ROLE")
    if test and role != "evaluator":
        raise RuntimeError("sealed test verification requires MAXVERA_DATA_ROLE=evaluator")
    if not test and role == "evaluator":
        raise RuntimeError("refusing development analyzer run while MAXVERA_DATA_ROLE=evaluator")
    dependency = _dependency_status(root, config)
    dependencies = cast(Mapping[str, Any], config["development_dependencies"])
    phase10_root = root / str(cast(Mapping[str, Any], dependencies["phase10"])["run_root"])
    phase9_root = root / str(cast(Mapping[str, Any], dependencies["phase9"])["run_root"])
    phase10_statuses = read_jsonl(phase10_root / "project_status.jsonl")
    selected = _select_projects(phase10_statuses, args)
    if args.mode == "full" and args.spec_limit is not None:
        raise ValueError("--spec-limit is forbidden in full mode")
    if args.spec_limit is not None and args.spec_limit < 1:
        raise ValueError("--spec-limit must be positive")
    if args.specification_id is not None:
        if args.mode != "pilot" or len(selected) != 1 or args.spec_limit is not None:
            raise ValueError("--specification-id requires one pilot project and no --spec-limit")
        if not any(
            row.get("project_id") == selected[0]
            and row.get("specification_id") == args.specification_id
            for row in read_jsonl(phase10_root / "specifications.jsonl")
        ):
            raise ValueError("--specification-id is absent from the selected project")
    if args.query_timeout is not None and (args.mode != "pilot" or args.query_timeout < 1):
        raise ValueError("--query-timeout requires pilot mode and a positive value")
    query_timeout = args.query_timeout or int(config["execution"]["timeout_seconds_per_query"])
    fixed_root_value = args.fixed_database_root or Path(
        str(cast(Mapping[str, Any], config["databases"])["fixed_root"])
    )
    fixed_root = fixed_root_value if fixed_root_value.is_absolute() else root / fixed_root_value
    if args.verification_mode == "differential":
        dependency["fixed_databases"] = _fixed_database_status(
            fixed_root, selected, phase10_statuses,
            str(config.get("analysis_scope", "development")),
            str(config["analyzer_snapshot_sha256"]) if test else None,
        )
    if args.fixed_endpoint_remapping and args.verification_mode != "differential":
        raise ValueError("fixed endpoint remapping requires differential verification")
    if args.reuse_vulnerable_from is not None and not args.fixed_endpoint_remapping:
        raise ValueError("vulnerable evidence reuse requires fixed endpoint remapping")
    vulnerable_evidence_record: dict[str, Any] | None = None
    reused_vulnerable: dict[tuple[str, str], Mapping[str, Any]] = {}
    if args.reuse_vulnerable_from is not None:
        source_root = (
            args.reuse_vulnerable_from
            if args.reuse_vulnerable_from.is_absolute()
            else root / args.reuse_vulnerable_from
        )
        vulnerable_evidence_record, reused_vulnerable = _verified_vulnerable_evidence(
            root, source_root, config_path, selected
        )
    if args.mode == "full" and collect_git(root).get("dirty") is not False:
        raise ValueError("Phase 11 full mode requires a clean Git worktree")
    work, final = _prepare_output(root, args)
    manifest_path = work / "manifest.json"
    if not manifest_path.exists():
        manifest = {
            "schema_version": 1,
            "phase": 11,
            "protocol_version": config["protocol_version"],
            "analysis_scope": "test_locked" if test else "development",
            "experiment_id": config["experiment_id"],
            "run_id": args.run_id,
            "mode": args.mode,
            "verification_mode": args.verification_mode,
            "fixed_endpoint_remapping": args.fixed_endpoint_remapping,
            "vulnerable_evidence_source": vulnerable_evidence_record,
            "specification_limit": args.spec_limit,
            "specification_id": args.specification_id,
            "created_at": utc_now(),
            "git": collect_git(root),
            "selected_project_ids": selected,
            "selected_project_count": len(selected),
            "development_dependencies": dependency,
            "config": {
                "path": config_path.relative_to(root).as_posix(),
                "sha256": sha256_file(config_path),
            },
            "implementation_sha256": {
                name: sha256_file(root / name)
                for name in (
                    "src/verification/query.py",
                    "src/verification/remap.py",
                    "src/verification/runner.py",
                    "src/verification/validate.py",
                )
            },
            "data_access": (
                "evaluator pass: sealed test artifacts and opaque fixed databases"
                if test
                else "development artifacts only; evaluator labels and locked test forbidden"
            ),
        }
        atomic_json(manifest_path, manifest)
        atomic_json(work / "environment.json", collect_environment(root))
        atomic_json(work / "dependency_status.json", dependency)
        if args.verification_mode == "differential":
            shutil.copyfile(
                fixed_root / "preparation_manifest.json",
                work / "fixed_database_preparation.json",
            )
            shutil.copyfile(
                fixed_root / "build_status.jsonl",
                work / "fixed_database_build_status.jsonl",
            )
            fixed_dependency = cast(Mapping[str, Any], dependency["fixed_databases"])
            if (
                sha256_file(work / "fixed_database_preparation.json")
                != fixed_dependency["preparation_manifest_sha256"]
                or sha256_file(work / "fixed_database_build_status.jsonl")
                != fixed_dependency["build_status_sha256"]
            ):
                raise RuntimeError("fixed database preparation changed while snapshotting")
        _write_text(work / "command.txt", shlex.join(sys.argv) + "\n")
        _write_text(
            work / "config.resolved.yaml",
            yaml.safe_dump(
                {
                    "arguments": {
                        k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                    },
                    "experiment": config,
                },
                sort_keys=True,
            ),
        )
        _write_text(
            work / "generated_queries/qlpack.yml",
            "name: maxvera/phase11-generated\n"
            "version: 0.0.0\n"
            "library: false\n"
            "dependencies:\n"
            "  codeql/java-all: 9.2.2\n",
        )
        atomic_jsonl(work / "verification_results.jsonl", [])
        atomic_jsonl(work / "taint_paths.jsonl", [])
        atomic_jsonl(work / "negative_evidence.jsonl", [])
        atomic_jsonl(
            work / "project_status.jsonl",
            [
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "status": "PENDING",
                    "updated_at": utc_now(),
                }
                for project_id in selected
            ],
        )
        atomic_jsonl(work / "resource_usage.jsonl", [])
        atomic_jsonl(work / "query_attempts.jsonl", [])
        atomic_jsonl(work / "useg_delta/nodes.jsonl", [])
        atomic_jsonl(work / "useg_delta/edges.jsonl", [])
    statuses = read_jsonl(work / "project_status.jsonl")
    results = read_jsonl(work / "verification_results.jsonl")
    result_ids = {str(row["specification_id"]) for row in results}
    taint_paths = read_jsonl(work / "taint_paths.jsonl")
    negative = read_jsonl(work / "negative_evidence.jsonl")
    resources = read_jsonl(work / "resource_usage.jsonl")
    query_attempts = read_jsonl(work / "query_attempts.jsonl")
    delta_nodes = read_jsonl(work / "useg_delta/nodes.jsonl")
    delta_edges = read_jsonl(work / "useg_delta/edges.jsonl")
    all_nodes = read_jsonl(phase9_root / "useg/nodes.jsonl")
    node_by_id = {str(node["node_id"]): node for node in all_nodes}
    hypothesis_nodes = {
        str(cast(Mapping[str, Any], node["properties"])["upstream_hypothesis_id"]): str(
            node["node_id"]
        )
        for node in all_nodes
        if node.get("kind") == "HYPOTHESIS"
    }
    specs = read_jsonl(phase10_root / "specifications.jsonl")
    specs_by_project: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        specs_by_project.setdefault(str(spec["project_id"]), []).append(spec)
    vulnerable_root = root / str(cast(Mapping[str, Any], config["databases"])["vulnerable_root"])
    execution = cast(Mapping[str, Any], config["execution"])
    policy = cast(Mapping[str, Any], config["verification"])
    codeql = _codeql(root)
    status_by_id = {str(row["project_id"]): row for row in statuses}
    phase10_by_id = {str(row["project_id"]): row for row in phase10_statuses}
    for position, project_id in enumerate(selected, start=1):
        project_status = status_by_id[project_id]
        if project_status["status"] != "PENDING":
            print(f"[{position}/{len(selected)}] {project_id}: {project_status['status']} (resume)")
            continue
        started = time.monotonic()
        query_count = sum(row.get("project_id") == project_id for row in query_attempts)
        project_specs = sorted(
            specs_by_project.get(project_id, []), key=lambda row: str(row["specification_id"])
        )
        if args.spec_limit is not None:
            project_specs = project_specs[: args.spec_limit]
        if args.specification_id is not None:
            project_specs = [
                spec for spec in project_specs if spec["specification_id"] == args.specification_id
            ]
        if phase10_by_id[project_id].get("status") != "SUCCESS":
            project_status.update(
                {
                    "status": "ANALYSIS_FAILED",
                    "reason": "inherited Phase 10 failure",
                    "updated_at": utc_now(),
                }
            )
        else:
            vulnerable_db = vulnerable_root / project_id
            fixed_db = fixed_root / project_id
            if not (vulnerable_db / "codeql-database.yml").is_file():
                project_status.update(
                    {
                        "status": "ANALYSIS_FAILED",
                        "reason": "vulnerable CodeQL database unavailable",
                        "updated_at": utc_now(),
                    }
                )
            elif (
                args.verification_mode == "differential"
                and not (fixed_db / "codeql-database.yml").is_file()
            ):
                project_status.update(
                    {
                        "status": "ANALYSIS_FAILED",
                        "reason": "fixed CodeQL database unavailable",
                        "updated_at": utc_now(),
                    }
                )
            else:
                failures = sum(
                    row.get("project_id") == project_id and row.get("status") == "ANALYSIS_FAILED"
                    for row in results
                )
                for spec in project_specs:
                    spec_id = str(spec["specification_id"])
                    if spec_id in result_ids:
                        continue
                    try:
                        reused = reused_vulnerable.get((project_id, spec_id))
                        needed = 0 if reused is not None else 2
                        if args.verification_mode == "differential":
                            needed += 2
                        if query_count + needed > int(policy["max_query_invocations_per_project"]):
                            raise RuntimeError("per-project CodeQL query budget exhausted")
                        vulnerable = (
                            dict(reused)
                            if reused is not None
                            else _analyze_version(
                                codeql=codeql,
                                database=vulnerable_db,
                                work=work,
                                project_id=project_id,
                                version="vulnerable",
                                specification=spec,
                                nodes=node_by_id,
                                timeout=query_timeout,
                                threads=int(execution["threads"]),
                                ram_mb=int(execution["ram_mb"]),
                                max_paths=int(policy["max_paths_per_specification"]),
                            )
                        )
                        fixed: dict[str, Any] | None = None
                        if args.verification_mode == "differential" and _needs_fixed_verification(
                            vulnerable
                        ):
                            fixed_nodes: Mapping[str, Mapping[str, Any]] = node_by_id
                            endpoint_mapping: dict[str, Any] | None = None
                            query_variant: str | None = None
                            if args.fixed_endpoint_remapping:
                                fixed_nodes, endpoint_mapping = remap_nodes_for_fixed(
                                    spec,
                                    node_by_id,
                                    vulnerable_db / "src.zip",
                                    fixed_db / "src.zip",
                                )
                                query_variant = "fixed_remapped"
                            if endpoint_mapping is not None and not endpoint_mapping["complete"]:
                                fixed = {
                                    "database": fixed_db.as_posix(),
                                    "source_endpoints": 0,
                                    "sink_endpoints": 0,
                                    "paths": [],
                                    "path_count": 0,
                                    "sarif": None,
                                    "sarif_sha256": None,
                                    "analysis_skipped": "incomplete exact endpoint mapping",
                                    "endpoint_mapping": endpoint_mapping,
                                }
                            else:
                                fixed = _analyze_version(
                                    codeql=codeql,
                                    database=fixed_db,
                                    work=work,
                                    project_id=project_id,
                                    version="fixed",
                                    specification=spec,
                                    nodes=fixed_nodes,
                                    timeout=query_timeout,
                                    threads=int(execution["threads"]),
                                    ram_mb=int(execution["ram_mb"]),
                                    max_paths=int(policy["max_paths_per_specification"]),
                                    query_variant=query_variant,
                                )
                                if endpoint_mapping is not None:
                                    fixed["endpoint_mapping"] = endpoint_mapping
                        verification_status, reason = _status(vulnerable, fixed)
                        result = {
                            "schema_version": 1,
                            "verification_version": "phase11-static-verification-v2"
                            if args.fixed_endpoint_remapping
                            else "phase11-static-verification-v1",
                            "project_id": project_id,
                            "hypothesis_id": spec["hypothesis_id"],
                            "specification_id": spec_id,
                            "candidate_cwe": spec["candidate_cwe"],
                            "verification_mode": args.verification_mode,
                            "analysis_iteration": 1,
                            "status": verification_status,
                            "reason": reason,
                            "vulnerable": vulnerable,
                            "fixed": fixed,
                            "stop_reason": "EVIDENCE_THRESHOLD_MET"
                            if verification_status == "VERIFIED_DIFFERENTIAL"
                            else "NO_NEW_EVIDENCE",
                            "llm_calls": 0,
                            "llm_tokens": 0,
                        }
                    except Exception as error:
                        failures += 1
                        error_text = f"{type(error).__name__}: {str(error)[:500]}"
                        result = {
                            "schema_version": 1,
                            "verification_version": "phase11-static-verification-v2"
                            if args.fixed_endpoint_remapping
                            else "phase11-static-verification-v1",
                            "project_id": project_id,
                            "hypothesis_id": spec["hypothesis_id"],
                            "specification_id": spec_id,
                            "candidate_cwe": spec["candidate_cwe"],
                            "verification_mode": args.verification_mode,
                            "analysis_iteration": 1,
                            "status": "ANALYSIS_FAILED",
                            "reason": error_text,
                            "vulnerable": None,
                            "fixed": None,
                            "stop_reason": "BUDGET_EXHAUSTED"
                            if "budget exhausted" in error_text
                            else "ANALYSIS_FAILURE",
                            "llm_calls": 0,
                            "llm_tokens": 0,
                        }
                    query_attempts = read_jsonl(work / "query_attempts.jsonl")
                    query_count = sum(row.get("project_id") == project_id for row in query_attempts)
                    results.append(result)
                    result_ids.add(spec_id)
                    if isinstance(result.get("vulnerable"), Mapping):
                        for index, path in enumerate(
                            cast(
                                Sequence[Any],
                                cast(Mapping[str, Any], result["vulnerable"])["paths"],
                            )
                        ):
                            taint_paths.append(
                                {
                                    "schema_version": 1,
                                    "project_id": project_id,
                                    "specification_id": spec_id,
                                    "version": "vulnerable",
                                    "path_index": index,
                                    "locations": path,
                                }
                            )
                    if result["status"] != "VERIFIED_DIFFERENTIAL":
                        negative.append(
                            {
                                "schema_version": 1,
                                "project_id": project_id,
                                "specification_id": spec_id,
                                "status": result["status"],
                                "reason": result["reason"],
                            }
                        )
                    if result["status"] != "ANALYSIS_FAILED":
                        new_nodes, new_edges = _useg_delta(
                            result=result,
                            hypothesis_node_id=hypothesis_nodes[str(spec["hypothesis_id"])],
                            run_id=args.run_id,
                        )
                        delta_nodes.extend(new_nodes)
                        delta_edges.extend(new_edges)
                    atomic_jsonl(work / "verification_results.jsonl", results)
                    atomic_jsonl(work / "taint_paths.jsonl", taint_paths)
                    atomic_jsonl(work / "negative_evidence.jsonl", negative)
                    atomic_jsonl(work / "useg_delta/nodes.jsonl", sort_nodes(delta_nodes))
                    atomic_jsonl(work / "useg_delta/edges.jsonl", sort_edges(delta_edges))
                project_status.update(
                    {
                        "status": "SUCCESS" if failures == 0 else "ANALYSIS_FAILED",
                        "reason": "all frozen specifications reached a final verification state"
                        if failures == 0
                        else f"{failures} specification analysis failure(s)",
                        "specifications": len(project_specs),
                        "query_invocations": query_count,
                        "updated_at": utc_now(),
                    }
                )
        resources = [row for row in resources if row.get("project_id") != project_id]
        resources.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "wall_seconds": round(time.monotonic() - started, 3),
                "peak_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "query_invocations": query_count,
                "llm_calls": 0,
                "llm_tokens": 0,
            }
        )
        atomic_jsonl(work / "project_status.jsonl", statuses)
        atomic_jsonl(
            work / "resource_usage.jsonl",
            sorted(resources, key=lambda row: selected.index(str(row["project_id"]))),
        )
        print(f"[{position}/{len(selected)}] {project_id}: {project_status['status']}", flush=True)
    counts = {
        status: sum(row.get("status") == status for row in results)
        for status in sorted(FINAL_SPEC_STATUSES)
    }
    summary = {
        "schema_version": 1,
        "phase": 11,
        "run_id": args.run_id,
        "verification_mode": args.verification_mode,
        "projects": len(selected),
        "analysis_successes": sum(row.get("status") == "SUCCESS" for row in statuses),
        "analysis_failures": sum(row.get("status") != "SUCCESS" for row in statuses),
        "specifications": len(results),
        "status_counts": counts,
        "verified_findings": counts["VERIFIED_DIFFERENTIAL"],
        "unverified_findings": sum(
            count for status, count in counts.items() if status.startswith("UNVERIFIED_")
        ),
        "taint_paths": len(taint_paths),
        "analysis_iterations": 1,
        "query_invocations": sum(int(row.get("query_invocations", 0)) for row in resources),
        "llm_calls": 0,
        "llm_tokens": 0,
    }
    atomic_json(work / "phase11_summary.json", summary)
    _write_text(work / "STATUS", "SUCCESS\n" if summary["analysis_failures"] == 0 else "FAILED\n")
    write_checksums(work)
    os.replace(work, final)
    print(f"Phase 11 artifact created: {final.relative_to(root)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--config", type=Path, default=Path("configs/experiments/phase11_static_verification.yaml")
    )
    parser.add_argument("--output-root", type=Path, default=Path("results/verification/phase11"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument(
        "--verification-mode",
        choices=("vulnerable-only", "differential"),
        default="vulnerable-only",
    )
    parser.add_argument("--project-id")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--spec-limit", type=int)
    parser.add_argument("--specification-id")
    parser.add_argument("--query-timeout", type=int)
    parser.add_argument("--fixed-database-root", type=Path)
    parser.add_argument(
        "--fixed-endpoint-remapping",
        action="store_true",
        help="map exact unchanged source locations before fixed-version queries",
    )
    parser.add_argument(
        "--reuse-vulnerable-from",
        type=Path,
        help="reuse checksum-verified vulnerable results from a compatible full run",
    )
    parser.add_argument("--resume", action="store_true")
    return parser


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
