"""Validate immutable Phase 11 static-verification artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import sha256_file
from src.graphs.evidence.model import cycle_nodes, sort_edges, sort_nodes
from src.reproduction.common import read_jsonl
from src.verification.runner import FINAL_SPEC_STATUSES, _dependency_status

REQUIRED_FILES = {
    "STATUS",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "dependency_status.json",
    "environment.json",
    "manifest.json",
    "negative_evidence.jsonl",
    "phase11_summary.json",
    "project_status.jsonl",
    "query_attempts.jsonl",
    "resource_usage.jsonl",
    "taint_paths.jsonl",
    "useg_delta/edges.jsonl",
    "useg_delta/nodes.jsonl",
    "verification_results.jsonl",
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
            raise ValueError(f"Phase 11 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if indexed != actual:
        raise ValueError("Phase 11 checksum index coverage mismatch")


def _path_count(result: Mapping[str, Any], version: str) -> int:
    value = result.get(version)
    return int(value.get("path_count", 0)) if isinstance(value, Mapping) else 0


def validate(run_root: Path, *, repo_root: Path) -> str:
    missing = sorted(name for name in REQUIRED_FILES if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 11 outputs: {', '.join(missing)}")
    manifest = _json(run_root / "manifest.json")
    if manifest.get("phase") != 11 or manifest.get("protocol_version") != "1.8.0":
        raise ValueError("not a Phase 11 protocol 1.8.0 artifact")
    config_record = cast(Mapping[str, Any], manifest["config"])
    config_path = repo_root / str(config_record["path"])
    if sha256_file(config_path) != config_record["sha256"]:
        raise ValueError("Phase 11 config checksum mismatch")
    config = _mapping(config_path)
    selected = [str(value) for value in cast(Sequence[Any], manifest["selected_project_ids"])]
    if len(selected) != manifest.get("selected_project_count") or len(selected) != len(
        set(selected)
    ):
        raise ValueError("Phase 11 selected project manifest is invalid")
    dependency = _dependency_status(repo_root, config)
    phase10_config = cast(
        Mapping[str, Any],
        cast(Mapping[str, Any], config["development_dependencies"])["phase10"],
    )
    phase10_root = repo_root / str(phase10_config["run_root"])
    phase10_status_rows = read_jsonl(phase10_root / "project_status.jsonl")
    if manifest.get("verification_mode") == "differential":
        snapshot_manifest_path = run_root / "fixed_database_preparation.json"
        snapshot_status_path = run_root / "fixed_database_build_status.jsonl"
        if not snapshot_manifest_path.is_file() or not snapshot_status_path.is_file():
            raise ValueError("Phase 11 differential dependency snapshot is missing")
        snapshot_manifest = _json(snapshot_manifest_path)
        if (
            snapshot_manifest.get("development_only") is not True
            or snapshot_manifest.get("locked_test_prepared") is not False
            or snapshot_manifest.get("identity_mapping_persisted") is not False
            or snapshot_manifest.get("status_sha256") != sha256_file(snapshot_status_path)
        ):
            raise ValueError("Phase 11 fixed database snapshot violates the opaque contract")
        snapshot_statuses = {
            str(row["project_id"]): row for row in read_jsonl(snapshot_status_path)
        }
        resolved = _mapping(run_root / "config.resolved.yaml")
        arguments = cast(Mapping[str, Any], resolved["arguments"])
        configured_root = (
            arguments.get("fixed_database_root")
            or cast(Mapping[str, Any], config["databases"])["fixed_root"]
        )
        fixed_root = Path(str(configured_root))
        if not fixed_root.is_absolute():
            fixed_root = repo_root / fixed_root
        phase10_by_id = {str(row["project_id"]): row for row in phase10_status_rows}
        required = [
            project_id
            for project_id in selected
            if phase10_by_id[project_id].get("status") == "SUCCESS"
        ]
        unavailable = [
            project_id
            for project_id in required
            if (
                snapshot_statuses.get(project_id, {}).get("status") != "SUCCESS"
                or not (fixed_root / project_id / "codeql-database.yml").is_file()
            )
        ]
        dependency["fixed_databases"] = {
            "preparation_manifest_sha256": sha256_file(snapshot_manifest_path),
            "build_status_sha256": sha256_file(snapshot_status_path),
            "required_databases": len(required),
            "available_databases": len(required) - len(unavailable),
            "unavailable_databases": len(unavailable),
        }
    if _json(run_root / "dependency_status.json") != dependency:
        raise ValueError("Phase 11 dependency status mismatch")
    if manifest.get("development_dependencies") != dependency:
        raise ValueError("Phase 11 manifest dependency mismatch")
    for relative, digest in cast(Mapping[str, Any], manifest["implementation_sha256"]).items():
        if sha256_file(repo_root / str(relative)) != digest:
            raise ValueError(f"Phase 11 implementation checksum mismatch: {relative}")
    if manifest.get("mode") == "full" and manifest.get("verification_mode") != "differential":
        raise ValueError("Phase 11 full artifact is not differential")
    statuses = read_jsonl(run_root / "project_status.jsonl")
    if [str(row.get("project_id")) for row in statuses] != selected:
        raise ValueError("Phase 11 project status coverage/order mismatch")
    if any(row.get("status") not in {"SUCCESS", "ANALYSIS_FAILED"} for row in statuses):
        raise ValueError("Phase 11 contains non-final project status")
    expected_run_status = (
        "SUCCESS" if all(row["status"] == "SUCCESS" for row in statuses) else "FAILED"
    )
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != expected_run_status:
        raise ValueError("Phase 11 STATUS does not match project outcomes")

    results = read_jsonl(run_root / "verification_results.jsonl")
    identifiers = [str(row.get("specification_id")) for row in results]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Phase 11 specification verification is duplicated")
    phase10_statuses = {str(row["project_id"]): row for row in phase10_status_rows}
    phase10_specs = read_jsonl(phase10_root / "specifications.jsonl")
    specification_limit = manifest.get("specification_limit")
    expected_ids: set[str] = set()
    for project_id in selected:
        if phase10_statuses[project_id].get("status") != "SUCCESS":
            continue
        project_specs = sorted(
            (row for row in phase10_specs if row.get("project_id") == project_id),
            key=lambda row: str(row["specification_id"]),
        )
        if isinstance(specification_limit, int):
            project_specs = project_specs[:specification_limit]
        if next(row for row in statuses if row["project_id"] == project_id)["status"] == "SUCCESS":
            expected_ids.update(str(row["specification_id"]) for row in project_specs)
    successful_result_ids = {
        str(row["specification_id"])
        for row in results
        if next(status for status in statuses if status["project_id"] == row["project_id"])[
            "status"
        ]
        == "SUCCESS"
    }
    if successful_result_ids != expected_ids:
        raise ValueError("Phase 11 successful-project specification coverage mismatch")
    mode = str(manifest["verification_mode"])
    for result in results:
        status = result.get("status")
        if status not in FINAL_SPEC_STATUSES or result.get("verification_mode") != mode:
            raise ValueError("Phase 11 verification result status/mode is invalid")
        if (
            result.get("analysis_iteration") != 1
            or result.get("llm_calls") != 0
            or result.get("llm_tokens") != 0
        ):
            raise ValueError("Phase 11 deterministic iteration/LLM invariant failed")
        expected_stop = (
            "EVIDENCE_THRESHOLD_MET"
            if status == "VERIFIED_DIFFERENTIAL"
            else "BUDGET_EXHAUSTED"
            if status == "ANALYSIS_FAILED" and "budget exhausted" in str(result.get("reason", ""))
            else "ANALYSIS_FAILURE"
            if status == "ANALYSIS_FAILED"
            else "NO_NEW_EVIDENCE"
        )
        if result.get("stop_reason") != expected_stop:
            raise ValueError("Phase 11 deterministic stop reason mismatch")
        vulnerable_paths = _path_count(result, "vulnerable")
        fixed_paths = _path_count(result, "fixed")
        if status == "VERIFIED_DIFFERENTIAL" and not (
            mode == "differential" and vulnerable_paths > 0 and fixed_paths == 0
        ):
            raise ValueError(
                "Phase 11 verified result lacks vulnerable/fixed differential evidence"
            )
        if status == "UNVERIFIED_FIXED_NOT_RUN" and not (
            mode == "vulnerable-only" and vulnerable_paths > 0 and result.get("fixed") is None
        ):
            raise ValueError("Phase 11 vulnerable-only result is inconsistent")
        if status == "UNVERIFIED_NO_VULNERABLE_PATH" and vulnerable_paths != 0:
            raise ValueError("Phase 11 no-path result contains a vulnerable path")
        if status == "UNVERIFIED_PERSISTS_FIXED" and fixed_paths == 0:
            raise ValueError("Phase 11 fixed-persistence result lacks a fixed path")

    path_rows = read_jsonl(run_root / "taint_paths.jsonl")
    expected_paths = sum(_path_count(result, "vulnerable") for result in results)
    if len(path_rows) != expected_paths:
        raise ValueError("Phase 11 normalized taint-path count mismatch")
    if any(row.get("version") != "vulnerable" or not row.get("locations") for row in path_rows):
        raise ValueError("Phase 11 taint path is malformed")
    negative = read_jsonl(run_root / "negative_evidence.jsonl")
    expected_negative = [row for row in results if row.get("status") != "VERIFIED_DIFFERENTIAL"]
    if len(negative) != len(expected_negative):
        raise ValueError("Phase 11 negative-evidence coverage mismatch")

    delta_nodes = read_jsonl(run_root / "useg_delta/nodes.jsonl")
    delta_edges = read_jsonl(run_root / "useg_delta/edges.jsonl")
    if delta_nodes != sort_nodes(delta_nodes) or delta_edges != sort_edges(delta_edges):
        raise ValueError("Phase 11 USEG delta is not deterministically ordered")
    node_ids = [str(node.get("node_id")) for node in delta_nodes]
    edge_ids = [str(edge.get("edge_id")) for edge in delta_edges]
    if len(node_ids) != len(set(node_ids)) or len(edge_ids) != len(set(edge_ids)):
        raise ValueError("Phase 11 USEG delta contains duplicate identities")
    phase9 = cast(
        Mapping[str, Any], cast(Mapping[str, Any], config["development_dependencies"])["phase9"]
    )
    phase9_nodes = read_jsonl(repo_root / str(phase9["run_root"]) / "useg/nodes.jsonl")
    phase9_edges = read_jsonl(repo_root / str(phase9["run_root"]) / "useg/edges.jsonl")
    all_nodes = phase9_nodes + delta_nodes
    all_ids = {str(node["node_id"]) for node in all_nodes}
    if len(all_ids) != len(all_nodes):
        raise ValueError("Phase 11 USEG delta collides with a Phase 9 node identity")
    if any(
        str(edge["source_id"]) not in all_ids or str(edge["target_id"]) not in all_ids
        for edge in delta_edges
    ):
        raise ValueError("Phase 11 USEG delta edge references an unknown node")
    if cycle_nodes(all_nodes, phase9_edges + delta_edges):
        raise ValueError("Phase 11 USEG delta introduces an evidence cycle")

    resources = read_jsonl(run_root / "resource_usage.jsonl")
    if {str(row.get("project_id")) for row in resources} != set(selected):
        raise ValueError("Phase 11 resource coverage mismatch")
    policy = cast(Mapping[str, Any], config["verification"])
    attempts = read_jsonl(run_root / "query_attempts.jsonl")
    attempt_counts = Counter(str(row.get("project_id")) for row in attempts)
    if any(
        int(row.get("query_invocations", 0)) != attempt_counts[str(row["project_id"])]
        for row in resources
    ):
        raise ValueError("Phase 11 query-attempt accounting mismatch")
    if any(
        int(row.get("query_invocations", 0)) > int(policy["max_query_invocations_per_project"])
        for row in resources
    ):
        raise ValueError("Phase 11 query budget exceeded")
    if any(row.get("llm_calls") != 0 or row.get("llm_tokens") != 0 for row in resources):
        raise ValueError("Phase 11 unexpectedly used an LLM")

    summary = _json(run_root / "phase11_summary.json")
    counts = Counter(str(row["status"]) for row in results)
    expected_counts = {status: counts[status] for status in sorted(FINAL_SPEC_STATUSES)}
    expected = {
        "projects": len(selected),
        "analysis_successes": sum(row["status"] == "SUCCESS" for row in statuses),
        "analysis_failures": sum(row["status"] != "SUCCESS" for row in statuses),
        "specifications": len(results),
        "status_counts": expected_counts,
        "verified_findings": counts["VERIFIED_DIFFERENTIAL"],
        "unverified_findings": sum(
            count for status, count in counts.items() if status.startswith("UNVERIFIED_")
        ),
        "taint_paths": len(path_rows),
        "analysis_iterations": 1,
        "query_invocations": sum(int(row.get("query_invocations", 0)) for row in resources),
        "llm_calls": 0,
        "llm_tokens": 0,
    }
    if any(summary.get(key) != value for key, value in expected.items()):
        raise ValueError("Phase 11 summary does not reproduce from project outputs")
    _verify_checksums(run_root)
    qualifier = "PASS" if not expected["analysis_failures"] else "PASS_WITH_ANALYSIS_FAILURES"
    verified = counts["VERIFIED_DIFFERENTIAL"]
    return f"{qualifier}: Phase 11 {mode} ({len(results)} specs, {verified} verified)"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = args.repo_root.resolve()
    run_root = args.run_root if args.run_root.is_absolute() else repo_root / args.run_root
    print(validate(run_root.resolve(), repo_root=repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
