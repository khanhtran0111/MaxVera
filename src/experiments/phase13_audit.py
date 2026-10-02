"""Audit sealed verification evidence without changing canonical queries or verdicts.

Line remapping and optional fixed queries are diagnostic only. They must never be
promoted to canonical findings or used to retune the locked experiment.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys
import zipfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import yaml

from src.baselines.validate import _verify_checksums
from src.common.envfile import effective_env
from src.common.provenance import collect_git, sha256_file, utc_now
from src.experiments.phase13 import RUN_ID
from src.experiments.phase13_snapshot import validate_snapshot
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums
from src.reproduction.runner import _codeql_binary
from src.verification.runner import _analyze_version
from src.verification.validate import validate as validate_verification


def line_mapping(before: list[str], after: list[str]) -> dict[int, int]:
    """Map only lines inside exact unchanged diff blocks; never guess changed lines."""
    mapping: dict[int, int] = {}
    for block in SequenceMatcher(None, before, after, autojunk=False).get_matching_blocks():
        for offset in range(block.size):
            mapping[block.a + offset + 1] = block.b + offset + 1
    return mapping


def archive_source(archive: Path, file: str) -> tuple[str, list[str]]:
    if not file or file.startswith("/") or ".." in Path(file).parts:
        raise ValueError("endpoint file must be a relative source path")
    with zipfile.ZipFile(archive) as handle:
        matches = [name for name in handle.namelist() if name == file or name.endswith("/" + file)]
        if len(matches) != 1:
            raise ValueError(f"source archive requires one match for {file}; found {len(matches)}")
        data = handle.read(matches[0])
    return hashlib.sha256(data).hexdigest(), data.decode("utf-8", errors="replace").splitlines()


def node_location(node: Mapping[str, Any]) -> tuple[str, int] | None:
    properties = node.get("properties", {})
    if node.get("layer") == "program":
        location = properties.get("location", {})
        file, line = location.get("file"), location.get("start_line")
    elif node.get("layer") == "evidence":
        file, line = properties.get("file"), properties.get("line")
    else:
        return None
    if isinstance(file, str) and isinstance(line, int) and line > 0:
        return file, line
    return None


def normalized_path(path: list[dict[str, Any]]) -> tuple[tuple[str, int], ...]:
    """Collapse repeated consecutive locations, preserving source-to-sink order."""
    result: list[tuple[str, int]] = []
    for item in path:
        location = (str(item["file"]), int(item["line"]))
        if not result or result[-1] != location:
            result.append(location)
    return tuple(result)


def audit_finding(
    result: dict[str, Any],
    specification: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    vulnerable_archive: Path,
    fixed_archive: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    remapped = dict(nodes)
    endpoints: list[dict[str, Any]] = []
    cache: dict[str, tuple[str, str, list[str], list[str], dict[int, int]]] = {}
    for role in ("sources", "sinks", "sanitizers", "propagators"):
        for entry in specification.get(role, []):
            node_id = str(entry["node_id"])
            remapped[node_id] = copy.deepcopy(nodes[node_id])
            location = node_location(nodes[node_id])
            if location is None:
                endpoints.append(
                    {"role": role, "node_id": node_id, "mapping": "SEMANTIC_DESCRIPTOR"}
                )
                continue
            file, old_line = location
            if file not in cache:
                before_sha, before = archive_source(vulnerable_archive, file)
                after_sha, after = archive_source(fixed_archive, file)
                cache[file] = (before_sha, after_sha, before, after, line_mapping(before, after))
            before_sha, after_sha, before, after, mapping = cache[file]
            new_line = mapping.get(old_line)
            mapping_status = (
                "UNCHANGED_AT_SAME_LINE"
                if new_line == old_line
                else "UNCHANGED_BUT_MOVED"
                if new_line is not None
                else "CHANGED_OR_REMOVED_REQUIRES_REVIEW"
            )
            endpoints.append(
                {
                    "role": role,
                    "node_id": node_id,
                    "file": file,
                    "vulnerable_line": old_line,
                    "mapped_fixed_line": new_line,
                    "vulnerable_text": before[old_line - 1] if old_line <= len(before) else None,
                    "fixed_text_at_original_line": after[old_line - 1]
                    if old_line <= len(after)
                    else None,
                    "fixed_text_at_mapped_line": after[new_line - 1] if new_line else None,
                    "mapping": mapping_status,
                    "vulnerable_source_sha256": before_sha,
                    "fixed_source_sha256": after_sha,
                }
            )
            if new_line is not None:
                props = remapped[node_id]["properties"]
                if nodes[node_id]["layer"] == "program":
                    delta = new_line - old_line
                    props["location"]["start_line"] = new_line
                    props["location"]["end_line"] += delta
                else:
                    props["line"] = new_line
    fixed = result["fixed"]
    missing = [role for role in ("source", "sink") if not fixed.get(role + "_endpoints")]
    moved_missing = any(
        row["role"] == role + "s" and row["mapping"] == "UNCHANGED_BUT_MOVED"
        for role in missing
        for row in endpoints
    )
    signature = sorted(
        (
            (row["role"], row.get("file"), row.get("vulnerable_line"))
            for row in endpoints
            if row["role"] in {"sources", "sinks"}
        ),
        key=str,
    )
    signature_sha = hashlib.sha256(json.dumps(signature).encode()).hexdigest()
    record = {
        "project_id": result["project_id"],
        "specification_id": result["specification_id"],
        "candidate_cwe": result["candidate_cwe"],
        "canonical_status": result["status"],
        "audit_status": "LINE_SHIFT_CONFOUNDED"
        if moved_missing
        else "FIXED_ENDPOINT_UNRESOLVED"
        if missing
        else "REVIEW_REQUIRED",
        "missing_fixed_roles": missing,
        "endpoints": endpoints,
        "endpoint_group_sha256": signature_sha,
        "normalized_vulnerable_paths": sorted(
            {normalized_path(p) for p in result["vulnerable"]["paths"]}
        ),
        "canonical_verdict_changed": False,
    }
    return record, remapped


def run(root: Path, run_id: str, audit_id: str, *, check_fixed: bool, resume: bool) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("verification audit requires evaluator role")
    if not RUN_ID.fullmatch(run_id) or not RUN_ID.fullmatch(audit_id):
        raise ValueError("invalid run/audit ID")
    parent = root / "results/phase13" / run_id
    snapshot_path = parent / "analyzer_snapshot.json"
    snapshot = validate_snapshot(root, snapshot_path)
    verification = parent / "evaluation/verification" / f"{run_id}_verification"
    validator = validate_verification(verification, repo_root=root)
    final = parent / "evaluation/audits" / audit_id
    work = final.parent / f".{audit_id}.inprogress"
    if final.exists():
        _verify_checksums(final)
        manifest = json.loads((final / "manifest.json").read_text())
        if manifest["check_fixed"] != check_fixed:
            raise ValueError("existing audit used different diagnostic query options")
        return final
    if work.exists() and not resume:
        raise FileExistsError("unfinished audit exists; use --resume")
    work.mkdir(parents=True, exist_ok=True)
    lock = sha256_file(verification / "checksums.sha256")
    input_record = {
        "analyzer_snapshot_sha256": sha256_file(snapshot_path),
        "verification_checksums_sha256": lock,
        "check_fixed": check_fixed,
    }
    input_path = work / "inputs.json"
    if input_path.exists() and json.loads(input_path.read_text()) != input_record:
        raise ValueError("audit resume input mismatch")
    atomic_json(input_path, input_record)
    b9 = root / snapshot["analysis_runs"]["B9"]["run_root"]
    p9 = root / snapshot["analysis_runs"]["phase9"]["run_root"]
    specs = {row["specification_id"]: row for row in read_jsonl(b9 / "specifications.jsonl")}
    nodes = {row["node_id"]: row for row in read_jsonl(p9 / "useg/nodes.jsonl")}
    config = yaml.safe_load((verification / "config.resolved.yaml").read_text())["experiment"]
    results = read_jsonl(verification / "verification_results.jsonl")
    records = []
    checks: dict[str, Any] = {}
    check_path = work / "fixed_diagnostic_checks.json"
    if check_path.exists():
        checks = json.loads(check_path.read_text())
    if check_fixed:
        query_dir = work / "generated_queries"
        query_dir.mkdir(exist_ok=True)
        shutil.copyfile(verification / "generated_queries/qlpack.yml", query_dir / "qlpack.yml")
    for result in results:
        if result["status"] != "VERIFIED_DIFFERENTIAL":
            continue
        project = result["project_id"]
        vulnerable = root / config["databases"]["vulnerable_root"] / project
        fixed = root / config["databases"]["fixed_root"] / project
        record, remapped = audit_finding(
            result,
            specs[result["specification_id"]],
            nodes,
            vulnerable / "src.zip",
            fixed / "src.zip",
        )
        if check_fixed:
            # Reuse diagnostics only for exactly identical rendered source/sink/barrier queries.
            from src.verification.query import render_path_query

            spec = copy.deepcopy(specs[result["specification_id"]])
            spec["specification_id"] = "diagnostic"
            key = hashlib.sha256(render_path_query(spec, remapped).encode()).hexdigest()
            key = project + ":" + key
            if key not in checks:
                spec["specification_id"] = result["specification_id"]
                print(f"AUDIT_FIXED_QUERY: {project} {spec['specification_id']}", flush=True)
                check = _analyze_version(
                    codeql=_codeql_binary(effective_env(root / ".env")["MAXVERA_CODEQL_HOME"]),
                    database=fixed,
                    work=work,
                    project_id=project,
                    version="fixed_diagnostic",
                    specification=spec,
                    nodes=remapped,
                    timeout=1800,
                    threads=2,
                    ram_mb=8192,
                    max_paths=4,
                )
                checks[key] = {**check, "representative_specification_id": spec["specification_id"]}
                atomic_json(check_path, checks)
            record["fixed_diagnostic"] = checks[key]
            if checks[key]["path_count"] > 0:
                record["audit_status"] = "PATH_PERSISTS_AFTER_LINE_REMAP"
        records.append(record)
    groups: dict[str, list[str]] = defaultdict(list)
    for row in records:
        groups[row["project_id"] + ":" + row["endpoint_group_sha256"]].append(
            row["specification_id"]
        )
    summary = {
        "schema_version": 1,
        "canonical_verification_validation": validator,
        "canonical_status_counts": dict(Counter(row["status"] for row in results)),
        "verified_specifications_audited": len(records),
        "audit_status_counts": dict(Counter(row["audit_status"] for row in records)),
        "unique_endpoint_groups": len(groups),
        "endpoint_groups_are_not_unique_vulnerabilities": True,
        "diagnostic_only": True,
        "canonical_verdicts_changed": False,
        "full_completion_gate": "REQUIRES_VERIFICATION_REVIEW"
        if records
        else "NO_VERIFIED_FINDINGS",
    }
    atomic_jsonl(work / "findings_audit.jsonl", records)
    atomic_json(work / "endpoint_groups.json", groups)
    atomic_json(work / "summary.json", summary)
    report = [
        "# Phase 13 verification audit",
        "",
        f"Canonical validation: {validator}",
        "",
        "This is a diagnostic supplement. Canonical verdicts, configs "
        "and checksums remain unchanged.",
        "Mapped queries are not eligible for canonical metrics or calibration.",
        "",
        "| Specification | Audit result | Fixed diagnostic paths |",
        "|---|---|---:|",
    ]
    for row in records:
        count = row.get("fixed_diagnostic", {}).get("path_count", "not run")
        report.append(f"| {row['specification_id']} | {row['audit_status']} | {count} |")
    report.extend(["", f"Endpoint groups: {len(groups)} (not a vulnerability count).", ""])
    for row in records:
        report.extend([f"## {row['specification_id']}", ""])
        for endpoint in row["endpoints"]:
            if endpoint.get("mapping") == "UNCHANGED_BUT_MOVED":
                report.append(
                    f"- {endpoint['role']}: `{endpoint['file']}` "
                    f"{endpoint['vulnerable_line']} → {endpoint['mapped_fixed_line']}; "
                    "unchanged source text."
                )
        report.append("")
    (work / "report.md").write_text("\n".join(report))
    atomic_json(
        work / "manifest.json",
        {
            "schema_version": 1,
            "run_id": audit_id,
            "parent_run_id": run_id,
            "created_at": utc_now(),
            **input_record,
            "diagnostic_only": True,
            "implementation_sha256": sha256_file(Path(__file__)),
            "git": collect_git(root),
        },
    )
    if sha256_file(verification / "checksums.sha256") != lock:
        raise ValueError("canonical verification changed during audit")
    _verify_checksums(verification)
    (work / "STATUS").write_text("SUCCESS\n")
    (work / "command.txt").write_text(json.dumps(sys.argv) + "\n")
    write_checksums(work)
    os.replace(work, final)
    print(f"AUDIT_COMPLETED: {final}", flush=True)
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument("--audit-id", default="verification_audit_001")
    parser.add_argument("--check-fixed", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    run(
        args.repo_root.resolve(),
        args.run_id,
        args.audit_id,
        check_fixed=args.check_fixed,
        resume=args.resume,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
