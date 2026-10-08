"""Verifier v3: exact and semantic mapping, explicit unresolved states, fixed-side queries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.graphs.evidence.model import cycle_nodes
from src.pipeline_v2.model import identifier, map_endpoint
from src.pipeline_v2.queries import (
    common_predicates,
    endpoint_query,
    path_query,
    resolution_complete,
)
from src.pipeline_v2.runtime import Run, codeql, dependency, endpoint_inventory, query_csv
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl
from src.verification.remap import archive_source, unchanged_line_mapping
from src.verification.runner import _interpret_paths


def differential_status(vulnerable: Mapping[str, Any], fixed: Mapping[str, Any] | None) -> str:
    if vulnerable.get("resolution_complete") is not True:
        return "UNVERIFIED_VULNERABLE_ENDPOINT_RESOLUTION"
    if vulnerable.get("query_completed") is not True:
        return "UNVERIFIED_VULNERABLE_QUERY_FAILED"
    if not vulnerable.get("path_count"):
        return "UNVERIFIED_NO_VULNERABLE_PATH"
    if fixed is None:
        return "UNVERIFIED_FIXED_NOT_RUN"
    if fixed.get("mapping_complete") is not True:
        return "UNVERIFIED_FIXED_ENDPOINT_MAPPING"
    if fixed.get("resolution_complete") is not True:
        return "UNVERIFIED_FIXED_ENDPOINT_RESOLUTION"
    if fixed.get("path_count") is None or fixed.get("query_completed") is not True:
        return "UNVERIFIED_FIXED_QUERY_FAILED"
    if fixed["path_count"]:
        return "UNVERIFIED_PERSISTS_FIXED"
    return "VERIFIED_DIFFERENTIAL"


def map_frozen_entries(
    entries: Sequence[Mapping[str, Any]],
    fixed_inventory: Sequence[Mapping[str, Any]],
    vulnerable_archive: Path,
    fixed_archive: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for entry in entries:
        file = entry["descriptor"]["file"]
        line = entry["descriptor"]["start_line"]
        exact_line = None
        try:
            _, before = archive_source(vulnerable_archive, file)
            _, after = archive_source(fixed_archive, file)
            exact_line = unchanged_line_mapping(before, after).get(line)
        except (OSError, ValueError):
            # A renamed file must still have one semantically equivalent occurrence.
            pass
        candidate, record = map_endpoint(entry, fixed_inventory, unchanged_line=exact_line)
        records.append(
            {
                "role": entry["role"],
                "node_id": entry["node_id"],
                "vulnerable_descriptor": entry["descriptor"],
                **record,
                "fixed_descriptor": candidate["descriptor"] if candidate else None,
            }
        )
        if candidate is not None:
            value = copy.deepcopy(dict(entry))
            # Preserve the frozen identity and source/sink model contract across sides.
            value["descriptor"] = dict(candidate["descriptor"])
            value["fixed_instance_id"] = candidate["node_id"]
            mapped.append(value)
    return mapped, {
        "complete": len(mapped) == len(entries),
        "entries": records,
        "policy": "exact_line_path_callable_symbol_and_dataflow_slot_v3",
    }


def batch_endpoint_query(specifications: Sequence[Mapping[str, Any]]) -> str:
    """Execute the unchanged frozen predicates once, keeping each spec's rows separate."""
    predicates, choices = [], []
    for index, spec in enumerate(specifications):
        name = f"batchEndpoint{index}"
        predicates.append(
            common_predicates(spec["frozen_endpoints"], str(spec["candidate_cwe"])).replace(
                "predicate frozenEndpoint(", "predicate " + name + "(", 1
            )
        )
        choices.append(
            f"(specificationId = {json.dumps(str(spec['specification_id']))} "
            f"and {name}(role, endpointId, node))"
        )
    if not choices:
        raise ValueError("empty endpoint resolution batch")
    return (
        "/** @name MaxVera v3 batch endpoint resolution\n"
        " * @kind table\n * @id maxvera/v3/batch-endpoints\n */\nimport Grounding\n"
        + "\n".join(predicates)
        + "\nfrom string specificationId, string role, string endpointId, V2Node node\nwhere "
        + "\n or ".join(choices)
        + "\nselect specificationId, role, endpointId, node as resolved_node,\n"
        " node.getLocation().getFile().getRelativePath() as file,\n"
        " node.getLocation().getStartLine() as line\n"
    )


def batch_endpoints(
    binary: Path,
    database: Path,
    directory: Path,
    pack: Path,
    specifications: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    before_query: Callable[[], None],
) -> dict[str, list[dict[str, str]]]:
    source = batch_endpoint_query(specifications)
    identity = {
        "query_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "database_metadata_sha256": sha256_file(database / "codeql-database.yml"),
        "source_archive_sha256": sha256_file(database / "src.zip"),
    }
    checkpoint = directory / "batch_endpoints.json"
    if checkpoint.is_file():
        saved = json.loads(checkpoint.read_text())
        if saved["identity"] != identity:
            raise ValueError("batch endpoint checkpoint provenance changed")
        rows = saved["rows"]
    else:
        query = (
            pack
            / "generated"
            / (directory.parent.name + "_" + directory.name + "_batch_endpoints.ql")
        )
        query.parent.mkdir(parents=True, exist_ok=True)
        query.write_text(source)
        rows = query_csv(
            binary,
            database,
            query,
            directory / "batch_endpoints",
            policy,
            before_query,
            entity_ids=True,
        )
        atomic_json(checkpoint, {"identity": identity, "rows": rows})
    expected = {str(spec["specification_id"]) for spec in specifications}
    if any(row["specificationId"] not in expected for row in rows):
        raise ValueError("batch resolution returned an unknown specification")
    return {
        spec_id: [
            {k: v for k, v in row.items() if k != "specificationId"}
            for row in rows
            if row["specificationId"] == spec_id
        ]
        for spec_id in expected
    }


def _side(
    binary: Path,
    database: Path,
    directory: Path,
    pack: Path,
    specification: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    remaining: int,
    before_query: Callable[[], None],
    endpoint_rows: Sequence[Mapping[str, str]] | None = None,
) -> tuple[dict[str, Any], int]:
    if remaining < 1:
        raise ValueError("verification query budget exhausted")
    for entry in entries:
        descriptor = entry["descriptor"]
        digest, _ = archive_source(database / "src.zip", descriptor["file"])
        if digest != descriptor["source_sha256"]:
            raise ValueError("database source no longer matches the frozen endpoint descriptor")
    directory.mkdir(parents=True, exist_ok=True)
    query = (
        pack
        / "generated"
        / (specification["specification_id"] + "_" + directory.name + "_endpoints.ql")
    )
    query.parent.mkdir(parents=True, exist_ok=True)
    query.write_text(endpoint_query(specification, entries))
    rows = (
        list(endpoint_rows)
        if endpoint_rows is not None
        else query_csv(
            binary, database, query, directory / "endpoints", policy, before_query, entity_ids=True
        )
    )
    result: dict[str, Any] = {
        "resolution_complete": resolution_complete(entries, rows),
        "endpoint_rows": rows,
        "path_count": 0,
        "paths": [],
        "query_completed": False,
    }
    used = int(endpoint_rows is None)
    if not result["resolution_complete"]:
        return result, used
    if remaining < used + 1:
        raise ValueError("verification path query budget exhausted")
    query = query.with_name(query.name.replace("_endpoints.ql", "_path.ql"))
    query.write_text(path_query(specification, entries))
    query_csv(binary, database, query, directory / "paths", policy, before_query)
    paths = _interpret_paths(
        binary,
        directory / "paths.bqrs",
        directory / "paths.sarif",
        specification_id=specification["specification_id"],
        max_paths=4,
    )
    result.update(
        {
            "path_count": len(paths),
            "paths": [[{"file": file, "line": line} for file, line in path] for path in paths],
            "query_completed": True,
        }
    )
    return result, used + 1


def phase11(
    root: Path,
    config: Mapping[str, Any],
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    phase10_relative: str,
    *,
    resume: bool = False,
    full: bool = False,
    fixed_preparation_relative: str | None = None,
) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("verifier v3 requires a separate evaluator process")
    upstream, lock = dependency(root, phase10_relative, selected, 10)
    upstream_manifest = json.loads((upstream / "manifest.json").read_text())
    if upstream_manifest["dependencies"].get("dry_run"):
        raise ValueError("verifier cannot consume a dry-run synthesis artifact")
    fixed_root = root / config["dataset"]["fixed_database_root"]
    fixed_lock: dict[str, Any] = {}
    if fixed_preparation_relative:
        prepared, fixed_lock = dependency(root, fixed_preparation_relative, selected, 0)
        preparation = json.loads((prepared / "preparation_manifest.json").read_text())
        if preparation.get("phase10_manifest_sha256") != lock["manifest_sha256"]:
            raise ValueError("fixed preparation is not bound to this synthesis run")
        fixed_root = root / preparation["database_root"]
        if not fixed_root.resolve().is_relative_to((root / "data/interim").resolve()):
            raise ValueError("fixed database root is outside data/interim")
        if sha256_file(fixed_root / "preparation_manifest.json") != sha256_file(
            prepared / "preparation_manifest.json"
        ):
            raise ValueError("fixed database preparation manifest changed")
        for database_record in read_jsonl(prepared / "databases.jsonl"):
            if database_record["project_id"] not in selected or any(
                sha256_file(fixed_root / database_record["project_id"] / filename)
                != database_record[field]
                for filename, field in (
                    ("src.zip", "source_archive_sha256"),
                    ("codeql-database.yml", "metadata_sha256"),
                )
            ):
                raise ValueError("fixed database provenance changed")
    preparation = json.loads((fixed_root / "preparation_manifest.json").read_text())
    if (
        preparation.get("development_only") is not True
        or preparation.get("locked_test_prepared") is not False
        or preparation.get("identity_mapping_persisted") is not False
        or preparation.get("development_split_sha256")
        != config["dataset"]["development_split_sha256"]
        or preparation.get("status_sha256") != sha256_file(fixed_root / "build_status.jsonl")
        or preparation.get("preparation_complete") is not True
    ):
        raise ValueError("fixed databases do not satisfy the opaque development-only contract")
    run = Run(
        root,
        "results/verification/v3",
        run_id,
        11,
        config_path,
        selected,
        resume=resume,
        dependencies={
            "phase10": lock,
            "fixed_preparation": {
                "manifest_sha256": sha256_file(fixed_root / "preparation_manifest.json"),
                "status_sha256": sha256_file(fixed_root / "build_status.jsonl"),
                **fixed_lock,
            },
        },
        require_clean=full,
    )
    if fixed_preparation_relative:
        run.config["dataset"] = {
            **run.config["dataset"],
            "fixed_database_root": fixed_root.relative_to(root).as_posix(),
        }
    binary = codeql(root, config["codeql"])
    p10_status = {row["project_id"]: row for row in read_jsonl(upstream / "project_status.jsonl")}
    specifications = read_jsonl(upstream / "specifications.jsonl")
    for project in run.pending():
        if p10_status[project]["status"] != "SUCCESS":
            atomic_jsonl(
                run.work / "projects" / project / "verification_results.jsonl",
                [
                    {
                        "project_id": project,
                        "hypothesis_id": specification["hypothesis_id"],
                        "specification_id": specification["specification_id"],
                        "candidate_cwe": specification["candidate_cwe"],
                        "verification_version": "semantic-differential-verifier-v3",
                        "status": "UNVERIFIED_UPSTREAM_ANALYSIS_FAILURE",
                        "vulnerable": None,
                        "fixed": None,
                        "llm_calls": 0,
                        "llm_tokens": 0,
                    }
                    for specification in specifications
                    if specification["project_id"] == project
                ],
            )
            run.status(project, "ANALYSIS_FAILED", "inherited Phase 10 analysis miss")
            continue
        project_specs = [row for row in specifications if row["project_id"] == project]
        vulnerable_db = root / config["dataset"]["vulnerable_database_root"] / project
        fixed_db = fixed_root / project
        attempts_path = run.work / "projects" / project / "query_attempts.jsonl"
        attempts = read_jsonl(attempts_path)
        used = len(attempts)

        def before_query(
            attempt_rows: list[dict[str, Any]] = attempts,
            attempt_file: Path = attempts_path,
            project_id: str = project,
        ) -> None:
            nonlocal used
            if used >= int(config["verification"]["max_query_invocations_per_project"]):
                raise ValueError("project verification query budget exhausted")
            used += 1
            attempt_rows.append({"project_id": project_id, "query_ordinal": used})
            atomic_jsonl(attempt_file, attempt_rows)

        fixed_inventory: list[dict[str, Any]] | None = None
        fixed_endpoint_batch: dict[str, list[dict[str, str]]] | None = None
        results = read_jsonl(run.work / "projects" / project / "verification_results.jsonl")
        completed_ids = {result["specification_id"] for result in results}
        pending_specs = [s for s in project_specs if s["specification_id"] not in completed_ids]
        endpoint_batch = None
        if pending_specs:
            try:
                endpoint_batch = batch_endpoints(
                    binary,
                    vulnerable_db,
                    run.work / "projects" / project,
                    run.work / "query_pack",
                    project_specs,
                    config["codeql"],
                    before_query,
                )
            except (
                OSError,
                ValueError,
                RuntimeError,
                KeyError,
                subprocess.TimeoutExpired,
            ) as error:
                # Individual queries remain fail-closed if batching cannot complete.
                atomic_json(
                    run.work / "projects" / project / "batch_endpoint_failure.json",
                    {"reason": str(error)},
                )
        for specification in project_specs:
            if specification["specification_id"] in completed_ids:
                continue
            record: dict[str, Any] = {
                "project_id": project,
                "hypothesis_id": specification["hypothesis_id"],
                "specification_id": specification["specification_id"],
                "candidate_cwe": specification["candidate_cwe"],
                "verification_version": "semantic-differential-verifier-v3",
                "vulnerable": None,
                "fixed": None,
                "llm_calls": 0,
                "llm_tokens": 0,
            }
            try:
                remaining = int(config["verification"]["max_query_invocations_per_project"]) - used
                frozen = specification["frozen_endpoints"]
                if not frozen:
                    raise ValueError("specification has no frozen semantic endpoint bindings")
                directory = run.work / "query_results" / project / specification["specification_id"]
                vulnerable, _count = _side(
                    binary,
                    vulnerable_db,
                    directory / "vulnerable",
                    run.work / "query_pack",
                    specification,
                    frozen,
                    config["codeql"],
                    remaining,
                    before_query,
                    endpoint_rows=(
                        endpoint_batch[specification["specification_id"]]
                        if endpoint_batch is not None
                        else None
                    ),
                )
                record["vulnerable"] = vulnerable
                if (
                    vulnerable["resolution_complete"]
                    and vulnerable["path_count"]
                    and (fixed_db / "codeql-database.yml").is_file()
                ):
                    if fixed_inventory is None:
                        if used >= int(config["verification"]["max_query_invocations_per_project"]):
                            raise ValueError("fixed inventory query budget exhausted")
                        fixed_inventory, provenance = endpoint_inventory(
                            project,
                            fixed_db,
                            binary,
                            run.work / "query_pack",
                            run.work / "fixed_inventory" / project,
                            config["codeql"],
                            before_query,
                        )
                        atomic_jsonl(
                            run.work / "fixed_inventory" / project / "endpoints.jsonl",
                            fixed_inventory,
                        )
                        atomic_json(
                            run.work / "fixed_inventory" / project / "provenance.json", provenance
                        )
                        batch_specs = []
                        for candidate in project_specs:
                            candidate_entries, candidate_mapping = map_frozen_entries(
                                candidate["frozen_endpoints"],
                                fixed_inventory,
                                vulnerable_db / "src.zip",
                                fixed_db / "src.zip",
                            )
                            if candidate_mapping["complete"]:
                                batch_specs.append(
                                    {**candidate, "frozen_endpoints": candidate_entries}
                                )
                        if batch_specs:
                            try:
                                fixed_endpoint_batch = batch_endpoints(
                                    binary,
                                    fixed_db,
                                    run.work / "fixed_inventory" / project / "resolution",
                                    run.work / "query_pack",
                                    batch_specs,
                                    config["codeql"],
                                    before_query,
                                )
                            except (
                                OSError,
                                ValueError,
                                RuntimeError,
                                KeyError,
                                subprocess.TimeoutExpired,
                            ) as error:
                                atomic_json(
                                    run.work / "fixed_inventory" / project / "batch_failure.json",
                                    {"reason": str(error)},
                                )
                    mapped, mapping = map_frozen_entries(
                        frozen, fixed_inventory, vulnerable_db / "src.zip", fixed_db / "src.zip"
                    )
                    fixed: dict[str, Any] = {
                        "mapping_complete": mapping["complete"],
                        "endpoint_mapping": mapping,
                        "resolution_complete": False,
                        "path_count": None,
                        "query_completed": False,
                    }
                    if mapping["complete"]:
                        remaining = (
                            int(config["verification"]["max_query_invocations_per_project"]) - used
                        )
                        side, _count = _side(
                            binary,
                            fixed_db,
                            directory / "fixed",
                            run.work / "query_pack",
                            specification,
                            mapped,
                            config["codeql"],
                            remaining,
                            before_query,
                            endpoint_rows=(
                                fixed_endpoint_batch[specification["specification_id"]]
                                if fixed_endpoint_batch is not None
                                else None
                            ),
                        )
                        fixed.update(side)
                    record["fixed"] = fixed
                record["status"] = differential_status(vulnerable, record["fixed"])
            except (
                OSError,
                ValueError,
                RuntimeError,
                KeyError,
                subprocess.TimeoutExpired,
            ) as error:
                record.update(
                    {"status": "UNVERIFIED_QUERY_OR_BUDGET_FAILURE", "reason": str(error)}
                )
            results.append(record)
            atomic_jsonl(run.work / "projects" / project / "verification_results.jsonl", results)
        run.status(
            project,
            "SUCCESS",
            "every specification has a path or explicit unverified state",
            specifications=len(results),
            query_invocations=used,
            verified=sum(row["status"] == "VERIFIED_DIFFERENTIAL" for row in results),
        )
    results = [
        row
        for project in selected
        for row in read_jsonl(run.work / "projects" / project / "verification_results.jsonl")
    ]
    atomic_jsonl(run.work / "verification_results.jsonl", results)
    delta_nodes, delta_edges = evidence_delta(results, run_id)
    p9_relative = str(upstream_manifest["dependencies"]["phase9"]["run_root"])
    p9 = root / p9_relative
    if cycle_nodes(
        read_jsonl(p9 / "useg/nodes.jsonl") + delta_nodes,
        read_jsonl(p9 / "useg/edges.jsonl") + delta_edges,
    ):
        raise ValueError("verifier v3 evidence update introduces a cycle")
    atomic_jsonl(run.work / "useg_delta/nodes.jsonl", delta_nodes)
    atomic_jsonl(run.work / "useg_delta/edges.jsonl", delta_edges)
    return run.finalize(
        {
            "verification_version": "semantic-differential-verifier-v3",
            "specifications": len(results),
            "status_counts": dict(sorted(Counter(row["status"] for row in results).items())),
            "verified_findings": sum(row["status"] == "VERIFIED_DIFFERENTIAL" for row in results),
            "query_invocations": sum(row.get("query_invocations", 0) for row in run.statuses),
            "llm_calls": 0,
        }
    )


def evidence_delta(
    results: Sequence[Mapping[str, Any]],
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for result in results:
        spec_id, project = result["specification_id"], result["project_id"]
        node_id = identifier("evr3", [run_id, spec_id])
        provenance = {
            "phase": 11,
            "run_id": run_id,
            "specification_id": spec_id,
            "producer": "semantic-differential-verifier-v3",
        }
        nodes.append(
            {
                "schema_version": 2,
                "node_id": node_id,
                "layer": "evidence",
                "kind": "VERIFICATION_RESULT",
                "project_id": project,
                "analysis_iteration": 1,
                "properties": {
                    "status": result["status"],
                    "specification_id": spec_id,
                    "candidate_cwe": result["candidate_cwe"],
                },
                "provenance": provenance,
                "confidence_components": [],
            }
        )
        hypothesis = identifier("evh2", result["hypothesis_id"])
        if result["status"] == "VERIFIED_DIFFERENTIAL":
            edges.append(
                {
                    "edge_id": identifier("uve3", [hypothesis, node_id, "VERIFIED_BY"]),
                    "source_id": hypothesis,
                    "target_id": node_id,
                    "kind": "VERIFIED_BY",
                    "project_id": project,
                    "analysis_iteration": 1,
                    "provenance": provenance,
                }
            )
        for index, path in enumerate((result.get("vulnerable") or {}).get("paths", [])):
            path_id = identifier("evp3", [run_id, spec_id, index, path])
            nodes.append(
                {
                    "schema_version": 2,
                    "node_id": path_id,
                    "layer": "evidence",
                    "kind": "TAINT_PATH",
                    "project_id": project,
                    "analysis_iteration": 1,
                    "properties": {
                        "version": "vulnerable",
                        "path": path,
                        "verification_status": result["status"],
                    },
                    "provenance": provenance,
                    "confidence_components": [],
                }
            )
            edges.append(
                {
                    "edge_id": identifier("uve3", [path_id, hypothesis, "SUPPORTS"]),
                    "source_id": path_id,
                    "target_id": hypothesis,
                    "kind": "SUPPORTS",
                    "project_id": project,
                    "analysis_iteration": 1,
                    "provenance": provenance,
                }
            )
    return sorted(nodes, key=lambda node: node["node_id"]), sorted(
        edges, key=lambda edge: edge["edge_id"]
    )
