"""Build the deterministic Phase 9 cross-layer Evidence Graph and USEG."""

from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from src.graphs.evidence.model import (
    EVIDENCE_NODE_KINDS,
    cycle_nodes,
    evidence_node,
    graph_digest,
    reference_node,
    sort_edges,
    sort_nodes,
    useg_edge,
)
from src.reproduction.common import read_jsonl


def _checksum_index(run_root: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        index[relative] = digest
    return index


def _artifact_provenance(
    *,
    phase: int,
    run_id: str,
    artifact: str,
    artifact_sha256: str,
    record_id: str,
    producer: str,
    tool_call_id: str | None = None,
) -> dict[str, Any]:
    provenance: dict[str, Any] = {
        "source_phase": phase,
        "source_run_id": run_id,
        "artifact": artifact,
        "artifact_sha256": artifact_sha256,
        "record_id": record_id,
        "producer": producer,
    }
    if tool_call_id is not None:
        provenance["tool_call_id"] = tool_call_id
    return provenance


def _mapping_provenance(config_sha256: str, rule: str, mapping_version: str) -> dict[str, Any]:
    return _artifact_provenance(
        phase=9,
        run_id="phase9-mapping-policy",
        artifact="configs/experiments/phase9_useg.yaml",
        artifact_sha256=config_sha256,
        record_id=rule,
        producer=mapping_version,
    )


class UsegStore:
    """Deduplicate graph facts and retain project membership for shared references."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.project_nodes: dict[str, set[str]] = defaultdict(set)
        self.project_edges: dict[str, set[str]] = defaultdict(set)

    def add_node(self, record: Mapping[str, Any], *, project_id: str) -> str:
        identifier = str(record["node_id"])
        candidate = dict(record)
        existing = self.nodes.get(identifier)
        if existing is not None and existing != candidate:
            raise ValueError(f"conflicting Phase 9 node identity: {identifier}")
        self.nodes.setdefault(identifier, candidate)
        self.project_nodes[project_id].add(identifier)
        return identifier

    def add_edge(self, record: Mapping[str, Any], *, project_id: str) -> str:
        identifier = str(record["edge_id"])
        candidate = dict(record)
        existing = self.edges.get(identifier)
        if existing is not None and existing != candidate:
            raise ValueError(f"conflicting Phase 9 edge identity: {identifier}")
        self.edges.setdefault(identifier, candidate)
        self.project_edges[project_id].add(identifier)
        return identifier

    def merge(self, other: UsegStore, *, project_id: str) -> None:
        for record in other.nodes.values():
            self.add_node(record, project_id=project_id)
        for record in other.edges.values():
            self.add_edge(record, project_id=project_id)


def _program_reference(
    node: Mapping[str, Any], *, artifact: str, artifact_sha256: str, run_id: str, iteration: int
) -> dict[str, Any]:
    upstream = cast(Mapping[str, Any], node["provenance"])
    query_sha = str(upstream.get("query_sha256", ""))
    provenance = _artifact_provenance(
        phase=7,
        run_id=run_id,
        artifact=artifact,
        artifact_sha256=artifact_sha256,
        record_id=str(node["node_id"]),
        producer=f"CodeQL {upstream.get('tool_version', '')}".strip(),
        tool_call_id=f"codeql-query:{query_sha}",
    )
    return reference_node(
        node_id=str(node["node_id"]),
        layer="program",
        project_id=str(node["project_id"]),
        properties={
            "external_kind": str(node["kind"]),
            "subkind": str(node["subkind"]),
            "symbol": str(node["symbol"]),
            "type_name": str(node["type_name"]),
            "location": dict(cast(Mapping[str, Any], node["location"])),
            "upstream_provenance": dict(upstream),
        },
        confidence_components=[],
        provenance=[provenance],
        analysis_iteration=iteration,
    )


def _security_reference(
    node: Mapping[str, Any], *, artifact_sha256: str, run_id: str, iteration: int
) -> dict[str, Any]:
    return reference_node(
        node_id=str(node["node_id"]),
        layer="security",
        project_id=None,
        properties={
            "external_kind": str(node["kind"]),
            "identity": str(node["identity"]),
            "label": str(node["label"]),
            "fact_properties": dict(cast(Mapping[str, Any], node["properties"])),
            "knowledge_provenance": [
                dict(item) for item in cast(Sequence[Mapping[str, Any]], node["provenance"])
            ],
        },
        confidence_components=[
            {
                "name": "security_fact_confidence",
                "value": float(node["confidence"]),
                "basis": str(node["node_id"]),
            }
        ],
        provenance=[
            _artifact_provenance(
                phase=8,
                run_id=run_id,
                artifact="deterministic/nodes.jsonl",
                artifact_sha256=artifact_sha256,
                record_id=str(node["node_id"]),
                producer="phase8-security-kg-v1",
            )
        ],
        analysis_iteration=iteration,
    )


def _line_candidates(
    by_file: Mapping[str, Sequence[Mapping[str, Any]]],
    location: Mapping[str, Any],
    *,
    maximum: int,
    prefer_exact_symbol: bool,
) -> list[Mapping[str, Any]]:
    file_name = str(location.get("file", ""))
    line = int(location.get("line", 0))
    symbol = str(location.get("symbol") or "").casefold()
    candidates = []
    for node in by_file.get(file_name, []):
        node_location = cast(Mapping[str, Any], node["location"])
        if int(node_location["start_line"]) <= line <= int(node_location["end_line"]):
            candidates.append(node)
    if not candidates:
        return []

    def exact(item: Mapping[str, Any]) -> bool:
        return bool(symbol) and symbol in {
            str(item.get("symbol", "")).casefold(),
            str(item.get("type_name", "")).casefold(),
        }

    if prefer_exact_symbol and any(exact(item) for item in candidates):
        candidates = [item for item in candidates if exact(item)]
    kind_order = {"EXPR": 0, "STMT": 1, "CALLABLE": 2, "TYPE": 3}
    return sorted(
        candidates,
        key=lambda item: (
            0 if exact(item) else 1,
            int(cast(Mapping[str, Any], item["location"])["end_line"])
            - int(cast(Mapping[str, Any], item["location"])["start_line"]),
            kind_order.get(str(item["kind"]), 9),
            str(item["node_id"]),
        ),
    )[:maximum]


def _security_api_matches(
    *,
    cwe_node_id: str,
    role: str,
    symbol: str,
    security_nodes: Mapping[str, Mapping[str, Any]],
    security_adjacency: Mapping[tuple[str, str], Sequence[str]],
    maximum: int,
) -> list[Mapping[str, Any]]:
    relation = {"source": "HAS_SOURCE", "sink": "HAS_SINK", "sanitizer": "HAS_SANITIZER"}.get(
        role
    )
    normalized = symbol.casefold()
    if relation is None or not normalized:
        return []
    matched: list[Mapping[str, Any]] = []
    for target_id in security_adjacency.get((cwe_node_id, relation), []):
        target = security_nodes[target_id]
        properties = cast(Mapping[str, Any], target["properties"])
        if normalized in {
            str(properties.get("callable", "")).casefold(),
            str(properties.get("type", "")).casefold(),
        }:
            matched.append(target)
    return sorted(matched, key=lambda item: str(item["node_id"]))[:maximum]


def _add_mapping_edge(
    store: UsegStore,
    *,
    kind: str,
    source_id: str,
    target_id: str,
    project_id: str,
    properties: Mapping[str, Any],
    rule: str,
    mapping_version: str,
    config_sha256: str,
    iteration: int,
) -> None:
    store.add_edge(
        useg_edge(
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            project_id=project_id,
            properties=properties,
            provenance=[_mapping_provenance(config_sha256, rule, mapping_version)],
            analysis_iteration=iteration,
        ),
        project_id=project_id,
    )


def _build_project(
    *,
    project_id: str,
    hypotheses: Sequence[Mapping[str, Any]],
    program_nodes: Sequence[Mapping[str, Any]],
    program_edges: Sequence[Mapping[str, Any]],
    security_nodes: Mapping[str, Mapping[str, Any]],
    cwe_nodes: Mapping[str, Mapping[str, Any]],
    security_adjacency: Mapping[tuple[str, str], Sequence[str]],
    experiment: Mapping[str, Any],
    config_sha256: str,
    phase6_hypotheses_sha: str,
    phase7_nodes_artifact: str,
    phase7_nodes_sha: str,
    phase7_edges_artifact: str,
    phase7_edges_sha: str,
    phase8_nodes_sha: str,
) -> tuple[UsegStore, dict[str, Any]]:
    dependencies = cast(Mapping[str, Any], experiment["development_dependencies"])
    phase6_run = str(cast(Mapping[str, Any], dependencies["phase6"])["run_id"])
    phase7_run = str(cast(Mapping[str, Any], dependencies["phase7"])["run_id"])
    phase8_run = str(cast(Mapping[str, Any], dependencies["phase8"])["run_id"])
    mapping = cast(Mapping[str, Any], experiment["mapping"])
    mapping_version = str(mapping["version"])
    iteration = int(experiment["analysis_iteration"])
    store = UsegStore()
    program_by_id = {str(node["node_id"]): node for node in program_nodes}
    by_file: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for node in program_nodes:
        location = cast(Mapping[str, Any], node["location"])
        by_file[str(location["file"])].append(node)
    taint_edges = [edge for edge in program_edges if edge.get("kind") == "TAINT_CANDIDATE"]
    phase6_producer = "phase6-family-balanced-v2/static_rules"
    location_assertions = 0
    program_mapped_assertions = 0
    security_mapped_assertions = 0
    hypothesis_ids: set[str] = set()
    assertion_ids: set[str] = set()
    finding_ids: set[str] = set()
    path_ids: set[str] = set()

    for hypothesis in sorted(hypotheses, key=lambda item: str(item["hypothesis_id"])):
        hypothesis_id = str(hypothesis["hypothesis_id"])
        candidate_cwes = [str(value) for value in cast(Sequence[Any], hypothesis["candidate_cwe"])]
        if len(candidate_cwes) != 1 or candidate_cwes[0] not in cwe_nodes:
            raise ValueError(f"Phase 9 requires one known candidate CWE: {hypothesis_id}")
        cwe_id = candidate_cwes[0]
        cwe = cwe_nodes[cwe_id]
        phase6_provenance = _artifact_provenance(
            phase=6,
            run_id=phase6_run,
            artifact="hypotheses.jsonl",
            artifact_sha256=phase6_hypotheses_sha,
            record_id=hypothesis_id,
            producer=phase6_producer,
        )
        hypothesis_record = evidence_node(
            kind="HYPOTHESIS",
            project_id=project_id,
            identity=hypothesis_id,
            properties={
                "upstream_hypothesis_id": hypothesis_id,
                "candidate_cwe": candidate_cwes,
                "generator": str(hypothesis["generator"]),
                "rank": int(hypothesis["rank"]),
                "ranking_version": str(hypothesis["ranking_version"]),
            },
            confidence_components=[
                {
                    "name": "phase6_hypothesis_score",
                    "value": float(hypothesis["score"]),
                    "basis": hypothesis_id,
                }
            ],
            provenance=[phase6_provenance],
            analysis_iteration=iteration,
        )
        hypothesis_node_id = store.add_node(hypothesis_record, project_id=project_id)
        hypothesis_ids.add(hypothesis_node_id)
        security_cwe = _security_reference(
            cwe, artifact_sha256=phase8_nodes_sha, run_id=phase8_run, iteration=iteration
        )
        cwe_node_id = store.add_node(security_cwe, project_id=project_id)
        _add_mapping_edge(
            store,
            kind="MATCHES",
            source_id=hypothesis_node_id,
            target_id=cwe_node_id,
            project_id=project_id,
            properties={"match_type": "exact_candidate_cwe"},
            rule="security_cwe_rule",
            mapping_version=mapping_version,
            config_sha256=config_sha256,
            iteration=iteration,
        )

        matched_program_ids: set[str] = set()
        for location_index, location_value in enumerate(
            cast(Sequence[Mapping[str, Any]], hypothesis.get("locations", [])), start=1
        ):
            location = dict(location_value)
            location_assertions += 1
            assertion_identity = f"{hypothesis_id}:location:{location_index}"
            assertion = evidence_node(
                kind="ASSERTION",
                project_id=project_id,
                identity=assertion_identity,
                properties={"assertion_type": "source_location", **location},
                confidence_components=[
                    {
                        "name": "inherited_phase6_hypothesis_score",
                        "value": float(hypothesis["score"]),
                        "basis": hypothesis_id,
                    }
                ],
                provenance=[phase6_provenance],
                analysis_iteration=iteration,
            )
            assertion_node_id = store.add_node(assertion, project_id=project_id)
            assertion_ids.add(assertion_node_id)
            _add_mapping_edge(
                store,
                kind="DERIVED_FROM",
                source_id=assertion_node_id,
                target_id=hypothesis_node_id,
                project_id=project_id,
                properties={"derivation": "phase6_location_assertion"},
                rule="location_assertion_projection",
                mapping_version=mapping_version,
                config_sha256=config_sha256,
                iteration=iteration,
            )
            matched_program = _line_candidates(
                by_file,
                location,
                maximum=int(mapping["max_program_matches_per_assertion"]),
                prefer_exact_symbol=bool(mapping["prefer_exact_symbol"]),
            )
            if matched_program:
                program_mapped_assertions += 1
            for program_node in matched_program:
                program_reference = _program_reference(
                    program_node,
                    artifact=phase7_nodes_artifact,
                    artifact_sha256=phase7_nodes_sha,
                    run_id=phase7_run,
                    iteration=iteration,
                )
                program_node_id = store.add_node(program_reference, project_id=project_id)
                matched_program_ids.add(program_node_id)
                _add_mapping_edge(
                    store,
                    kind="MATCHES",
                    source_id=assertion_node_id,
                    target_id=program_node_id,
                    project_id=project_id,
                    properties={"match_type": "same_file_line_containment"},
                    rule="program_location_rule",
                    mapping_version=mapping_version,
                    config_sha256=config_sha256,
                    iteration=iteration,
                )
            api_matches = _security_api_matches(
                cwe_node_id=str(cwe["node_id"]),
                role=str(location.get("role", "")),
                symbol=str(location.get("symbol") or ""),
                security_nodes=security_nodes,
                security_adjacency=security_adjacency,
                maximum=int(mapping["max_security_api_matches_per_assertion"]),
            )
            if api_matches:
                security_mapped_assertions += 1
            for api_node in api_matches:
                api_reference = _security_reference(
                    api_node,
                    artifact_sha256=phase8_nodes_sha,
                    run_id=phase8_run,
                    iteration=iteration,
                )
                api_node_id = store.add_node(api_reference, project_id=project_id)
                _add_mapping_edge(
                    store,
                    kind="MATCHES",
                    source_id=assertion_node_id,
                    target_id=api_node_id,
                    project_id=project_id,
                    properties={
                        "match_type": "exact_symbol_to_callable_or_type_with_cwe_role",
                        "role": str(location.get("role", "")),
                    },
                    rule="security_api_rule",
                    mapping_version=mapping_version,
                    config_sha256=config_sha256,
                    iteration=iteration,
                )

        for precondition_index, text in enumerate(
            cast(Sequence[Any], hypothesis.get("preconditions", [])), start=1
        ):
            assertion_identity = f"{hypothesis_id}:precondition:{precondition_index}"
            assertion = evidence_node(
                kind="ASSERTION",
                project_id=project_id,
                identity=assertion_identity,
                properties={"assertion_type": "precondition", "text": str(text)},
                confidence_components=[
                    {
                        "name": "inherited_phase6_hypothesis_score",
                        "value": float(hypothesis["score"]),
                        "basis": hypothesis_id,
                    }
                ],
                provenance=[phase6_provenance],
                analysis_iteration=iteration,
            )
            assertion_node_id = store.add_node(assertion, project_id=project_id)
            assertion_ids.add(assertion_node_id)
            _add_mapping_edge(
                store,
                kind="DERIVED_FROM",
                source_id=assertion_node_id,
                target_id=hypothesis_node_id,
                project_id=project_id,
                properties={"derivation": "phase6_precondition_assertion"},
                rule="precondition_assertion_projection",
                mapping_version=mapping_version,
                config_sha256=config_sha256,
                iteration=iteration,
            )
            precondition_ids = list(
                security_adjacency.get((str(cwe["node_id"]), "HAS_PRECONDITION"), [])
            )[: int(mapping["max_precondition_matches_per_assertion"])]
            if precondition_ids:
                security_mapped_assertions += 1
            for precondition_id in precondition_ids:
                precondition_node = security_nodes[precondition_id]
                precondition_reference = _security_reference(
                    precondition_node,
                    artifact_sha256=phase8_nodes_sha,
                    run_id=phase8_run,
                    iteration=iteration,
                )
                target_id = store.add_node(precondition_reference, project_id=project_id)
                _add_mapping_edge(
                    store,
                    kind="MATCHES",
                    source_id=assertion_node_id,
                    target_id=target_id,
                    project_id=project_id,
                    properties={"match_type": "cwe_precondition_membership"},
                    rule="precondition_relation_rule",
                    mapping_version=mapping_version,
                    config_sha256=config_sha256,
                    iteration=iteration,
                )

        incident = [
            edge
            for edge in taint_edges
            if str(edge["source_id"]) in matched_program_ids
            or str(edge["target_id"]) in matched_program_ids
        ]
        incident = sorted(incident, key=lambda item: str(item["edge_id"]))[
            : int(mapping["max_taint_candidates_per_hypothesis"])
        ]
        for candidate in incident:
            candidate_id = str(candidate["edge_id"])
            upstream = cast(Mapping[str, Any], candidate["provenance"])
            candidate_provenance = _artifact_provenance(
                phase=7,
                run_id=phase7_run,
                artifact=phase7_edges_artifact,
                artifact_sha256=phase7_edges_sha,
                record_id=candidate_id,
                producer=f"CodeQL {upstream.get('tool_version', '')}".strip(),
                tool_call_id=f"codeql-query:{upstream.get('query_sha256', '')}",
            )
            finding = evidence_node(
                kind="CODEQL_FINDING",
                project_id=project_id,
                identity=f"taint-candidate:{candidate_id}",
                properties={
                    "finding_status": "unverified_candidate",
                    "final_finding": False,
                    "upstream_edge_id": candidate_id,
                    "upstream_edge_kind": "TAINT_CANDIDATE",
                },
                confidence_components=[],
                provenance=[candidate_provenance],
                analysis_iteration=iteration,
            )
            finding_node_id = store.add_node(finding, project_id=project_id)
            finding_ids.add(finding_node_id)
            for endpoint_role in ("source_id", "target_id"):
                endpoint_id = str(candidate[endpoint_role])
                program_node = program_by_id[endpoint_id]
                program_reference = _program_reference(
                    program_node,
                    artifact=phase7_nodes_artifact,
                    artifact_sha256=phase7_nodes_sha,
                    run_id=phase7_run,
                    iteration=iteration,
                )
                store.add_node(program_reference, project_id=project_id)
                _add_mapping_edge(
                    store,
                    kind="MATCHES",
                    source_id=finding_node_id,
                    target_id=endpoint_id,
                    project_id=project_id,
                    properties={"endpoint_role": endpoint_role.removesuffix("_id")},
                    rule="taint_candidate_endpoint_rule",
                    mapping_version=mapping_version,
                    config_sha256=config_sha256,
                    iteration=iteration,
                )
            path = evidence_node(
                kind="TAINT_PATH",
                project_id=project_id,
                identity=f"candidate-path:{candidate_id}",
                properties={
                    "path_status": "unverified_candidate",
                    "complete_path": False,
                    "ordered_program_node_ids": [
                        str(candidate["source_id"]),
                        str(candidate["target_id"]),
                    ],
                },
                confidence_components=[],
                provenance=[
                    candidate_provenance,
                    _mapping_provenance(
                        config_sha256, "taint_candidate_rule", mapping_version
                    ),
                ],
                analysis_iteration=iteration,
            )
            path_node_id = store.add_node(path, project_id=project_id)
            path_ids.add(path_node_id)
            _add_mapping_edge(
                store,
                kind="DERIVED_FROM",
                source_id=path_node_id,
                target_id=finding_node_id,
                project_id=project_id,
                properties={"derivation": "phase7_taint_candidate_edge"},
                rule="taint_candidate_rule",
                mapping_version=mapping_version,
                config_sha256=config_sha256,
                iteration=iteration,
            )
            _add_mapping_edge(
                store,
                kind="SUPPORTS",
                source_id=path_node_id,
                target_id=hypothesis_node_id,
                project_id=project_id,
                properties={"support_status": "structural_candidate_only"},
                rule="taint_candidate_hypothesis_support",
                mapping_version=mapping_version,
                config_sha256=config_sha256,
                iteration=iteration,
            )

    evidence_counts = Counter(
        str(node["kind"])
        for node in store.nodes.values()
        if node.get("layer") == "evidence"
    )
    summary = {
        "schema_version": 1,
        "project_id": project_id,
        "status": "SUCCESS",
        "hypotheses": len(hypothesis_ids),
        "assertions": len(assertion_ids),
        "location_assertions": location_assertions,
        "program_mapped_assertions": program_mapped_assertions,
        "security_mapped_assertions": security_mapped_assertions,
        "codeql_candidate_findings": len(finding_ids),
        "candidate_taint_paths": len(path_ids),
        "nodes": len(store.nodes),
        "edges": len(store.edges),
        "evidence_node_kinds": dict(sorted(evidence_counts.items())),
    }
    return store, summary


def _trace_audit(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    by_id = {str(node["node_id"]): node for node in nodes}
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        outgoing[str(edge["source_id"])].append(str(edge["target_id"]))

    def reachable(start: str) -> set[str]:
        seen = {start}
        queue = deque([start])
        while queue:
            source = queue.popleft()
            for target in outgoing.get(source, []):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen

    candidate_paths = [node for node in nodes if node.get("kind") == "TAINT_PATH"]
    candidate_paths_traceable = 0
    for candidate in candidate_paths:
        reached = [by_id[node_id] for node_id in reachable(str(candidate["node_id"]))]
        layers = {str(node["layer"]) for node in reached}
        if {"program", "security"} <= layers:
            candidate_paths_traceable += 1
    final_findings = [
        node
        for node in nodes
        if node.get("kind") == "CODEQL_FINDING"
        and cast(Mapping[str, Any], node["properties"]).get("final_finding") is True
    ]
    traceable_final = 0
    for finding in final_findings:
        reached = [by_id[node_id] for node_id in reachable(str(finding["node_id"]))]
        layers = {str(node["layer"]) for node in reached}
        has_tool_or_model_call = any(
            any("tool_call_id" in item or "model_call_id" in item for item in node["provenance"])
            for node in reached
        )
        if {"program", "security"} <= layers and has_tool_or_model_call:
            traceable_final += 1
    cycles = cycle_nodes(nodes, edges)
    roundtrip_lossless = all(
        json.loads(json.dumps(record, ensure_ascii=False, sort_keys=True)) == record
        for record in [*nodes, *edges]
    )
    status = "PASS"
    if cycles or candidate_paths_traceable != len(candidate_paths) or not roundtrip_lossless:
        status = "FAIL"
    if final_findings and traceable_final != len(final_findings):
        status = "FAIL"
    return {
        "schema_version": 1,
        "status": status,
        "cycles_detected": len(cycles),
        "cycle_node_sample": cycles[:20],
        "roundtrip_lossless": roundtrip_lossless,
        "candidate_taint_paths": len(candidate_paths),
        "candidate_paths_with_program_and_security_trace": candidate_paths_traceable,
        "final_findings": len(final_findings),
        "fully_traceable_final_findings": traceable_final,
        "final_finding_gate": "PASS" if final_findings else "PASS_NO_FINAL_FINDINGS_PHASE9",
    }


def build_useg(
    *,
    phase6_root: Path,
    phase7_root: Path,
    phase8_root: Path,
    experiment: Mapping[str, Any],
    config_sha256: str,
    selected_project_ids: Sequence[str],
) -> dict[str, Any]:
    dependencies = cast(Mapping[str, Any], experiment["development_dependencies"])
    phase6 = cast(Mapping[str, Any], dependencies["phase6"])
    phase8 = cast(Mapping[str, Any], dependencies["phase8"])
    phase6_hypotheses = read_jsonl(phase6_root / "hypotheses.jsonl")
    hypotheses_by_project: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for hypothesis in phase6_hypotheses:
        hypotheses_by_project[str(hypothesis["project_id"])].append(hypothesis)
    phase7_statuses = {
        str(row["project_id"]): row
        for row in read_jsonl(phase7_root / "project_status.jsonl")
    }
    phase7_checksums = _checksum_index(phase7_root)
    security_node_records = read_jsonl(phase8_root / "deterministic/nodes.jsonl")
    security_edge_records = read_jsonl(phase8_root / "deterministic/edges.jsonl")
    security_nodes = {str(node["node_id"]): node for node in security_node_records}
    cwe_nodes = {
        str(node["identity"]): node
        for node in security_node_records
        if node.get("kind") == "CWE"
    }
    security_adjacency: dict[tuple[str, str], list[str]] = defaultdict(list)
    for edge in security_edge_records:
        security_adjacency[(str(edge["source_id"]), str(edge["kind"]))].append(
            str(edge["target_id"])
        )
    for targets in security_adjacency.values():
        targets.sort()

    store = UsegStore()
    statuses: list[dict[str, Any]] = []
    project_summaries: list[dict[str, Any]] = []
    for project_id in selected_project_ids:
        upstream_status = phase7_statuses.get(project_id)
        if upstream_status is None:
            raise ValueError(f"Phase 7 has no final status for {project_id}")
        if upstream_status.get("status") != "SUCCESS":
            statuses.append(
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "status": "ANALYSIS_FAILED",
                    "reason": f"upstream Phase 7 failure: {upstream_status.get('reason', '')}",
                    "upstream_phase7_status": str(upstream_status.get("status")),
                }
            )
            project_summaries.append(
                {
                    "schema_version": 1,
                    "project_id": project_id,
                    "status": "ANALYSIS_FAILED",
                    "nodes": 0,
                    "edges": 0,
                }
            )
            continue
        nodes_artifact = f"graphs/{project_id}/nodes.jsonl"
        edges_artifact = f"graphs/{project_id}/edges.jsonl"
        if nodes_artifact not in phase7_checksums or edges_artifact not in phase7_checksums:
            raise ValueError(f"Phase 7 checksum index lacks graph for {project_id}")
        program_nodes = read_jsonl(phase7_root / nodes_artifact)
        program_edges = read_jsonl(phase7_root / edges_artifact)
        project_store, summary = _build_project(
            project_id=project_id,
            hypotheses=hypotheses_by_project.get(project_id, []),
            program_nodes=program_nodes,
            program_edges=program_edges,
            security_nodes=security_nodes,
            cwe_nodes=cwe_nodes,
            security_adjacency=security_adjacency,
            experiment=experiment,
            config_sha256=config_sha256,
            phase6_hypotheses_sha=str(phase6["hypotheses_sha256"]),
            phase7_nodes_artifact=nodes_artifact,
            phase7_nodes_sha=phase7_checksums[nodes_artifact],
            phase7_edges_artifact=edges_artifact,
            phase7_edges_sha=phase7_checksums[edges_artifact],
            phase8_nodes_sha=str(phase8["nodes_sha256"]),
        )
        store.merge(project_store, project_id=project_id)
        statuses.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": "SUCCESS",
                "reason": "Phase 9 cross-layer Evidence Graph materialized",
                "nodes": int(summary["nodes"]),
                "edges": int(summary["edges"]),
                "hypotheses": int(summary["hypotheses"]),
                "candidate_taint_paths": int(summary["candidate_taint_paths"]),
            }
        )
        project_summaries.append(summary)

    nodes = sort_nodes(list(store.nodes.values()))
    edges = sort_edges(list(store.edges.values()))
    trace_audit = _trace_audit(nodes, edges)
    status_counts = Counter(str(row["status"]) for row in statuses)
    node_layers = Counter(str(node["layer"]) for node in nodes)
    evidence_kinds = Counter(
        str(node["kind"]) for node in nodes if node.get("layer") == "evidence"
    )
    edge_kinds = Counter(str(edge["kind"]) for edge in edges)
    summary = {
        "schema_version": 1,
        "useg_version": str(experiment["useg_version"]),
        "analysis_iteration": int(experiment["analysis_iteration"]),
        "projects": len(selected_project_ids),
        "analysis_successes": int(status_counts.get("SUCCESS", 0)),
        "analysis_failures": int(status_counts.get("ANALYSIS_FAILED", 0)),
        "nodes": len(nodes),
        "edges": len(edges),
        "node_layers": dict(sorted(node_layers.items())),
        "evidence_node_kinds": dict(sorted(evidence_kinds.items())),
        "declared_evidence_node_kinds": sorted(EVIDENCE_NODE_KINDS),
        "edge_kinds": dict(sorted(edge_kinds.items())),
        "graph_sha256": graph_digest(nodes, edges),
        "trace_audit_status": str(trace_audit["status"]),
        "llm_calls": 0,
        "network_calls": 0,
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "statuses": statuses,
        "project_summaries": project_summaries,
        "summary": summary,
        "trace_audit": trace_audit,
    }
