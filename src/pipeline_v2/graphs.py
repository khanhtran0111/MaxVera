"""Semantic endpoint/callable Program Graph and grounded USEG v2."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.model import identifier, validate_descriptor
from src.pipeline_v2.runtime import Run, dependency
from src.reproduction.common import atomic_jsonl, read_jsonl


def program_graph(
    hypotheses: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    for hypothesis in hypotheses:
        project = hypothesis["project_id"]
        endpoint_ids: dict[str, str] = {}
        for role, field in (("source", "source_candidates"), ("sink", "sink_candidates")):
            if not hypothesis.get(field):
                raise ValueError("eligible hypothesis requires both grounded endpoint roles")
            endpoint = hypothesis[field][0]
            descriptor = endpoint["descriptor"]
            validate_descriptor(descriptor)
            if role not in endpoint["roles"] or not endpoint.get("provenance"):
                raise ValueError("endpoint role has no source-backed provenance")
            node_id = endpoint["node_id"]
            endpoint_ids[role] = node_id
            record = nodes.setdefault(
                node_id,
                {
                    "schema_version": 2,
                    "node_id": node_id,
                    "project_id": project,
                    "kind": "EXPR" if descriptor["dataflow_kind"] == "expr" else "PARAMETER",
                    "semantic_id": endpoint["semantic_id"],
                    "semantic_descriptor": dict(descriptor),
                    "enclosing_callable": descriptor["enclosing_callable"],
                    "symbol": descriptor["target_signature"] or descriptor["expression"],
                    "location": {
                        key: descriptor[key]
                        for key in ("file", "start_line", "start_column", "end_line", "end_column")
                    },
                    "endpoint_roles": list(endpoint["roles"]),
                    "models": list(endpoint["models"]),
                    "hypothesis_ids": [],
                    "provenance": dict(endpoint["provenance"]),
                },
            )
            if hypothesis["hypothesis_id"] not in record["hypothesis_ids"]:
                record["hypothesis_ids"].append(hypothesis["hypothesis_id"])
            callable_id = identifier(
                "call2", [project, descriptor["file"], descriptor["enclosing_callable"]]
            )
            nodes.setdefault(
                callable_id,
                {
                    "schema_version": 2,
                    "node_id": callable_id,
                    "project_id": project,
                    "kind": "CALLABLE",
                    "symbol": descriptor["enclosing_callable"],
                    "enclosing_callable": descriptor["enclosing_callable"],
                    "file": descriptor["file"],
                    "source_sha256": descriptor["source_sha256"],
                    "provenance": dict(endpoint["provenance"]),
                },
            )
            edge_id = identifier("pge2", ["ENCLOSED_BY", node_id, callable_id])
            edges[edge_id] = {
                "edge_id": edge_id,
                "project_id": project,
                "kind": "ENCLOSED_BY",
                "source_id": node_id,
                "target_id": callable_id,
                "provenance": dict(endpoint["provenance"]),
            }
        kind = (
            "TAINT_CANDIDATE"
            if hypothesis.get("evidence_kind") == "GLOBAL_TAINT_CANDIDATE"
            else "CALL_BOUNDARY_CANDIDATE"
        )
        edge_id = identifier(
            "pge2",
            [kind, endpoint_ids["source"], endpoint_ids["sink"], hypothesis["candidate_cwe"]],
        )
        edges[edge_id] = {
            "edge_id": edge_id,
            "project_id": project,
            "kind": kind,
            "source_id": endpoint_ids["source"],
            "target_id": endpoint_ids["sink"],
            "candidate_cwe": hypothesis["candidate_cwe"],
            "status": "UNVERIFIED_CANDIDATE",
            "provenance": hypothesis["provenance"],
        }
    return [nodes[key] for key in sorted(nodes)], [edges[key] for key in sorted(edges)]


def phase7(
    root: Path,
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    phase6_relative: str,
    *,
    resume: bool = False,
    full: bool = False,
) -> Path:
    upstream, lock = dependency(root, phase6_relative, selected, 6)
    run = Run(
        root,
        "results/graphs/program_v2",
        run_id,
        7,
        config_path,
        selected,
        resume=resume,
        dependencies={"phase6": lock},
        require_clean=full,
    )
    statuses = {row["project_id"]: row for row in read_jsonl(upstream / "project_status.jsonl")}
    for project in run.pending():
        if statuses[project]["status"] != "SUCCESS":
            run.status(project, "ANALYSIS_FAILED", "inherited Phase 6 analysis failure")
            continue
        try:
            hypothesis_path = upstream / "projects" / project / "hypotheses.jsonl"
            if not hypothesis_path.is_file():
                raise ValueError("completed discovery is missing its hypothesis artifact")
            hypotheses = read_jsonl(hypothesis_path)
            nodes, edges = program_graph(hypotheses)
            empty_success = run.config.get("execution", {}).get("empty_discovery_is_success", False)
            if not nodes and not empty_success:
                raise ValueError("NO_GROUNDED_HYPOTHESIS: no nonempty semantic program graph")
            directory = run.work / "graphs" / project
            atomic_jsonl(directory / "nodes.jsonl", nodes)
            atomic_jsonl(directory / "edges.jsonl", edges)
            run.status(
                project,
                "SUCCESS",
                "semantic endpoint/callable graph built"
                if nodes
                else "NO_CANDIDATES: discovery completed with no grounded hypothesis",
                analysis_outcome="CANDIDATES" if nodes else "NO_CANDIDATES",
                hypotheses=len(hypotheses),
                nodes=len(nodes),
                edges=len(edges),
            )
        except (KeyError, ValueError) as error:
            run.status(project, "ANALYSIS_FAILED", str(error))
    return run.finalize(
        {
            "graph_version": "typed-endpoint-callable-graph-v2",
            "scope": "selected grounded source/sink endpoints and enclosing callables",
            "nodes": sum(row.get("nodes", 0) for row in run.statuses),
            "edges": sum(row.get("edges", 0) for row in run.statuses),
            "llm_calls": 0,
        }
    )


def useg_project(
    hypotheses: Sequence[Mapping[str, Any]],
    program_nodes: Sequence[Mapping[str, Any]],
    cwe_facts: Mapping[str, Mapping[str, Any]],
    kg_provenance: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    program = {node["node_id"]: node for node in program_nodes}
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(
        node_id: str,
        layer: str,
        kind: str,
        project: str | None,
        properties: Mapping[str, Any],
        provenance: object,
    ) -> None:
        nodes[node_id] = {
            "schema_version": 2,
            "useg_version": "grounded-useg-v2",
            "analysis_iteration": 0,
            "node_id": node_id,
            "layer": layer,
            "kind": kind,
            "project_id": project,
            "properties": dict(properties),
            "provenance": provenance,
            "confidence_components": [],
        }

    def edge(source: str, target: str, kind: str, project: str, provenance: object) -> None:
        node_id = identifier("uve2", [source, target, kind])
        edges[node_id] = {
            "edge_id": node_id,
            "source_id": source,
            "target_id": target,
            "project_id": project,
            "kind": kind,
            "provenance": provenance,
            "analysis_iteration": 0,
        }

    for hypothesis in hypotheses:
        project, hyp_id = hypothesis["project_id"], hypothesis["hypothesis_id"]
        cwe = hypothesis["candidate_cwe"][0]
        if cwe not in cwe_facts:
            raise ValueError("hypothesis CWE has no pinned Security KG fact")
        cwe_node = cwe_facts[cwe]
        add_node(
            cwe_node["node_id"],
            "security",
            "SECURITY_NODE",
            None,
            {"external_kind": "CWE", "identity": cwe, "candidate_cwe": [cwe]},
            kg_provenance,
        )
        hyp_node = identifier("evh2", hyp_id)
        add_node(
            hyp_node,
            "evidence",
            "HYPOTHESIS",
            project,
            {
                "upstream_hypothesis_id": hyp_id,
                "candidate_cwe": [cwe],
                "rank": hypothesis["rank"],
                "grounding_version": 2,
                "score": hypothesis["score"],
            },
            hypothesis["provenance"],
        )
        endpoint_assertions: list[str] = []
        for role, field in (("source", "source_candidates"), ("sink", "sink_candidates")):
            endpoint = hypothesis[field][0]
            descriptor = endpoint["descriptor"]
            validate_descriptor(descriptor)
            if endpoint["node_id"] not in program or role not in endpoint["roles"]:
                raise ValueError("USEG endpoint is not grounded in the Program Graph")
            if role == "sink" and not any(
                model["role"] == "sink" and model["candidate_cwe"] == cwe
                for model in endpoint["models"]
            ):
                raise ValueError("sink model does not ground the hypothesis CWE")
            common = {
                "grounding_version": 2,
                "binding_status": "RESOLVED_VULNERABLE",
                "semantic_descriptor": descriptor,
                "endpoint_id": endpoint["node_id"],
                "endpoint_roles": list(endpoint["roles"]),
                "models": list(endpoint["models"]),
                "hypothesis_ids": [hyp_id],
                "file": descriptor["file"],
                "line": descriptor["start_line"],
                "symbol": descriptor["target_signature"] or descriptor["expression"],
            }
            assertion_id = identifier("eva2", [hyp_id, role, endpoint["node_id"]])
            add_node(
                assertion_id,
                "evidence",
                "ASSERTION",
                project,
                {**common, "assertion_type": "source_location", "role": role},
                endpoint["provenance"],
            )
            endpoint_assertions.append(assertion_id)
            add_node(
                endpoint["node_id"],
                "program",
                "PROGRAM_NODE",
                project,
                {
                    **common,
                    "external_kind": program[endpoint["node_id"]]["kind"],
                    "location": program[endpoint["node_id"]]["location"],
                    "hypothesis_ids": program[endpoint["node_id"]]["hypothesis_ids"],
                },
                endpoint["provenance"],
            )
            model_id = identifier("skg2", [project, hyp_id, role, endpoint["node_id"]])
            add_node(
                model_id,
                "security",
                "SECURITY_NODE",
                project,
                {
                    **common,
                    "external_kind": role.upper(),
                    "identity": role + ":" + endpoint["semantic_id"],
                    "fact_properties": {
                        "callable": descriptor["target_signature"],
                        "access": descriptor["slot"],
                        "semantic_kind": role,
                        "basis": endpoint["models"],
                    },
                },
                endpoint["provenance"],
            )
            edge(assertion_id, hyp_node, "DERIVED_FROM", project, endpoint["provenance"])
            edge(assertion_id, endpoint["node_id"], "MATCHES", project, endpoint["provenance"])
            edge(assertion_id, model_id, "MATCHES", project, endpoint["provenance"])
            edge(model_id, cwe_node["node_id"], "MATCHES", project, kg_provenance)
        path_id = identifier("evp2", [hyp_id, endpoint_assertions])
        has_flow = hypothesis.get("evidence_kind") == "GLOBAL_TAINT_CANDIDATE"
        add_node(
            path_id,
            "evidence",
            "TAINT_PATH" if has_flow else "ASSERTION",
            project,
            {
                "status": "unverified_candidate",
                "evidence_kind": hypothesis.get("evidence_kind"),
                "flow_proven": has_flow,
                "candidate_cwe": [cwe],
                "source_assertion": endpoint_assertions[0],
                "sink_assertion": endpoint_assertions[1],
            },
            hypothesis["provenance"],
        )
        edge(path_id, hyp_node, "SUPPORTS", project, hypothesis["provenance"])
        for assertion in endpoint_assertions:
            edge(path_id, assertion, "DERIVED_FROM", project, hypothesis["provenance"])
    return [nodes[key] for key in sorted(nodes)], [edges[key] for key in sorted(edges)]


def phase9(
    root: Path,
    config: Mapping[str, Any],
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    phase6_relative: str,
    phase7_relative: str,
    *,
    resume: bool = False,
    full: bool = False,
) -> Path:
    phase6_root, p6_lock = dependency(root, phase6_relative, selected, 6)
    phase7_root, p7_lock = dependency(root, phase7_relative, selected, 7)
    kg_root = root / str(config["phase8"]["run_root"])
    snapshot_run(kg_root)
    if sha256_file(kg_root / "manifest.json") != config["phase8"]["manifest_sha256"]:
        raise ValueError("global Security KG manifest checksum mismatch")
    kg_provenance = {
        "run_id": config["phase8"]["run_id"],
        "nodes_sha256": sha256_file(kg_root / "deterministic/nodes.jsonl"),
    }
    cwes = {
        node["identity"]: node
        for node in read_jsonl(kg_root / "deterministic/nodes.jsonl")
        if node["kind"] == "CWE"
    }
    run = Run(
        root,
        "results/graphs/useg_v2",
        run_id,
        9,
        config_path,
        selected,
        resume=resume,
        dependencies={"phase6": p6_lock, "phase7": p7_lock, "phase8": kg_provenance},
        require_clean=full,
    )
    p7_status = {row["project_id"]: row for row in read_jsonl(phase7_root / "project_status.jsonl")}
    for project in run.pending():
        if p7_status[project]["status"] != "SUCCESS":
            run.status(project, "ANALYSIS_FAILED", "inherited Phase 7 failure")
            continue
        try:
            hypotheses = read_jsonl(phase6_root / "projects" / project / "hypotheses.jsonl")
            program_nodes = read_jsonl(phase7_root / "graphs" / project / "nodes.jsonl")
            nodes, edges = useg_project(hypotheses, program_nodes, cwes, kg_provenance)
            atomic_jsonl(run.work / "projects" / project / "nodes.jsonl", nodes)
            atomic_jsonl(run.work / "projects" / project / "edges.jsonl", edges)
            run.status(
                project,
                "SUCCESS",
                "both endpoint roles have complete grounding provenance",
                analysis_outcome="CANDIDATES" if hypotheses else "NO_CANDIDATES",
                hypotheses=len(hypotheses),
                nodes=len(nodes),
                edges=len(edges),
            )
        except (KeyError, ValueError) as error:
            run.status(project, "ANALYSIS_FAILED", str(error))
    all_nodes: dict[str, dict[str, Any]] = {}
    all_edges: dict[str, dict[str, Any]] = {}
    for status in run.statuses:
        if status["status"] == "SUCCESS":
            directory = run.work / "projects" / status["project_id"]
            all_nodes.update({row["node_id"]: row for row in read_jsonl(directory / "nodes.jsonl")})
            all_edges.update({row["edge_id"]: row for row in read_jsonl(directory / "edges.jsonl")})
    atomic_jsonl(run.work / "useg/nodes.jsonl", [all_nodes[key] for key in sorted(all_nodes)])
    atomic_jsonl(run.work / "useg/edges.jsonl", [all_edges[key] for key in sorted(all_edges)])
    return run.finalize(
        {
            "useg_version": "grounded-useg-v2",
            "nodes": len(all_nodes),
            "edges": len(all_edges),
            "llm_calls": 0,
            "verified_findings": 0,
        }
    )
