"""Audit historical Phase 6-10 development artifacts without rerunning analysis."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import collect_git, sha256_file, utc_now
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums

AUDIT_VERSION = "phase6-10-development-audit-v1"
BASELINES = {
    "B6": "program_graph_only",
    "B7": "security_kg_only",
    "B8": "useg_no_pruning",
    "B9": "full_useg",
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def check_projects(rows: Sequence[Mapping[str, Any]], development: set[str]) -> None:
    """Reject mixed-split artifacts even when their manifest claims development."""
    for row in rows:
        if row.get("project_id") not in development:
            raise ValueError("audit record is outside the development split")


def check_manifest(manifest: Mapping[str, Any], development: set[str], phase: int) -> None:
    if manifest.get("phase") != phase:
        raise ValueError("audit dependency phase mismatch")
    if manifest.get("analysis_scope", "development") != "development":
        raise ValueError("audit refuses non-development scope")
    selected = manifest.get("selected_project_ids")
    if not isinstance(selected, list) or len(selected) != len(set(selected)):
        raise ValueError("audit dependency requires unique selected project IDs")
    if set(selected) != development:
        raise ValueError("audit dependency must cover the complete development split")
    dataset = manifest.get("dataset", {})
    if dataset and dataset.get("split") != "data/processed/splits/development.csv":
        raise ValueError("audit dependency is not a development run")


def snapshot_run(run_root: Path) -> dict[str, str]:
    """Verify every historical checksum, including coverage, and retain actual hashes."""
    index = run_root / "checksums.sha256"
    expected: dict[str, str] = {}
    for line in index.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = (run_root / relative).resolve()
        if not target.is_relative_to(run_root.resolve()) or relative in expected:
            raise ValueError("unsafe or duplicate checksum entry")
        expected[relative] = digest
    actual = {
        path.relative_to(run_root).as_posix(): sha256_file(path)
        for path in sorted(run_root.rglob("*"))
        if path.is_file() and path != index
    }
    if actual != expected:
        raise ValueError(f"historical checksum or coverage mismatch: {run_root}")
    return {**actual, "checksums.sha256": sha256_file(index)}


def summarize_hypotheses(hypotheses: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    missing = [row for row in hypotheses if not row.get("source_candidates")]
    endpoints = [
        endpoint
        for row in hypotheses
        for role in ("source_candidates", "sink_candidates")
        for endpoint in row.get(role, [])
    ]
    return {
        "hypotheses": len(hypotheses),
        "without_source": len(missing),
        "without_sink": sum(not row.get("sink_candidates") for row in hypotheses),
        "without_source_by_candidate_cwe": dict(
            sorted(Counter(str(row["candidate_cwe"][0]) for row in missing).items())
        ),
        "endpoint_candidates": len(endpoints),
        "endpoints_without_symbol": sum(not row.get("symbol") for row in endpoints),
        "endpoints_without_enclosing_callable": sum(
            not row.get("enclosing_callable") for row in endpoints
        ),
    }


def summarize_specifications(
    specifications: Sequence[Mapping[str, Any]],
    hypotheses: Mapping[str, Mapping[str, Any]],
    nodes: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    layers: dict[str, Counter[str]] = {role: Counter() for role in ("sources", "sinks")}
    missing_source = 0
    shared = 0
    for specification in specifications:
        hypothesis = hypotheses[str(specification["hypothesis_id"])]
        if hypothesis["project_id"] != specification["project_id"]:
            raise ValueError("specification references a hypothesis from another project")
        missing_source += not hypothesis["source_candidates"]
        shared += bool(
            {entry["node_id"] for entry in specification["sources"]}
            & {entry["node_id"] for entry in specification["sinks"]}
        )
        for role in layers:
            for entry in specification[role]:
                node = nodes[str(entry["node_id"])]
                if node.get("project_id") not in (None, specification["project_id"]):
                    raise ValueError("specification references a node from another project")
                layers[role][str(node["layer"])] += 1
    return {
        "specifications": len(specifications),
        "from_hypotheses_without_source": missing_source,
        "shared_source_sink_node": shared,
        "endpoint_layers": {role: dict(sorted(count.items())) for role, count in layers.items()},
        "interpretation": "grounding observations; not vulnerability verdicts",
    }


def audit(repo_root: Path, config_path: Path, run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", run_id):
        raise ValueError("invalid audit run ID")
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    inputs = config["audit_inputs"]
    split = repo_root / "data/processed/splits/development.csv"
    development = {row["project_id"] for row in read_csv(split)}
    split_sha256 = sha256_file(split)
    if split_sha256 != inputs["development_split_sha256"]:
        raise ValueError("development split checksum mismatch")
    roots: dict[str, Path] = {}
    for name, prefix, phase in (
        ("phase6", "results/hypotheses/static", 6),
        ("phase7", "results/graphs/program", 7),
        ("phase9", "results/graphs/useg", 9),
        *(
            (baseline, f"results/specifications/phase10/{folder}", 10)
            for baseline, folder in BASELINES.items()
        ),
    ):
        dependency = inputs[name]
        path = (repo_root / dependency["run_root"]).resolve()
        if path.parent != (repo_root / prefix).resolve():
            raise ValueError("audit input is outside its allowed development artifact directory")
        manifest = _json(path / "manifest.json")
        check_manifest(manifest, development, phase)
        if manifest["run_id"] != dependency["run_id"]:
            raise ValueError("audit dependency run ID mismatch")
        if sha256_file(path / "manifest.json") != dependency["manifest_sha256"]:
            raise ValueError("audit dependency manifest checksum mismatch")
        roots[name] = path
    # Cached evaluator metrics contain development-only booleans, not raw labels or patches.
    evaluation = inputs["phase10_evaluation"]
    evaluation_root = (repo_root / evaluation["run_root"]).resolve()
    if evaluation_root.parent != (repo_root / "results/evaluations/phase10").resolve():
        raise ValueError("audit evaluator input is outside its allowed directory")
    evaluation_manifest = _json(evaluation_root / "manifest.json")
    if (
        evaluation_manifest.get("run_id") != evaluation["run_id"]
        or evaluation_manifest.get("data_access")
        != "development labels/fix locations only; test_locked forbidden"
        or evaluation_manifest.get("evaluator_inputs", {}).get("development_split_sha256")
        != split_sha256
        or sha256_file(evaluation_root / "manifest.json") != evaluation["manifest_sha256"]
    ):
        raise ValueError("audit requires pinned development-only evaluator metrics")
    roots["phase10_evaluation"] = evaluation_root
    for baseline in BASELINES:
        dependency = evaluation_manifest.get("dependencies", {}).get(baseline, {})
        if (
            dependency.get("run_id") != inputs[baseline]["run_id"]
            or dependency.get("manifest_sha256") != inputs[baseline]["manifest_sha256"]
        ):
            raise ValueError("cached evaluator metrics do not match audit synthesis inputs")
    final = repo_root / "results/audits" / run_id
    work = final.with_name(final.name + ".inprogress")
    if final.exists() or work.exists():
        raise FileExistsError("audit run ID already exists; use a new ID")
    before = {name: snapshot_run(path) for name, path in roots.items()}

    def records(name: str, relative: str) -> list[dict[str, Any]]:
        path = roots[name] / relative
        if not path.is_file():
            raise ValueError(f"required audit input missing: {path}")
        values = read_jsonl(path)
        check_projects(values, development)
        return values

    hypotheses = records("phase6", "hypotheses.jsonl")
    hypotheses_by_id = {str(row["hypothesis_id"]): row for row in hypotheses}
    cases: list[dict[str, Any]] = []
    for row in hypotheses:
        if not row["source_candidates"]:
            cases.append(
                {
                    "phase": 6,
                    "project_id": row["project_id"],
                    "hypothesis_id": row["hypothesis_id"],
                    "issue": "MISSING_SOURCE",
                }
            )
    metrics = records("phase6", "metrics_project.jsonl")
    if len(metrics) != len(development) or {row["project_id"] for row in metrics} != development:
        raise ValueError("Phase 6 metrics must cover each development project exactly once")
    phase6 = summarize_hypotheses(hypotheses)
    phase6.update(
        {
            "projects": len(development),
            "cwe_recall_at_10": sum(row["hypothesis_recall_at_10"] for row in metrics)
            / len(metrics),
            "candidate_pool_cwe_misses": sum(
                not row["candidate_pool_recall_at_40"] for row in metrics
            ),
            "historical_recall_target": "CWE match only; endpoints/localization not validated",
        }
    )
    program_kinds: Counter[str] = Counter()
    program_without_callable = 0
    for status in records("phase7", "project_status.jsonl"):
        if status["status"] == "SUCCESS":
            for node in records("phase7", f"graphs/{status['project_id']}/nodes.jsonl"):
                program_kinds[str(node["kind"])] += 1
                program_without_callable += not node.get("enclosing_callable")
    nodes = read_jsonl(roots["phase9"] / "useg/nodes.jsonl")
    check_projects([node for node in nodes if node.get("project_id") is not None], development)
    nodes_by_id = {str(node["node_id"]): node for node in nodes}
    matches: dict[str, list[str]] = defaultdict(list)
    for edge in records("phase9", "useg/edges.jsonl"):
        if edge["kind"] == "MATCHES" and nodes_by_id[edge["target_id"]]["layer"] == "program":
            matches[str(edge["source_id"])].append(str(edge["target_id"]))
    mapping_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for node in nodes:
        properties = node["properties"]
        if node["kind"] != "ASSERTION" or properties.get("assertion_type") != "source_location":
            continue
        count = len(set(matches[str(node["node_id"])]))
        category = "unmapped" if count == 0 else "multiple_matches" if count > 1 else "single_match"
        mapping_counts[str(properties["role"])][category] += 1
        if count != 1:
            cases.append(
                {
                    "phase": 9,
                    "project_id": node["project_id"],
                    "node_id": node["node_id"],
                    "role": properties["role"],
                    "program_matches": count,
                    "issue": category.upper(),
                }
            )
    useg_hypotheses = [node for node in nodes if node["kind"] == "HYPOTHESIS"]
    phase10: dict[str, Any] = {}
    proxy_metrics = records("phase10_evaluation", "spec_metrics.jsonl")
    for baseline in BASELINES:
        specifications = records(baseline, "specifications.jsonl")
        summary = summarize_specifications(specifications, hypotheses_by_id, nodes_by_id)
        proxy = [row for row in proxy_metrics if row["baseline_id"] == baseline]
        summary["annotated_evaluator_subset"] = {
            "specifications": len(proxy),
            "candidate_cwe_correct": sum(row["candidate_cwe_correct"] for row in proxy),
            "paper_fix_location_proxy_matches": sum(row["paper_proxy_match"] for row in proxy),
            "correct_cwe_without_fix_location_proxy": sum(
                row["candidate_cwe_correct"] and not row["paper_proxy_match"] for row in proxy
            ),
            "nonmatching_proxy_is_false_positive": False,
        }
        phase10[baseline] = summary
        for row in specifications:
            if not hypotheses_by_id[str(row["hypothesis_id"])]["source_candidates"]:
                cases.append(
                    {
                        "phase": 10,
                        "baseline_id": baseline,
                        "project_id": row["project_id"],
                        "hypothesis_id": row["hypothesis_id"],
                        "specification_id": row["specification_id"],
                        "issue": "UPSTREAM_HYPOTHESIS_MISSING_SOURCE",
                    }
                )
    after = {name: snapshot_run(path) for name, path in roots.items()}
    if before != after or sha256_file(split) != split_sha256:
        raise ValueError("historical input changed during audit")
    work.mkdir(parents=True, exist_ok=False)
    atomic_json(
        work / "summary.json",
        {
            "schema_version": 1,
            "audit_version": AUDIT_VERSION,
            "run_id": run_id,
            "analysis_scope": "development",
            "status": "DIAGNOSTIC_ONLY",
            "historical_inputs_unchanged": True,
            "llm_calls": 0,
            "codeql_calls": 0,
            "raw_evaluator_labels_opened": False,
            "test_artifacts_opened": False,
            "phase6": phase6,
            "phase7": {
                "node_kinds": dict(sorted(program_kinds.items())),
                "nodes_without_enclosing_callable": program_without_callable,
                "identity_basis": "file/span/symbol/type; no enclosing signature",
            },
            "phase9": {
                "hypotheses": len(useg_hypotheses),
                "hypotheses_without_phase6_source": sum(
                    not hypotheses_by_id[node["properties"]["upstream_hypothesis_id"]][
                        "source_candidates"
                    ]
                    for node in useg_hypotheses
                ),
                "location_program_mapping": {
                    role: dict(sorted(count.items()))
                    for role, count in sorted(mapping_counts.items())
                },
                "multiple_matches_meaning": "semantic equivalence is unaudited",
            },
            "phase10": phase10,
        },
    )
    atomic_jsonl(work / "cases.jsonl", cases)
    atomic_json(work / "input_checksums.json", before)
    atomic_json(
        work / "manifest.json",
        {
            "schema_version": 1,
            "audit_version": AUDIT_VERSION,
            "run_id": run_id,
            "created_at": utc_now(),
            "git": collect_git(repo_root),
            "data_access": "development artifacts and cached development evaluator metrics only",
            "inputs": {
                name: path.relative_to(repo_root).as_posix() for name, path in roots.items()
            },
            "development_split_sha256": split_sha256,
            "config_sha256": sha256_file(config_path),
            "implementation_sha256": sha256_file(Path(__file__)),
            "canonical_result": False,
        },
    )
    write_checksums(work)
    work.rename(final)
    return final


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, default=Path("configs/experiments/pipeline_v2.yaml"))
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    path = args.config if args.config.is_absolute() else root / args.config
    print(audit(root, path, args.run_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
