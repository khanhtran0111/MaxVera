"""Offline evaluator audit of frozen B9 results; never invokes an analyzer or API."""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file, utc_now
from src.pipeline_v2.benchmark_evaluate import path_metric
from src.pipeline_v2.model import descriptor_key
from src.pipeline_v2.runtime import configuration, development_ids
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl, write_checksums
from src.verification.remap import archive_source, unchanged_line_mapping


def audit(root: Path, run: Path, output: Path) -> dict[str, Any]:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("audit requires evaluator role; its evidence contains ground truth")
    run, output = run.resolve(), output.resolve()
    if output.exists() or not output.is_relative_to(root / "results/diagnostics"):
        raise ValueError("use a new directory under results/diagnostics")
    inputs: dict[str, str] = {}

    def pin(path: Path) -> Path:
        path = path.resolve()
        inputs[path.relative_to(root).as_posix()] = sha256_file(path)
        return path

    def rows(path: Path) -> list[dict[str, Any]]:
        return list(read_jsonl(pin(path))) if path.exists() else []

    steps = json.loads(pin(run / "steps.json").read_text())

    def stage(suffix: str) -> Path:
        matches = [v for k, v in steps.items() if k.endswith(suffix) and "_pilot_" not in k]
        if len(matches) != 1 or matches[0]["status"] != "COMPLETE":
            raise ValueError(f"expected one completed stage: {suffix}")
        path = root / str(matches[0]["output"])
        pin(path / "manifest.json")
        pin(path / "checksums.sha256")
        return path

    p6, p7, p9 = (stage(s) for s in ("_p6", "_p7", "_p9"))
    p10, p11, evaluated = (stage(s) for s in ("_synth", "_verify", "_evaluate"))
    fixed = stage("_fixed")
    manifest = json.loads(pin(p10 / "manifest.json").read_text())
    # Config path is recorded by the frozen run, rather than supplied by audit callers.
    lock = json.loads(pin(run / "benchmark_lock.json").read_text())
    config_path = root / lock["config_path"]
    pin(config_path)
    if sha256_file(config_path) != manifest["config_sha256"]:
        raise ValueError("config differs from frozen synthesis manifest")
    config = configuration(root, config_path)
    with pin(root / config["dataset"]["labels"]).open() as handle:
        labels = {r["project_id"]: r for r in csv.DictReader(handle)}
    truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows(root / config["benchmark"]["truth"]):
        truth[r["project_id"]].append(r)
    pin(root / "data/processed/splits/development.csv")
    development = set(development_ids(root))
    metrics = rows(evaluated / "vulnerable_paths_projects.jsonl")
    verified_metrics = rows(evaluated / "differential_verified_projects.jsonl")
    if {r["project_id"] for r in metrics} != set(labels):
        raise ValueError("case coverage differs from frozen evaluator population")
    if {r["project_id"] for r in metrics if r["origin_split"] == "development"} != development:
        raise ValueError("audit development selection differs from frozen split")
    verification = rows(p11 / "verification_results.jsonl")
    specs = rows(p10 / "specifications.jsonl")
    spec_by_id = {r["specification_id"]: r for r in specs}
    statuses = {
        name: {r["project_id"]: r for r in rows(path / "project_status.jsonl")}
        for name, path in [("p6", p6), ("p7", p7), ("p9", p9), ("p10", p10)]
    }
    hypotheses_by_id = {
        h["hypothesis_id"]: h
        for pid in labels
        for h in rows(p6 / "projects" / pid / "hypotheses.jsonl")
    }
    unchanged_pairs = 0
    for s in specs:
        h = hypotheses_by_id[s["hypothesis_id"]]
        expected_pair = {
            (role, e["node_id"])
            for key, role in [("source_candidates", "source"), ("sink_candidates", "sink")]
            for e in h[key]
        }
        unchanged_pairs += expected_pair == {
            (e["role"], e["node_id"]) for e in s["frozen_endpoints"]
        }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in verification:
        grouped[r["project_id"]].append(r)
    # Reconstruct both metrics from actual frozen paths, including deduplication.
    for variant, expected in [("raw", metrics), ("verified", verified_metrics)]:
        for expected_row in expected:
            pid = expected_row["project_id"]
            paths = [
                path
                for r in grouped[pid]
                if variant == "raw" or r["status"] == "VERIFIED_DIFFERENTIAL"
                for path in (r.get("vulnerable") or {}).get("paths", [])
                if (r.get("vulnerable") or {}).get("query_completed") is True
                and (r.get("vulnerable") or {}).get("resolution_complete") is True
            ]
            actual = path_metric(pid, statuses["p10"][pid]["status"], paths, truth[pid])
            if any(actual[k] != expected_row[k] for k in actual):
                raise ValueError(f"reconstructed metric mismatch: {variant}/{pid}")
    output.mkdir(parents=True)
    cases, evidence, failures, mapping_diagnostics = [], [], [], []
    for m in metrics:
        pid = m["project_id"]
        if not (m["detected"] and pid in development):
            continue
        vulnerable_archive = root / config["dataset"]["vulnerable_database_root"] / pid / "src.zip"
        fixed_archive = (
            root / config["dataset"]["fixed_database_root"] / fixed.name / pid / "src.zip"
        )
        pin(vulnerable_archive)
        pin(fixed_archive)
        inventory = rows(p11 / "fixed_inventory" / pid / "endpoints.jsonl")
        relevant = []
        for r in grouped[pid]:
            side = r.get("vulnerable") or {}
            match = path_metric(pid, "SUCCESS", side.get("paths", []), truth[pid])
            if not match["detected"]:
                continue
            spec = spec_by_id[r["specification_id"]]
            ev = {
                "project_id": pid,
                "cve_id": labels[pid]["cve_id"],
                "specification_id": r["specification_id"],
                "status": r["status"],
                "candidate_cwe": r["candidate_cwe"],
                "tp_paths": match["tp_paths"],
                "vulnerable_path_count": side.get("path_count"),
                "fixed_path_count": (r.get("fixed") or {}).get("path_count"),
                "endpoints": spec["frozen_endpoints"],
                "mapping": (r.get("fixed") or {}).get("endpoint_mapping"),
                "preconditions": spec.get("preconditions", []),
            }
            for entry in (ev["mapping"] or {}).get("entries", []):
                if entry["complete"]:
                    continue
                descriptor = entry["vulnerable_descriptor"]
                endpoint = next(
                    e
                    for e in spec["frozen_endpoints"]
                    if e["node_id"] == entry["node_id"] and e["role"] == entry["role"]
                )
                required = {(v["role"], v["candidate_cwe"], v["basis"]) for v in endpoint["models"]}
                _, before = archive_source(vulnerable_archive, descriptor["file"])
                _, after = archive_source(fixed_archive, descriptor["file"])
                line_map = unchanged_line_mapping(before, after)
                exact = [
                    candidate
                    for candidate in inventory
                    if descriptor_key(candidate["descriptor"]) == descriptor_key(descriptor)
                    and set(endpoint["roles"]) <= set(candidate["roles"])
                    and required
                    <= {(v["role"], v["candidate_cwe"], v["basis"]) for v in candidate["models"]}
                    and candidate["descriptor"]["start_line"]
                    == line_map.get(descriptor["start_line"])
                    and candidate["descriptor"]["end_line"] == line_map.get(descriptor["end_line"])
                    and candidate["descriptor"]["start_column"] == descriptor["start_column"]
                    and candidate["descriptor"]["end_column"] == descriptor["end_column"]
                ]
                mapping_diagnostics.append(
                    {
                        "project_id": pid,
                        "specification_id": r["specification_id"],
                        "role": entry["role"],
                        "node_id": entry["node_id"],
                        "original_alternatives": entry["alternatives"],
                        "unchanged_line": line_map.get(descriptor["start_line"]),
                        "exact_unchanged_span_candidates": [e["node_id"] for e in exact],
                        "counterfactual_only": True,
                        "verdict_changed": False,
                    }
                )
            evidence.append(ev)
            relevant.append(ev)
        case = {
            "project_id": pid,
            "cve_id": labels[pid]["cve_id"],
            "repository": labels[pid]["github_repository_name"],
            "ground_truth_cwe": labels[pid]["ground_truth_cwe"],
            "paths": m["paths"],
            "tp_paths": m["tp_paths"],
            "matching_specs": len(relevant),
            "matching_statuses": dict(Counter(r["status"] for r in relevant)),
            "candidate_cwes_on_matching_specs": dict(Counter(r["candidate_cwe"] for r in relevant)),
            "has_matching_spec_with_ground_truth_cwe": any(
                r["candidate_cwe"] == labels[pid]["ground_truth_cwe"] for r in relevant
            ),
        }
        cases.append(case)
        directory = output / "development" / pid
        directory.mkdir(parents=True)
        texts = [f"# {case['cve_id']} — {case['repository']}", "", json.dumps(case), ""]
        for file in sorted({r["file"] for r in truth[pid]}):
            texts.extend([f"## Frozen source diff: {file}", ""])
            try:
                pin(vulnerable_archive)
                pin(fixed_archive)
                _, before = archive_source(vulnerable_archive, file)
                _, after = archive_source(fixed_archive, file)
                diff = list(
                    difflib.unified_diff(
                        before, after, "vulnerable/" + file, "fixed/" + file, n=5, lineterm=""
                    )
                )
                texts.extend(["```diff", *diff, "```", ""])
                if not diff:
                    texts.append("File unchanged between the analyzed source archives.\n")
            except (OSError, ValueError) as error:
                texts.append(f"SOURCE_DIFF_UNAVAILABLE: {error}\n")
        texts.extend(
            [
                "## Matching specification evidence",
                "",
                "```json",
                json.dumps(relevant, ensure_ascii=False, indent=2),
                "```",
                "",
            ]
        )
        (directory / "evidence.md").write_text("\n".join(texts))

    calls = rows(p10 / "llm_calls.jsonl")
    for pid, status in statuses["p10"].items():
        if status["status"] == "SUCCESS":
            continue
        directory = p6 / "projects" / pid
        inventory_available = (directory / "endpoints.jsonl").exists()
        endpoints = rows(directory / "endpoints.jsonl")
        hypotheses = rows(directory / "hypotheses.jsonl")
        rejected = rows(directory / "rejected.jsonl")
        flow_file = directory / "flows.csv"
        flow_count = None
        if flow_file.exists():
            with pin(flow_file).open() as handle:
                flow_count = sum(1 for _ in csv.DictReader(handle))
        sources = sum("source" in e["roles"] for e in endpoints)
        sinks = sum("sink" in e["roles"] for e in endpoints)
        plans = rows(p10 / "projects" / pid / "plans.jsonl")
        if statuses["p6"][pid]["status"] != "SUCCESS":
            cause = (
                "PHASE6_FLOW_TIMEOUT"
                if "TimeoutExpired" in statuses["p6"][pid]["reason"]
                else "PHASE6_FAILURE"
            )
        elif not hypotheses:
            cause = (
                "NO_MODELED_ENDPOINTS"
                if not endpoints
                else "NO_MODELED_SOURCE"
                if not sources
                else "NO_MODELED_SINK"
                if not sinks
                else "NO_CANDIDATE_RELATION"
            )
        elif any(r["status"] == "API_FATAL_ERROR" for r in plans):
            cause = "API_FATAL_RESPONSE"
        else:
            cause = "OTHER_SYNTHESIS_FAILURE"
        archive = root / config["dataset"]["vulnerable_database_root"] / pid / "src.zip"
        with zipfile.ZipFile(pin(archive)) as source_zip:
            archive_names = source_zip.namelist()
        java_files = [name for name in archive_names if name.endswith(".java")]
        build_helpers = [name for name in java_files if "/buildSrc/" in name]
        annotated_files = sorted({r["file"] for r in truth[pid]}) if pid in development else []
        missing_annotated = [
            file
            for file in annotated_files
            if not any(name == file or name.endswith("/" + file) for name in archive_names)
        ]
        failures.append(
            {
                "project_id": pid,
                "cve_id": labels[pid]["cve_id"],
                "repository": labels[pid]["github_repository_name"],
                "split": "development" if pid in development else "test_diagnostic",
                "root_cause": cause,
                "source_java_files": len(java_files),
                "buildsrc_java_files": len(build_helpers),
                "only_build_helpers_extracted": bool(java_files) and java_files == build_helpers,
                "development_annotated_files": annotated_files if pid in development else None,
                "development_annotated_files_missing": missing_annotated
                if pid in development
                else None,
                "endpoint_inventory_available": inventory_available,
                "endpoints": len(endpoints) if inventory_available else None,
                "source_endpoints": sources if inventory_available else None,
                "sink_endpoints": sinks if inventory_available else None,
                "flow_rows": flow_count,
                "hypotheses": len(hypotheses),
                "retained_specs": sum(r["project_id"] == pid for r in specs),
                "phase6_reason": statuses["p6"][pid]["reason"],
                "phase7_reason": statuses["p7"][pid]["reason"],
                "phase10_reason": status["reason"],
                "rejection_reasons": dict(Counter(r["reason"] for r in rejected)),
                "terminal_plans": [
                    {k: r.get(k) for k in ["hypothesis_id", "status", "reason"]}
                    for r in plans
                    if r["status"] in {"REJECTED", "API_FATAL_ERROR", "API_BUDGET_EXHAUSTED"}
                ],
                "api_errors": dict(
                    Counter(
                        str(r.get("error_type"))
                        for r in calls
                        if r.get("project_id") == pid and r["status"] != "SUCCESS"
                    )
                ),
            }
        )
    atomic_jsonl(output / "development_cases.jsonl", cases)
    atomic_jsonl(output / "development_spec_evidence.jsonl", evidence)
    atomic_jsonl(output / "mapping_diagnostics.jsonl", mapping_diagnostics)
    atomic_jsonl(output / "analysis_failures.jsonl", failures)
    for name, data in [("development_cases", cases), ("analysis_failures", failures)]:
        with (output / f"{name}.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(data[0]) if data else ["project_id"])
            writer.writeheader()
            writer.writerows(
                {
                    k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                    for k, v in r.items()
                }
                for r in data
            )
    summary = {
        "development_detected_before_verification": len(cases),
        "development_detected_after_verification": sum(
            r["detected"] and r["project_id"] in development for r in verified_metrics
        ),
        "matching_specifications": len(evidence),
        "matching_spec_statuses": dict(Counter(r["status"] for r in evidence)),
        "case_status_combinations": dict(
            Counter(" + ".join(sorted(r["matching_statuses"])) for r in cases)
        ),
        "analysis_failures": len(failures),
        "failed_cases_with_only_build_helpers_extracted": sum(
            r["only_build_helpers_extracted"] for r in failures
        ),
        "failure_causes_by_split": {
            split: dict(Counter(r["root_cause"] for r in failures if r["split"] == split))
            for split in ["development", "test_diagnostic"]
        },
        "specifications_with_sanitizers": sum(bool(r.get("sanitizers")) for r in specs),
        "specifications_with_propagators": sum(bool(r.get("propagators")) for r in specs),
        "specifications_preserving_phase6_endpoint_pair": unchanged_pairs,
        "development_detected_without_matching_cwe_spec": sum(
            not r["has_matching_spec_with_ground_truth_cwe"] for r in cases
        ),
        "unresolved_matching_endpoint_occurrences": len(mapping_diagnostics),
        "unique_exact_unchanged_span_counterfactual": sum(
            len(r["exact_unchanged_span_candidates"]) == 1 for r in mapping_diagnostics
        ),
        "metric_reconstruction": "PASS: every raw/verified case matches frozen evaluator",
        "api_calls": 0,
    }
    atomic_json(output / "summary.json", summary)
    pin(Path(__file__))
    for name in [
        "src/pipeline_v2/model.py",
        "src/pipeline_v2/queries.py",
        "src/pipeline_v2/specifications.py",
        "src/pipeline_v2/verification.py",
        "src/pipeline_v2/benchmark_evaluate.py",
        "src/static_analysis/queries/v2/Grounding.qll",
    ]:
        pin(root / name)
    for name, digest in inputs.items():
        if sha256_file(root / name) != digest:
            raise ValueError(f"audit input changed while reading: {name}")
    atomic_json(
        output / "manifest.json",
        {
            "created_at": utc_now(),
            "source_run": run.relative_to(root).as_posix(),
            "role": "evaluator",
            "scope": "development source/TP audit; all120 failure inventory only",
            "confirmatory": False,
            "analysis_mutations": 0,
            "api_calls": 0,
            "source_inputs_unchanged": True,
            "inputs_sha256": inputs,
        },
    )
    write_checksums(output)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(audit(root, root / args.run_root, root / args.output), ensure_ascii=False))


if __name__ == "__main__":
    main()
