"""Evaluator-only 120-case patched-method proxy using the IRIS paper formulas."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.runtime import Run, configuration, development_ids, selection_ids
from src.pipeline_v2.validate import validate_stages
from src.reproduction.common import atomic_json, atomic_jsonl, normalize_uri, read_csv, read_jsonl

VARIANTS = ("vulnerable_paths", "differential_verified", "routed_verify_or_accept", "accept_only")


def path_metric(
    project: str,
    status: str,
    paths: Sequence[Sequence[Mapping[str, Any]]],
    truth: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    ranges = []
    for row in truth:
        try:
            start, end = int(row["method_start"]), int(row["method_end"])
        except (ValueError, KeyError, TypeError):
            continue
        if 0 < start <= end:
            ranges.append((normalize_uri(str(row["file"])), start, end))
    unique = (
        {
            tuple((normalize_uri(str(node["file"])), int(node["line"])) for node in path)
            for path in paths
            if path
        }
        if status == "SUCCESS"
        else set()
    )
    matches = [
        path
        for path in unique
        if any(
            (file == target or file.endswith("/" + target)) and start <= line <= end
            for file, line in path
            for target, start, end in ranges
        )
    ]
    precision = len(matches) / len(unique) if unique else 0.0
    recall = float(bool(matches))
    return {
        "project_id": project,
        "status": status,
        "paths": len(unique),
        "tp_paths": len(matches),
        "detected": bool(matches),
        "precision": precision,
        "recall": recall,
        "fdr": 1 - precision if unique else None,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "method_annotation_available": bool(ranges),
    }


def paper_aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    alerts = [r for r in rows if r["paths"]]
    return {
        "cases": total,
        "analysis_successes": sum(r["status"] == "SUCCESS" for r in rows),
        "detected": sum(bool(r["detected"]) for r in rows),
        "detection_rate": sum(bool(r["detected"]) for r in rows) / total if total else 0.0,
        "avg_fdr": sum(float(r["fdr"]) for r in alerts) / len(alerts) if alerts else None,
        "avg_fdr_denominator": len(alerts),
        "avg_f1": sum(float(r["f1"]) for r in rows) / total if total else 0.0,
        "method_annotated_cases": sum(bool(r["method_annotation_available"]) for r in rows),
        "paths": sum(int(r["paths"]) for r in rows),
        "tp_paths": sum(int(r["tp_paths"]) for r in rows),
    }


def case_alignment(
    extended: Sequence[Mapping[str, str]], reproduction: Sequence[Mapping[str, str]]
) -> dict[str, Any]:
    def index(rows: Sequence[Mapping[str, str]]) -> dict[tuple[str, str, str], Mapping[str, str]]:
        result = {(r["cve_id"], r["github_username"], r["github_repository_name"]): r for r in rows}
        if len(result) != len(rows):
            raise ValueError("ambiguous benchmark case identity")
        return result

    current, original = index(extended), index(reproduction)
    if set(current) != set(original):
        raise ValueError("benchmark does not contain the same cases as the reproduction release")
    return {
        "same_case_population": True,
        "cases": len(current),
        "different_declared_refs": {
            key: sum(current[c][key] != original[c][key] for c in current)
            for key in ("github_tag", "buggy_commit_id", "fix_commit_ids")
        },
        "comparison_scope": "same CVEs; source snapshots/model/toolchain differ; "
        "diagnostic comparison",
    }


def evaluate(
    root: Path,
    config_path: Path,
    run_id: str,
    p10: Path,
    p11: Path,
    p12: Path,
    *,
    resume: bool = False,
) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise ValueError("benchmark metrics require evaluator role")
    config = configuration(root, config_path)
    selected = selection_ids(root, config)
    validation = validate_stages(root, config, selected, p10, p11, p12)
    policy = config["benchmark"]
    for path, digest in [
        (config["dataset"]["labels"], config["dataset"]["labels_sha256"]),
        (policy["truth"], policy["truth_sha256"]),
        (policy["reproduction_labels"], policy["reproduction_labels_sha256"]),
    ]:
        if sha256_file(root / path) != digest:
            raise ValueError("benchmark evaluator release changed")
    extended = read_csv(root / config["dataset"]["labels"])
    original = read_csv(root / policy["reproduction_labels"])
    alignment = case_alignment(extended, original)
    labels = {r["project_id"]: r for r in extended}
    if set(labels) != set(selected):
        raise ValueError("benchmark evaluator label coverage differs from 120-case analysis")
    truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(root / policy["truth"]):
        truth[row["project_id"]].append(row)
    run = Run(
        root,
        "results/pipeline_v2/benchmark_evaluation",
        run_id,
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=True,
        dependencies={
            "synthesis_manifest_sha256": sha256_file(p10 / "manifest.json"),
            "verification_manifest_sha256": sha256_file(p11 / "manifest.json"),
            "calibration_manifest_sha256": sha256_file(p12 / "manifest.json"),
            "truth_sha256": policy["truth_sha256"],
        },
    )
    manifest = json.loads((run.work / "manifest.json").read_text())
    manifest["data_access"] = "evaluator-only labels and patched-method annotations for all120"
    atomic_json(run.work / "manifest.json", manifest)
    atomic_json(run.work / "operational_validation.json", validation)
    atomic_json(run.work / "case_alignment.json", alignment)
    statuses = {r["project_id"]: r["status"] for r in read_jsonl(p10 / "project_status.jsonl")}
    routes = {r["specification_id"]: r["decision"] for r in read_jsonl(p12 / "routing.jsonl")}
    results = read_jsonl(p11 / "verification_results.jsonl")
    development = set(development_ids(root))
    tables, summaries = [], {}
    for variant in VARIANTS:
        by_project: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
        for result in results:
            verified = result["status"] == "VERIFIED_DIFFERENTIAL"
            keep = (
                variant == "vulnerable_paths"
                or (variant == "differential_verified" and verified)
                or (
                    variant == "routed_verify_or_accept"
                    and routes[result["specification_id"]] in {"VERIFY", "ACCEPT"}
                )
                or (variant == "accept_only" and routes[result["specification_id"]] == "ACCEPT")
            )
            side = result.get("vulnerable") or {}
            if (
                keep
                and side.get("query_completed") is True
                and side.get("resolution_complete") is True
            ):
                by_project[result["project_id"]].extend(side.get("paths", []))
        rows = [path_metric(p, statuses[p], by_project[p], truth[p]) for p in selected]
        for row in rows:
            row["origin_split"] = (
                "development" if row["project_id"] in development else "test_diagnostic"
            )
            row["candidate_cwe_ground_truth"] = labels[row["project_id"]]["ground_truth_cwe"]
        atomic_jsonl(run.work / f"{variant}_projects.jsonl", rows)
        for scope in ("all120", "development96", "test24_diagnostic"):
            scope_rows = (
                rows
                if scope == "all120"
                else [
                    r
                    for r in rows
                    if (r["project_id"] in development) == (scope == "development96")
                ]
            )
            summary = paper_aggregate(scope_rows)
            summary.update(
                method="B9 " + variant,
                scope=scope,
                model="GPT-OSS20B",
                hint_condition="zero_hint",
                metrics_scope="patched-method path-overlap proxy",
            )
            tables.append(summary)
            summaries[variant + "/" + scope] = summary
    for reference in policy["paper_reference"]["rows"]:
        tables.append(
            {
                **reference,
                "scope": "published_reference",
                "model": reference["method"],
                "hint_condition": "oracle_CWE",
                "detection_rate": reference["detected"] / reference["cases"],
                "metrics_scope": "published Table1; reference only",
            }
        )
    local_path = root / policy["local_baseline_table"]
    if sha256_file(local_path) != policy["local_baseline_table_sha256"]:
        raise ValueError("registered local reproduction table changed")
    atomic_json(
        run.work / "local_baseline_legacy.json",
        {
            "rows": read_csv(local_path),
            "metrics_scope": "legacy alert/success macro metrics; not the paper path formula",
        },
    )
    fields = [
        "method",
        "scope",
        "cases",
        "detected",
        "detection_rate",
        "avg_fdr",
        "avg_f1",
        "analysis_successes",
        "avg_fdr_denominator",
        "model",
        "hint_condition",
        "metrics_scope",
    ]
    with (run.work / "table_paper_comparison.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(tables)
    atomic_json(run.work / "metrics_paper_proxy.json", summaries)
    report = [
        "# B9 — all 120 benchmark cases",
        "",
        "Diagnostic comparison on the same 120 CVEs. "
        "D_extended source snapshots differ from D_repro_v1.",
        "B9 is zero-hint with GPT-OSS20B/CodeQL2.26.2; "
        "published IRIS rows use oracle CWE and other models/toolchains.",
        "Calibration fitting uses development only. "
        "Test24 is diagnostic; this is not a new holdout result.",
        "",
        "Paper formulas: deduplicate paths; detection requires patched-method overlap; "
        "AvgFDR averages only cases with paths; AvgF1 includes every case.",
        "Missing method annotations do not fall back to class/file matching. "
        "FDR is a location proxy, not adjudicated vulnerability correctness.",
        "Published reference: " + policy["paper_reference"]["url"],
        "",
        "| Method | Scope | Detected/cases | Avg FDR | Avg F1 |",
        "|---|---|---:|---:|---:|",
    ]
    for row in tables:
        fdr = f"{row['avg_fdr']:.4f}" if row["avg_fdr"] is not None else "N/A (no paths)"
        report.append(
            f"| {row['method']} | {row['scope']} | {row['detected']}/{row['cases']} "
            f"| {fdr} | {row['avg_f1']:.4f} |"
        )
    (run.work / "report.md").write_text("\n".join(report) + "\n")
    for project in run.pending():
        run.status(project, "SUCCESS", "independent metric row recorded including analysis misses")
    return run.finalize(
        {
            "cases": len(selected),
            "same_case_population": True,
            "confirmatory_result": False,
            "metrics_scope": "IRIS paper formulas; patched-method overlap proxy",
            "llm_calls": 0,
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=["full"], required=True)
    parser.add_argument("--resume", action="store_true")
    for name in ("phase10-run", "phase11-run", "phase12-run"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = evaluate(
        root,
        (root / args.config).resolve(),
        args.run_id,
        root / args.phase10_run,
        root / args.phase11_run,
        root / args.phase12_run,
        resume=args.resume,
    )
    snapshot_run(output)
    print(output, flush=True)


if __name__ == "__main__":
    main()
