"""Reproducible Phase 13 ablation progress report, with compatible paired statistics.

An incomplete or audit-confounded experiment is explicitly a progress report,
never a final Full result. Canonical artifacts are read-only inputs.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from src.baselines.validate import _verify_checksums
from src.common.provenance import collect_git, sha256_file, utc_now
from src.experiments.phase13 import RUN_ID
from src.experiments.phase13_oracles import validate as validate_oracle
from src.experiments.phase13_snapshot import validate_snapshot
from src.experiments.phase13_statistics import holm, paired_bootstrap
from src.reproduction.common import (
    atomic_json,
    atomic_jsonl,
    read_csv,
    read_jsonl,
    write_checksums,
)
from src.verification.validate import validate as validate_verification

ABLATIONS = {"A0": "B0", "A1": "B6", "A2": "B7", "A3": "B8", "A4": "B9"}


def paired_statistics(
    metrics: list[dict[str, Any]],
    groups: dict[str, str],
    samples: int,
) -> list[dict[str, Any]]:
    methods: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in metrics:
        methods[row["baseline_id"]][row["project_id"]] = row
    comparisons = []
    # Separate families: only pair methods with the same operational positive definition.
    for family in (("B0", "B3", "B4", "B5"), ("B6", "B7", "B8", "B9")):
        family_results = []
        for left, right in itertools.combinations(family, 2):
            if left not in methods or right not in methods:
                continue
            for sensitivity in (False, True):
                result = paired_bootstrap(
                    methods[left],
                    methods[right],
                    groups,
                    samples=samples,
                    successful_only=sensitivity,
                )
                family_results.append(
                    {"left": left, "right": right, "family": list(family), **result}
                )
        for sensitivity_name in ("failures_as_miss", "common_analysis_successes"):
            selected = [r for r in family_results if r.get("sensitivity") == sensitivity_name]
            corrected = holm([r["paired_detection"]["p_value"] for r in selected])
            for result, p in zip(selected, corrected, strict=True):
                result["paired_detection"]["holm_adjusted_p_value"] = p
        comparisons.extend(family_results)
    return comparisons


def run(root: Path, run_id: str, report_id: str, audit_id: str) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("Phase 13 reporting requires evaluator role")
    if any(not RUN_ID.fullmatch(value) for value in (run_id, report_id, audit_id)):
        raise ValueError("invalid Phase 13 report/run ID")
    parent = root / "results/phase13" / run_id
    snapshot_path = parent / "analyzer_snapshot.json"
    snapshot = validate_snapshot(root, snapshot_path)
    evaluation = parent / "evaluation"
    verification = evaluation / "verification" / f"{run_id}_verification"
    print(validate_verification(verification, repo_root=root), flush=True)
    audit = evaluation / "audits" / audit_id
    _verify_checksums(audit)
    audit_manifest = json.loads((audit / "manifest.json").read_text())
    if audit_manifest["analyzer_snapshot_sha256"] != sha256_file(snapshot_path):
        raise ValueError("audit does not belong to this sealed analyzer snapshot")
    if audit_manifest["verification_checksums_sha256"] != sha256_file(
        verification / "checksums.sha256"
    ):
        raise ValueError("audit does not belong to this verification artifact")
    proxy = evaluation / "proxy_metrics"
    _verify_checksums(proxy)
    final = evaluation / "reports" / report_id
    if final.exists():
        _verify_checksums(final)
        return final
    work = final.parent / f".{report_id}.inprogress"
    work.mkdir(parents=True, exist_ok=False)
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    labels = {row["project_id"]: row for row in read_csv(labels_path)}
    selected = snapshot["selected_project_ids"]
    groups = {
        p: labels[p]["github_username"] + "/" + labels[p]["github_repository_name"]
        for p in selected
    }
    config = yaml.safe_load((root / "configs/experiments/phase13.yaml").read_text())
    proxy_rows = read_jsonl(proxy / "project_metrics.jsonl")
    aggregates = json.loads((proxy / "metrics_aggregate.json").read_text())
    ablations = {a: {"entrypoint": b, **aggregates[b]} for a, b in ABLATIONS.items()}
    sources = {
        "analyzer_snapshot.json": sha256_file(snapshot_path),
        "verification": sha256_file(verification / "checksums.sha256"),
        "audit": sha256_file(audit / "checksums.sha256"),
        "proxy_metrics": sha256_file(proxy / "checksums.sha256"),
    }
    verified_metrics = evaluation / "verification_metrics"
    if verified_metrics.exists():
        _verify_checksums(verified_metrics)
        cohorts = json.loads((verified_metrics / "metrics_aggregate.json").read_text())
        ablations["A5"] = {
            "entrypoint": "B9+differential",
            **cohorts["A5"],
            "validity": "CANONICAL_VERDICTS_CONFOUNDED_SEE_AUDIT",
        }
        sources["verification_metrics"] = sha256_file(verified_metrics / "checksums.sha256")
    else:
        ablations["A5"] = {"status": "MISSING_VERIFICATION_METRICS"}
    ablations["Full"] = {
        "status": "REQUIRES_VERIFICATION_REVIEW",
        "reason": "VERIFY routing cohort has no final Full verdict policy; "
        "verification evidence requires review against the audit",
    }
    oracle_status = {}
    for baseline in ("B1", "B2"):
        oracle = evaluation / "oracles" / f"{run_id}_{baseline.lower()}_oracle"
        if oracle.exists():
            validation = validate_oracle(oracle, root)
            oracle_status[baseline] = {
                "status": "COMPLETED",
                "validation": validation,
                "role": "oracle_reference",
                "metrics": json.loads((oracle / "metrics_aggregate.json").read_text()),
            }
            sources[baseline] = sha256_file(oracle / "checksums.sha256")
        else:
            work_root = oracle.parent / f".{oracle.name}.inprogress"
            statuses = read_jsonl(work_root / "project_status.jsonl")
            oracle_status[baseline] = {
                "status": "IN_PROGRESS" if work_root.exists() else "PENDING",
                "finished_projects": sum(
                    s["status"] in {"SUCCESS", "ANALYSIS_FAILED"} for s in statuses
                ),
            }
    statistics = paired_statistics(
        proxy_rows, groups, int(config["robustness"]["paired_bootstrap_samples"])
    )
    audit_summary = json.loads((audit / "summary.json").read_text())
    pending = [b + "_oracle" for b in ("B1", "B2") if oracle_status[b]["status"] != "COMPLETED"]
    pending += [
        "Full_verdict_policy_and_verifier_review",
        "development_baseline_selection_lock",
        "five_seed_robustness",
        "final_ablation_report",
    ]
    summary = {
        "schema_version": 1,
        "parent_run_id": run_id,
        "report_kind": "PROGRESS_REPORT",
        "phase13_complete": False,
        "pending_workloads": pending,
        "ablations": ablations,
        "oracles": oracle_status,
        "verification_audit": audit_summary,
        "paired_bootstrap_completed_for_available_proxy_families": True,
        "bootstrap_samples": config["robustness"]["paired_bootstrap_samples"],
        "repository_groups": len(set(groups.values())),
        "unknown_unreviewed_is_false_positive": False,
        "precision_and_fdr_interpretation": "fix-location proxies; "
        "vulnerability precision has not been adjudicated",
    }
    atomic_json(work / "summary.json", summary)
    atomic_jsonl(work / "paired_statistics.jsonl", statistics)
    atomic_jsonl(work / "project_metrics.jsonl", proxy_rows)
    lines = [
        "# Phase 13 ablation progress report",
        "",
        "Phase 13 is incomplete. This report preserves canonical numbers and adds an audit.",
        f"Verification audit: {audit_summary['audit_status_counts']}.",
        "See audit evidence before interpreting canonical differential results. "
        "Full metrics are pending.",
        "",
        "| Cell | Entry point | Successful projects | Detected projects | "
        "Recall (ITA) | Interpretation |",
        "|---|---|---:|---:|---:|---|",
    ]
    for cell, value in ablations.items():
        if "projects" in value:
            lines.append(
                f"| {cell} | {value['entrypoint']} | "
                f"{value['analysis_successes']}/{value['projects']} | "
                f"{value['detected_projects']} | {value['recall_intention_to_analyze']:.4f} | "
                f"{value['interpretation']} |"
            )
        else:
            lines.append(f"| {cell} | — | — | — | — | {value['status']} |")
    lines.extend(
        [
            "",
            "## Paired statistics",
            "",
            "10,000 paired bootstrap draws resample whole repository groups "
            "and retain all project rows.",
            "Both failures-as-miss and common-success sensitivities are reported. "
            "Exact McNemar p-values",
            "receive Holm correction within each compatible outcome-definition family.",
            "Proxy families and A5 use different positive definitions and are not pooled.",
            "",
            "| Left - right | Recall difference | 95% cluster-bootstrap CI | Holm p |",
            "|---|---:|---|---:|",
        ]
    )
    for stat in statistics:
        if stat.get("sensitivity") == "failures_as_miss":
            lines.append(
                f"| {stat['left']} - {stat['right']} | {stat['effect_size']:.4f} | "
                f"[{stat['ci_lower']:.4f}, {stat['ci_upper']:.4f}] | "
                f"{stat['paired_detection']['holm_adjusted_p_value']:.4f} |"
            )
    lines.extend(
        [
            "",
            "Precision/FDR are location proxies; non-intersecting findings "
            "are not adjudicated false positives.",
            "McNemar's project independence assumption may not hold for "
            "multiple rows in one repository.",
            "",
            "## Remaining workloads",
            "",
            *[f"- {item}" for item in pending],
            "",
        ]
    )
    (work / "report.md").write_text("\n".join(lines))
    atomic_json(
        work / "manifest.json",
        {
            "schema_version": 1,
            "run_id": report_id,
            "parent_run_id": run_id,
            "created_at": utc_now(),
            "sources": sources,
            "labels_sha256": sha256_file(labels_path),
            "git": collect_git(root),
            "implementation_sha256": {
                p: sha256_file(root / p)
                for p in (
                    "src/experiments/phase13_report.py",
                    "src/experiments/phase13_statistics.py",
                )
            },
        },
    )
    (work / "STATUS").write_text("SUCCESS\n")
    (work / "command.txt").write_text(json.dumps(sys.argv) + "\n")
    write_checksums(work)
    os.replace(work, final)
    print(f"PROGRESS_REPORT_COMPLETED: {final}", flush=True)
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument("--report-id", default="ablation_progress_001")
    parser.add_argument("--audit-id", default="verification_audit_001")
    args = parser.parse_args()
    run(args.repo_root.resolve(), args.run_id, args.report_id, args.audit_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
