"""Validate complete specification-to-verification-to-routing provenance for v2."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.runtime import configuration, development_ids, selection_ids
from src.pipeline_v2.verification import differential_status
from src.reproduction.common import read_jsonl


def unique_rows(rows: Sequence[dict[str, Any]], field: str) -> dict[str, dict[str, Any]]:
    indexed = {row[field]: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError(f"duplicate {field} records")
    return indexed


def validate_stages(
    root: Path,
    config: Mapping[str, Any],
    selected: Sequence[str],
    synthesis: Path,
    verification: Path,
    calibration: Path,
) -> dict[str, Any]:
    selected_set = set(selected)
    statuses: dict[int, dict[str, dict[str, Any]]] = {}
    manifests = []
    for path, phase in ((synthesis, 10), (verification, 11), (calibration, 12)):
        snapshot_run(path)
        manifest = json.loads((path / "manifest.json").read_text())
        if (
            manifest.get("phase") != phase
            or manifest.get("analysis_scope") != config["analysis_scope"]
            or manifest.get("protocol_version") != "2.0.0"
            or manifest.get("selected_project_ids") != list(selected)
        ):
            raise ValueError("end-to-end stage selection/protocol mismatch")
        manifests.append(manifest)
        stage_status = unique_rows(read_jsonl(path / "project_status.jsonl"), "project_id")
        if set(stage_status) != selected_set or any(
            row["status"]
            not in {
                "SUCCESS",
                "ANALYSIS_FAILED",
                "CODEQL_DB_FAILED",
                "BUILD_FAILED",
                "EXCLUDED_WITH_REASON",
            }
            for row in stage_status.values()
        ):
            raise ValueError("stage lacks an explicit final status for every selected project")
        summary = json.loads((path / "summary.json").read_text())
        successes = sum(row["status"] == "SUCCESS" for row in stage_status.values())
        if (
            summary["projects"] != len(selected)
            or summary["analysis_successes"] != successes
            or (summary["analysis_failures"] != len(selected) - successes)
        ):
            raise ValueError("stage summary does not match project statuses")
        statuses[phase] = stage_status
    for key in ("config_sha256", "model_config_sha256", "implementation_sha256"):
        if any(manifest.get(key) != manifests[0].get(key) for manifest in manifests):
            raise ValueError("end-to-end stage snapshot mismatch")
    if (
        manifests[1]["dependencies"]["phase10"]["manifest_sha256"]
        != sha256_file(synthesis / "manifest.json")
        or manifests[2]["dependencies"]["phase11"]["manifest_sha256"]
        != sha256_file(verification / "manifest.json")
        or manifests[2]["dependencies"]["phase10"]["manifest_sha256"]
        != sha256_file(synthesis / "manifest.json")
    ):
        raise ValueError("end-to-end dependency lineage mismatch")
    if manifests[0]["dependencies"].get("dry_run") or (
        manifests[0]["dependencies"].get("baseline_id") != "B9"
    ):
        raise ValueError("end-to-end validation requires actual B9 synthesis")
    specifications = unique_rows(read_jsonl(synthesis / "specifications.jsonl"), "specification_id")
    results = unique_rows(
        read_jsonl(verification / "verification_results.jsonl"), "specification_id"
    )
    routes = unique_rows(read_jsonl(calibration / "routing.jsonl"), "specification_id")
    if set(specifications) != set(results) or set(results) != set(routes):
        raise ValueError("each specification must have exactly one verification and routing result")
    for spec_id, specification in specifications.items():
        result, route = results[spec_id], routes[spec_id]
        if specification["project_id"] not in selected_set or any(
            row["project_id"] != specification["project_id"] for row in (result, route)
        ):
            raise ValueError("finding crosses project selection")
        if (
            result.get("verification_version") != "semantic-differential-verifier-v3"
            or result["hypothesis_id"] != specification["hypothesis_id"]
            or result["candidate_cwe"] != specification["candidate_cwe"]
            or route["verification_status"] != result["status"]
            or not specification.get("frozen_endpoints")
        ):
            raise ValueError("finding loses its frozen endpoint/hypothesis provenance")
        verified = result["status"] == "VERIFIED_DIFFERENTIAL"
        if verified and differential_status(
            result.get("vulnerable") or {}, result.get("fixed")
        ) != ("VERIFIED_DIFFERENTIAL"):
            raise ValueError("verified finding lacks completed differential evidence")
        if not verified and not result["status"].startswith("UNVERIFIED_"):
            raise ValueError("unknown verification state")
        if statuses[10][specification["project_id"]]["status"] != "SUCCESS" and verified:
            raise ValueError("analysis miss cannot become a verified finding")
        if route["decision"] not in {"ACCEPT", "VERIFY", "ABSTAIN"} or (
            not verified
            and (
                route["decision"] != "ABSTAIN"
                or route.get("oof_candidate_cwe_probability") is not None
                or route.get("frozen_candidate_cwe_probability") is not None
            )
        ):
            raise ValueError("routing treats an unverified result as calibrated/accepted")
    summary = json.loads((calibration / "summary.json").read_text())
    if (
        any(row["decision"] == "ACCEPT" for row in routes.values())
        and not summary["accept_enabled"]
    ):
        raise ValueError("ACCEPT emitted while the acceptance gate is disabled")
    if not summary["calibrated_full"] and any(
        row.get("oof_candidate_cwe_probability") is not None
        or row.get("frozen_candidate_cwe_probability") is not None
        for row in routes.values()
    ):
        raise ValueError("ineligible calibration emitted probabilities")
    if config["analysis_scope"] == "benchmark_diagnostic":
        fit = json.loads((calibration / "fit_scope.json").read_text())
        development = set(development_ids(root)) & selected_set
        if set(fit["selected_project_ids"]) != development or fit["test_labels_used"] is not False:
            raise ValueError("benchmark calibration used non-development fitting data")
        for route in routes.values():
            if (
                route["project_id"] not in development
                and route.get("oof_candidate_cwe_probability") is not None
            ) or (
                route["project_id"] in development
                and route.get("frozen_candidate_cwe_probability") is not None
            ):
                raise ValueError("benchmark routing confuses OOF and frozen application")
    budget = config["budget"]
    for project in selected:
        reserved = read_jsonl(synthesis / "projects" / project / "api_attempts.jsonl")
        if (
            len(reserved) > budget["max_calls_per_project"]
            or sum(row["request_estimate_tokens"] for row in reserved)
            > budget["max_total_input_tokens_per_project"]
            or any(
                row["request_estimate_tokens"] > budget["max_context_tokens_per_call"]
                for row in reserved
            )
        ):
            raise ValueError("synthesis reservation budget exceeded")
        attempts = read_jsonl(verification / "projects" / project / "query_attempts.jsonl")
        if len(attempts) > config["verification"]["max_query_invocations_per_project"]:
            raise ValueError("verification query budget exceeded")
    calls = read_jsonl(synthesis / "llm_calls.jsonl")
    if any(row.get("project_id") not in selected_set for row in calls):
        raise ValueError("LLM log crosses project selection")
    successes = [row for row in calls if row.get("status") == "SUCCESS"]
    successful_projects = sum(
        statuses[10][project]["status"] == statuses[11][project]["status"] == "SUCCESS"
        for project in selected
    )
    return {
        "status": "PASS" if successful_projects == len(selected) else "PASS_WITH_ANALYSIS_FAILURES",
        "projects": len(selected),
        "analysis_successes": successful_projects,
        "analysis_misses": len(selected) - successful_projects,
        "specifications": len(specifications),
        "verification_status_counts": dict(Counter(row["status"] for row in results.values())),
        "routing_counts": dict(Counter(row["decision"] for row in routes.values())),
        "verified_findings": sum(
            row["status"] == "VERIFIED_DIFFERENTIAL" for row in results.values()
        ),
        "calibrated_full": summary["calibrated_full"],
        "accept_enabled": summary["accept_enabled"],
        "llm_successful_calls": len(successes),
        "http_429_attempts": sum(row.get("http_status") == 429 for row in calls),
        "input_tokens": sum(
            int(row.get("usage", {}).get("prompt_tokens", 0) or 0) for row in successes
        ),
        "output_tokens": sum(
            int(row.get("usage", {}).get("completion_tokens", 0) or 0) for row in successes
        ),
        "metrics_scope": config["analysis_scope"]
        + " operational counts; no vulnerability precision/FDR claim",
        "confirmatory_test_ready": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    controller = args.run_root.resolve()
    if not controller.is_relative_to((root / "results/pipeline_v2").resolve()):
        parser.error("controller must be under results/pipeline_v2")
    snapshot_run(controller)
    manifest = json.loads((controller / "manifest.json").read_text())
    lock_file = (
        "benchmark_lock.json"
        if manifest["analysis_scope"] == "benchmark_diagnostic"
        else "development_lock.json"
    )
    lock = json.loads((controller / lock_file).read_text())
    paths = lock["analysis_runs"]
    config_path = root / lock["config_path"]
    if sha256_file(config_path) != manifest["config_sha256"]:
        raise ValueError("controller config changed")
    config = configuration(root, config_path)
    selected = manifest["selected_project_ids"]
    if manifest["analysis_scope"] == "benchmark_diagnostic" and selected != selection_ids(
        root, config
    ):
        raise ValueError("benchmark controller lacks the complete 120-case population")
    if manifest.get("canonical_result") and selected != selection_ids(root, config):
        raise ValueError("canonical end-to-end run lacks the complete development selection")
    for name, record in lock["stages"].items():
        path = root / record["output"]
        snapshot_run(path)
        if sha256_file(path / "manifest.json") != record["manifest_sha256"]:
            raise ValueError("controller stage changed: " + name)
    result = validate_stages(
        root,
        config,
        selected,
        *(root / paths[name] for name in ("synthesis", "verification", "calibration")),
    )
    if result != json.loads((controller / "validation.json").read_text()):
        raise ValueError("controller validation report differs from raw outputs")
    if manifest["analysis_scope"] == "benchmark_diagnostic":
        evaluated = root / lock["evaluation_run"]
        snapshot_run(evaluated)
        for filename in (
            "report.md",
            "table_paper_comparison.csv",
            "metrics_paper_proxy.json",
            "case_alignment.json",
        ):
            if sha256_file(controller / filename) != sha256_file(evaluated / filename):
                raise ValueError("benchmark report differs from its locked evaluator output")
        from src.pipeline_v2.benchmark_evaluate import VARIANTS, paper_aggregate

        expected = json.loads((evaluated / "metrics_paper_proxy.json").read_text())
        dev = set(development_ids(root))
        for variant in VARIANTS:
            rows = read_jsonl(evaluated / f"{variant}_projects.jsonl")
            if len(rows) != 120 or {r["project_id"] for r in rows} != set(selected):
                raise ValueError("paper metrics dropped benchmark cases")
            for scope in ("all120", "development96", "test24_diagnostic"):
                chosen = (
                    rows
                    if scope == "all120"
                    else [r for r in rows if (r["project_id"] in dev) == (scope == "development96")]
                )
                if any(
                    expected[variant + "/" + scope][key] != value
                    for key, value in paper_aggregate(chosen).items()
                ):
                    raise ValueError("paper metrics cannot be regenerated from case rows")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
