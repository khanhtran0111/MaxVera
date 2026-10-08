"""B9 end-to-end on all 120 cases with diagnostic paper-reference reporting."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from src.common.provenance import utc_now
from src.pipeline_v2.b9 import branch, stage, upstream_runs
from src.pipeline_v2.fixed import parent_databases
from src.pipeline_v2.runtime import Run, configuration, development_ids, selection_ids
from src.pipeline_v2.specifications import RetryableSynthesisError
from src.pipeline_v2.validate import validate_stages
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl

DEFAULT_CONFIG = "configs/experiments/b9_benchmark_120.yaml"


def preflight(root: Path, config: dict[str, Any]) -> dict[str, Any]:
    selected = selection_ids(root, config)
    base = configuration(root, root / config["benchmark"]["seed_config_path"])
    upstream_runs(root, base, development_ids(root))
    parent_databases(root, config)
    available = sum(
        any(
            (root / parent / p / "codeql-database.yml").is_file()
            for parent in config["benchmark"]["vulnerable_parent_roots"]
        )
        for p in selected
    )
    sources = sum(
        (root / config["fixed_preparation"]["source_root"] / p / ".git").exists() for p in selected
    )
    return {
        "status": "INPUT_PREFLIGHT_PASS",
        "cases": len(selected),
        "development": len(development_ids(root)),
        "test_diagnostic": len(selected) - len(development_ids(root)),
        "available_vulnerable_databases": available,
        "source_repositories": sources,
        "api_calls": 0,
        "confirmatory_result": False,
    }


def run(
    root: Path,
    config_path: Path,
    run_id: str,
    *,
    resume: bool,
    confirm_api_spend: bool,
    dry_run: bool = False,
) -> Path | dict[str, Any]:
    config = configuration(root, config_path)
    if (
        config["execution"]["entrypoint"] != "b9_benchmark_end_to_end"
        or config["analysis_scope"] != "benchmark_diagnostic"
    ):
        raise ValueError("120-case B9 config is not registered")
    if (root / config["execution"]["config_path"]).resolve() != config_path.resolve():
        raise ValueError("benchmark execution path changed")
    check = preflight(root, config)
    if dry_run:
        return check
    if not confirm_api_spend:
        raise ValueError("benchmark synthesis requires --confirm-api-spend")
    selected = selection_ids(root, config)
    controller = Run(
        root,
        "results/pipeline_v2/benchmark",
        run_id,
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=True,
        dependencies={"phase6_seed": config["benchmark"]["phase6_seed"]},
    )
    try:
        stage(
            controller,
            "inputs",
            run_id + "_inputs",
            "results/pipeline_v2/benchmark_inputs",
            0,
            selected,
            [],
            fixed=True,
            module_name="src.pipeline_v2.benchmark_inputs",
        )
        p6 = stage(
            controller, "phase6", run_id + "_p6", "results/hypotheses/grounded_v2", 6, selected, []
        )
        p7 = stage(
            controller,
            "phase7",
            run_id + "_p7",
            "results/graphs/program_v2",
            7,
            selected,
            ["--phase6-run", p6.relative_to(root).as_posix()],
        )
        p9 = stage(
            controller,
            "phase9",
            run_id + "_p9",
            "results/graphs/useg_v2",
            9,
            selected,
            [
                "--phase6-run",
                p6.relative_to(root).as_posix(),
                "--phase7-run",
                p7.relative_to(root).as_posix(),
            ],
        )
        inputs = [
            "--phase6-run",
            p6.relative_to(root).as_posix(),
            "--phase9-run",
            p9.relative_to(root).as_posix(),
        ]
        dry = stage(
            controller,
            "phase10",
            run_id + "_dry",
            "results/specifications/v2/b9",
            10,
            selected,
            [*inputs, "--baseline", "B9", "--dry-run"],
        )
        dry_summary = json.loads((dry / "summary.json").read_text())
        if (
            dry_summary["llm_calls"]
            or dry_summary["rejected_hypotheses"]
            or not dry_summary["api_eligible"]
        ):
            raise ValueError("120-case grounding dry-run failed")
        project = config["execution"]["pilot_project_id"]
        pilot = branch(
            controller,
            [project],
            run_id + "_pilot",
            inputs,
            inherit=root / config["benchmark"]["synthesis_seed"],
        )
        gate = validate_stages(
            root, config, [project], pilot["synthesis"], pilot["verification"], pilot["calibration"]
        )
        prepared = json.loads((pilot["fixed_preparation"] / "summary.json").read_text())
        if (
            gate["analysis_misses"]
            or not gate["specifications"]
            or prepared["prepared_databases"] != 1
            or gate["verification_status_counts"].get("UNVERIFIED_QUERY_OR_BUDGET_FAILURE", 0)
        ):
            raise ValueError("120-case pilot has a grounding/database/verifier failure")
        atomic_json(controller.work / "end_to_end_pilot_gate.json", gate)
        paths = branch(controller, selected, run_id, inputs, inherit=pilot["synthesis"])
        validation = validate_stages(
            root, config, selected, paths["synthesis"], paths["verification"], paths["calibration"]
        )
        evaluated = stage(
            controller,
            "evaluate",
            run_id + "_evaluate",
            "results/pipeline_v2/benchmark_evaluation",
            0,
            selected,
            [
                "--phase10-run",
                paths["synthesis"].relative_to(root).as_posix(),
                "--phase11-run",
                paths["verification"].relative_to(root).as_posix(),
                "--phase12-run",
                paths["calibration"].relative_to(root).as_posix(),
            ],
            evaluator=True,
            fixed=True,
            module_name="src.pipeline_v2.benchmark_evaluate",
        )
        atomic_json(controller.work / "validation.json", validation)
        atomic_json(controller.work / "metrics_operational.json", validation)
        steps = json.loads((controller.work / "steps.json").read_text())
        atomic_json(
            controller.work / "benchmark_lock.json",
            {
                "config_path": config_path.relative_to(root).as_posix(),
                "stages": steps,
                "analysis_runs": {
                    name: path.relative_to(root).as_posix() for name, path in paths.items()
                },
                "evaluation_run": evaluated.relative_to(root).as_posix(),
                "scope": "all120_diagnostic",
                "calibrated_full": validation["calibrated_full"],
                "accept_enabled": validation["accept_enabled"],
                "confirmatory_test_ready": False,
            },
        )
        for filename in (
            "report.md",
            "table_paper_comparison.csv",
            "metrics_paper_proxy.json",
            "case_alignment.json",
        ):
            (controller.work / filename).write_bytes((evaluated / filename).read_bytes())
        results = {
            r["specification_id"]: r
            for r in read_jsonl(paths["verification"] / "verification_results.jsonl")
        }
        routes = {
            r["specification_id"]: r for r in read_jsonl(paths["calibration"] / "routing.jsonl")
        }
        atomic_jsonl(
            controller.work / "findings.jsonl",
            [
                {
                    "project_id": s["project_id"],
                    "specification_id": s["specification_id"],
                    "candidate_cwe": s["candidate_cwe"],
                    "frozen_endpoints": s["frozen_endpoints"],
                    "verification_status": results[s["specification_id"]]["status"],
                    "decision": routes[s["specification_id"]]["decision"],
                    "evidence_paths": (results[s["specification_id"]].get("vulnerable") or {}).get(
                        "paths", []
                    ),
                }
                for s in read_jsonl(paths["synthesis"] / "specifications.jsonl")
            ],
        )
        statuses = {
            r["project_id"]: r["status"]
            for r in read_jsonl(paths["synthesis"] / "project_status.jsonl")
        }
        for project in controller.pending():
            controller.status(
                project,
                statuses[project],
                "120-case analysis and independent paper-proxy evaluation recorded",
            )
        return controller.finalize(
            {
                "kind": "b9_benchmark_end_to_end",
                "validation_status": validation["status"],
                "cases": 120,
                "confirmatory_result": False,
            }
        )
    except BaseException as error:
        atomic_json(
            controller.work / "failure.json",
            {"type": type(error).__name__, "reason": str(error), "time": utc_now()},
        )
        (controller.work / "STATUS").write_text(
            "WAITING_FOR_API\n"
            if isinstance(error, RetryableSynthesisError)
            else "STOPPED_AT_GATE\n"
        )
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(DEFAULT_CONFIG))
    parser.add_argument("--mode", choices=["full"], default="full")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    os.environ["MAXVERA_DATA_ROLE"] = "analyzer"
    try:
        output = run(
            root,
            (root / args.config).resolve(),
            args.run_id,
            resume=args.resume,
            confirm_api_spend=args.confirm_api_spend,
            dry_run=args.dry_run,
        )
    except RetryableSynthesisError as error:
        print(str(error), flush=True)
        return 75
    print(output if isinstance(output, Path) else json.dumps(output, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
