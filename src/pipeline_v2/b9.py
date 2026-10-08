"""Run B9 v2 end to end on development, with separate analyzer/evaluator stages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.provenance import sha256_file, utc_now
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.fixed import parent_databases
from src.pipeline_v2.recovery import ast_contract
from src.pipeline_v2.runtime import (
    Run,
    configuration,
    dependency,
    development_ids,
    implementation_hashes,
)
from src.pipeline_v2.specifications import RetryableSynthesisError
from src.pipeline_v2.validate import validate_stages
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl

DEFAULT_CONFIG = "configs/experiments/b9_pipeline_v2.yaml"


def upstream_runs(root: Path, config: Mapping[str, Any], selected: Sequence[str]) -> dict[str, Any]:
    policy = config["upstream_reuse"]
    path = root / policy["config_path"]
    if sha256_file(path) != policy["config_sha256"]:
        raise ValueError("registered upstream configuration changed")
    previous = yaml.safe_load(path.read_text())
    for name in (
        "top_k",
        "codeql",
        "budget",
        "model_config",
        "phase8",
        "verification",
        "calibration",
    ):
        if previous[name] != config[name]:
            raise ValueError("upstream scientific policy changed: " + name)
    if (
        previous["dataset"]["vulnerable_database_root"]
        != config["dataset"]["vulnerable_database_root"]
    ):
        raise ValueError("upstream vulnerable database root changed")
    current = implementation_hashes(root)
    infrastructure = {
        "src/pipeline_v2/runtime.py",
        "src/pipeline_v2/__main__.py",
        "src/pipeline_v2/orchestrator.py",
        "src/pipeline_v2/specifications.py",
        "src/pipeline_v2/verification.py",
        "src/llm/providers/openrouter.py",
    }
    result = {}
    for name, phase in (("phase6", 6), ("phase7", 7), ("phase9", 9)):
        registered = policy[name]
        run, lock = dependency(root, registered["run_root"], selected, phase)
        if any(lock[key] != registered[key] for key in ("manifest_sha256", "checksums_sha256")):
            raise ValueError("registered upstream run changed: " + name)
        manifest = json.loads((run / "manifest.json").read_text())
        if manifest["config_sha256"] != policy["config_sha256"] or (
            manifest["model_config_sha256"] != sha256_file(root / config["model_config"])
        ):
            raise ValueError("upstream model/config does not match the registered snapshot")
        for asset, digest in manifest["implementation_sha256"].items():
            if asset not in infrastructure and current.get(asset) != digest:
                raise ValueError("upstream scientific asset changed: " + asset)
        revision = manifest["git"]["commit"]
        old_source = subprocess.check_output(
            ["git", "show", f"{revision}:src/pipeline_v2/runtime.py"],
            cwd=root,
            text=True,
        )
        if (
            hashlib.sha256(old_source.encode()).hexdigest()
            != manifest["implementation_sha256"]["src/pipeline_v2/runtime.py"]
        ):
            raise ValueError("upstream runtime does not match its recorded Git snapshot")
        if (
            sha256_file(root / "src/pipeline_v2/runtime.py")
            != manifest["implementation_sha256"]["src/pipeline_v2/runtime.py"]
        ):
            for function in (
                "endpoint_inventory",
                "archive_sources",
                "source_text_fingerprint",
                "entity_rows",
                "unique_inventory_rows",
                "query_csv",
                "codeql",
                "phase6",
            ):
                if ast_contract(old_source, function) != ast_contract(
                    (root / "src/pipeline_v2/runtime.py").read_text(),
                    function,
                ):
                    raise ValueError("upstream discovery contract changed: " + function)
        result[name] = {"path": run, "lock": lock}
    return result


def execute(command: Sequence[str], root: Path, log: Path, role: str) -> int:
    environment = dict(os.environ, MAXVERA_DATA_ROLE=role)
    with log.open("a") as output:
        process = subprocess.Popen(
            list(command),
            cwd=root,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            return process.wait()
        except BaseException:
            # Interrupt Python first so its CodeQL subprocess cleanup can execute.
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise


def stage(
    controller: Run,
    name: str,
    run_id: str,
    output: str,
    phase: int,
    selected: Sequence[str],
    arguments: Sequence[str],
    *,
    evaluator: bool = False,
    fixed: bool = False,
) -> Path:
    root = controller.root
    target = root / output / run_id
    steps_path = controller.work / "steps.json"
    steps = json.loads(steps_path.read_text()) if steps_path.is_file() else {}
    state = steps.get(run_id, {})
    config_path = root / controller.config["execution"]["config_path"]
    if not target.exists():
        module = "src.pipeline_v2.fixed" if fixed else "src.pipeline_v2"
        command = [sys.executable, "-m", module]
        if not fixed:
            command.append(name)
        command += [
            "--config",
            str(config_path),
            "--run-id",
            run_id,
            "--mode",
            "full" if len(selected) == len(development_ids(root)) else "pilot",
        ]
        if len(selected) != len(development_ids(root)):
            command += ["--project-id", selected[0]]
        command += list(arguments)
        if target.with_name("." + run_id + ".inprogress").exists():
            command.append("--resume")
        policy = controller.config["execution"]["api_retry"]
        while True:
            state.update(
                status="RUNNING",
                output=target.relative_to(root).as_posix(),
                started_at=state.get("started_at", utc_now()),
            )
            steps[run_id] = state
            atomic_json(steps_path, steps)
            print(f"{utc_now()} START {run_id}", flush=True)
            code = execute(
                command,
                root,
                controller.work / (run_id + ".log"),
                "evaluator" if evaluator else "analyzer",
            )
            if code != 75:
                break
            retries = state.get("transport_retries", 0)
            state.update(status="WAITING_FOR_API", exit_code=75)
            steps[run_id] = state
            atomic_json(steps_path, steps)
            if retries >= policy["max_stage_retries"]:
                raise RetryableSynthesisError(
                    "API retry limit reached; resume retains checkpoint and budget"
                )
            delay = min(policy["cooldown_seconds"] * 2**retries, policy["cooldown_max_seconds"])
            state.update(transport_retries=retries + 1, cooldown_seconds=delay)
            atomic_json(steps_path, steps)
            print(f"{utc_now()} WAITING_FOR_API {run_id}: {delay}s", flush=True)
            while delay > 0:
                interval = min(60, delay)
                time.sleep(interval)
                delay -= interval
            if "--resume" not in command:
                command.append("--resume")
        if code:
            state.update(status="FAILED", exit_code=code)
            steps[run_id] = state
            atomic_json(steps_path, steps)
            raise RuntimeError(f"{run_id} failed with exit code {code}; see its stage log")
    snapshot_run(target)
    manifest = json.loads((target / "manifest.json").read_text())
    controller_manifest = json.loads((controller.work / "manifest.json").read_text())
    if (
        manifest.get("phase") != phase
        or manifest.get("selected_project_ids") != list(selected)
        or any(
            manifest.get(key) != controller_manifest[key]
            for key in ("config_sha256", "model_config_sha256", "implementation_sha256")
        )
    ):
        raise ValueError("completed stage is from a different frozen snapshot")
    state.update(
        status="COMPLETE",
        output=target.relative_to(root).as_posix(),
        manifest_sha256=sha256_file(target / "manifest.json"),
        checksums_sha256=sha256_file(target / "checksums.sha256"),
        completed_at=utc_now(),
    )
    steps[run_id] = state
    atomic_json(steps_path, steps)
    print(f"{utc_now()} COMPLETE {run_id}", flush=True)
    return target


def branch(
    controller: Run,
    selected: Sequence[str],
    prefix: str,
    inputs: Sequence[str],
    *,
    inherit: Path | None = None,
) -> dict[str, Path]:
    p10 = stage(
        controller,
        "phase10",
        prefix + "_synth",
        "results/specifications/v2/b9",
        10,
        selected,
        [
            *inputs,
            "--baseline",
            "B9",
            "--confirm-api-spend",
            *(
                ["--inherit-run", inherit.relative_to(controller.root).as_posix()]
                if inherit
                else []
            ),
        ],
    )
    fixed = stage(
        controller,
        "prepare-fixed",
        prefix + "_fixed",
        "results/pipeline_v2/fixed_preparation",
        0,
        selected,
        ["--phase10-run", p10.relative_to(controller.root).as_posix()],
        evaluator=True,
        fixed=True,
    )
    p11 = stage(
        controller,
        "phase11",
        prefix + "_verify",
        "results/verification/v3",
        11,
        selected,
        [
            "--phase10-run",
            p10.relative_to(controller.root).as_posix(),
            "--fixed-preparation-run",
            fixed.relative_to(controller.root).as_posix(),
        ],
        evaluator=True,
    )
    p12 = stage(
        controller,
        "phase12",
        prefix + "_route",
        "results/calibration/v2",
        12,
        selected,
        [
            "--phase6-run",
            inputs[1],
            "--phase10-run",
            p10.relative_to(controller.root).as_posix(),
            "--phase11-run",
            p11.relative_to(controller.root).as_posix(),
        ],
        evaluator=True,
    )
    return {"synthesis": p10, "fixed_preparation": fixed, "verification": p11, "calibration": p12}


def run(
    root: Path,
    config_path: Path,
    run_id: str,
    *,
    full: bool,
    resume: bool,
    confirm_api_spend: bool,
    dry_run: bool = False,
    project_id: str | None = None,
) -> Path | dict[str, Any]:
    config = configuration(root, config_path)
    if config.get("execution", {}).get("entrypoint") != "b9_end_to_end":
        raise ValueError("B9 end-to-end execution config is not registered")
    if (root / config["execution"]["config_path"]).resolve() != config_path.resolve():
        raise ValueError("execution config path differs from its registered path")
    if full and project_id:
        raise ValueError("full must select the complete development split")
    project = project_id or config["execution"]["pilot_project_id"]
    selected = development_ids(root, project_id=None if full else project)
    upstream = upstream_runs(root, config, selected)
    parent_databases(root, config)
    inputs = [
        "--phase6-run",
        upstream["phase6"]["lock"]["run_root"],
        "--phase9-run",
        upstream["phase9"]["lock"]["run_root"],
    ]
    if dry_run:
        return {
            "status": "INPUT_PREFLIGHT_PASS",
            "projects": len(selected),
            "api_calls": 0,
            "upstream_runs": {name: value["lock"] for name, value in upstream.items()},
            "stages": [
                "B9 dry-run",
                "B9 API pilot",
                "fixed preparation",
                "verifier v3",
                "conditional calibration",
                "validation",
            ],
            "confirmatory_test_ready": False,
        }
    if not confirm_api_spend:
        raise ValueError("B9 synthesis requires --confirm-api-spend")
    controller = Run(
        root,
        "results/pipeline_v2/b9",
        run_id,
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=full,
        dependencies={"upstream_runs": {name: value["lock"] for name, value in upstream.items()}},
    )
    try:
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
        if dry_summary["llm_calls"] or dry_summary["rejected_hypotheses"]:
            raise ValueError("B9 dry-run grounding/budget gate failed")
        if not dry_summary["api_eligible"]:
            raise ValueError("B9 dry-run found no grounded hypothesis to validate end to end")
        pilot_selection = development_ids(root, project_id=project)
        if not any(
            row["project_id"] == project and row["status"] == "API_ELIGIBLE"
            for row in read_jsonl(dry / "dry_run_plan.jsonl")
        ):
            raise ValueError("registered pilot has no API-eligible hypothesis")
        pilot = branch(controller, pilot_selection, run_id + "_pilot" if full else run_id, inputs)
        validation = validate_stages(
            root,
            config,
            pilot_selection,
            pilot["synthesis"],
            pilot["verification"],
            pilot["calibration"],
        )
        prepared = json.loads((pilot["fixed_preparation"] / "summary.json").read_text())
        if (
            validation["analysis_misses"]
            or not validation["specifications"]
            or prepared["prepared_databases"] != 1
        ):
            raise ValueError("B9 end-to-end pilot lacks synthesis/fixed database coverage")
        if validation["verification_status_counts"].get("UNVERIFIED_QUERY_OR_BUDGET_FAILURE", 0):
            raise ValueError("B9 pilot has a verifier query/budget failure")
        atomic_json(controller.work / "end_to_end_pilot_gate.json", validation)
        paths = (
            branch(controller, selected, run_id, inputs, inherit=pilot["synthesis"])
            if full
            else pilot
        )
        validation = validate_stages(
            root, config, selected, paths["synthesis"], paths["verification"], paths["calibration"]
        )
        atomic_json(controller.work / "validation.json", validation)
        atomic_json(controller.work / "metrics_operational.json", validation)
        results = {
            row["specification_id"]: row
            for row in read_jsonl(paths["verification"] / "verification_results.jsonl")
        }
        routes = {
            row["specification_id"]: row
            for row in read_jsonl(paths["calibration"] / "routing.jsonl")
        }
        findings = []
        for spec in read_jsonl(paths["synthesis"] / "specifications.jsonl"):
            result, route = results[spec["specification_id"]], routes[spec["specification_id"]]
            findings.append(
                {
                    "project_id": spec["project_id"],
                    "specification_id": spec["specification_id"],
                    "hypothesis_id": spec["hypothesis_id"],
                    "candidate_cwe": spec["candidate_cwe"],
                    "endpoints": spec["frozen_endpoints"],
                    "preconditions": spec["preconditions"],
                    "verification_status": result["status"],
                    "decision": route["decision"],
                    "evidence_paths": (result.get("vulnerable") or {}).get("paths", []),
                    "oof_candidate_cwe_probability": route.get("oof_candidate_cwe_probability"),
                    "provenance": {
                        name: value.relative_to(root).as_posix() for name, value in paths.items()
                    },
                }
            )
        atomic_jsonl(controller.work / "findings.jsonl", findings)
        steps = json.loads((controller.work / "steps.json").read_text())
        atomic_json(
            controller.work / "development_lock.json",
            {
                "config_path": config_path.relative_to(root).as_posix(),
                "stages": steps,
                "analysis_runs": {
                    name: value.relative_to(root).as_posix() for name, value in paths.items()
                },
                "calibrated_full": validation["calibrated_full"],
                "accept_enabled": validation["accept_enabled"],
                "scope": "full_development" if full else "development_pilot",
                "confirmatory_test_ready": False,
            },
        )
        synthesis_status = {
            row["project_id"]: row
            for row in read_jsonl(paths["synthesis"] / "project_status.jsonl")
        }
        for project in controller.pending():
            controller.status(
                project,
                "SUCCESS"
                if synthesis_status[project]["status"] == "SUCCESS"
                else "ANALYSIS_FAILED",
                "validated B9 end-to-end result with explicit finding states",
            )
        (controller.work / "report.md").write_text(
            f"# B9 v2 development {'full' if full else 'pilot'}\n\n"
            f"Validation: {validation['status']}. Projects: {len(selected)}. "
            f"Specifications: {validation['specifications']}. "
            f"Differential verified: {validation['verified_findings']}.\n\n"
            f"Routing: {json.dumps(validation['routing_counts'], sort_keys=True)}. "
            f"Calibrated Full eligible: {validation['calibrated_full']}.\n\n"
            "Operational development results; confirmatory evaluation requires "
            "a new unopened holdout.\n",
        )
        return controller.finalize(
            {
                "kind": "b9_end_to_end",
                "validation_status": validation["status"],
                "confirmatory_test_ready": False,
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(DEFAULT_CONFIG))
    parser.add_argument("--mode", choices=["pilot", "full"], default="pilot")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--project-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    subprocess.run(["bash", "scripts/tools/assert_no_smoke_artifacts.sh"], cwd=root, check=True)
    try:
        output = run(
            root,
            (root / args.config).resolve(),
            args.run_id,
            full=args.mode == "full",
            resume=args.resume,
            dry_run=args.dry_run,
            confirm_api_spend=args.confirm_api_spend,
            project_id=args.project_id,
        )
    except RetryableSynthesisError as error:
        print(str(error), flush=True)
        return 75
    print(
        output.relative_to(root)
        if isinstance(output, Path)
        else json.dumps(output, sort_keys=True),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
