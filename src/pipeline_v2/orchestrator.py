"""Sequential restart controller: development dry-runs, API pilots, full runs and v3 gates."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from src.common.provenance import collect_git, sha256_file, utc_now
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.runtime import configuration, development_ids, implementation_hashes
from src.reproduction.common import atomic_json, read_jsonl, write_checksums

CONTROLLER_ID = "dev_restart_v2_001"


def automate(root: Path, config_path: Path, *, resume: bool, confirm_api_spend: bool) -> Path:
    if not confirm_api_spend:
        raise ValueError("automatic synthesis requires the authorized --confirm-api-spend flag")
    config = configuration(root, config_path)
    controller_id = str(config["execution"].get("controller_id", CONTROLLER_ID))
    suffix = str(config["execution"].get("run_suffix", "001"))
    git = collect_git(root)
    if git["dirty"]:
        raise ValueError(
            "freeze the implementation in a clean local commit before automatic full runs"
        )
    selected = development_ids(root)
    final = root / "results/pipeline_v2" / controller_id
    work = final.with_name("." + controller_id + ".inprogress")
    expected = {
        "schema_version": 2,
        "protocol_version": "2.0.0",
        "analysis_scope": "development",
        "config_sha256": sha256_file(config_path),
        "model_config_sha256": sha256_file(root / config["model_config"]),
        "git": git,
        "implementation_sha256": implementation_hashes(root),
        "selected_project_ids": selected,
    }
    if final.exists():
        raise FileExistsError("immutable controller already finalized")
    if work.exists():
        if not resume:
            raise FileExistsError("unfinished controller exists; use --resume")
        manifest = json.loads((work / "manifest.json").read_text())
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError("controller resume snapshot changed")
    else:
        work.mkdir(parents=True)
        atomic_json(
            work / "manifest.json", {**expected, "created_at": utc_now(), "run_id": controller_id}
        )
    steps = json.loads((work / "steps.json").read_text()) if (work / "steps.json").exists() else {}

    def stage(
        name: str,
        run_id: str,
        output: str,
        phase: int,
        extra: list[str],
        *,
        evaluator: bool = False,
        project: str | None = None,
    ) -> Path:
        path = root / output / run_id
        wanted = [project] if project else selected
        if not path.exists():
            command = [
                sys.executable,
                "-m",
                "src.pipeline_v2",
                name,
                "--config",
                str(config_path),
                "--mode",
                "pilot" if project else "full",
                "--run-id",
                run_id,
                *extra,
            ]
            if project:
                command += ["--project-id", project]
            if path.with_name("." + run_id + ".inprogress").exists():
                command += ["--resume"]
            env = dict(os.environ)
            env["MAXVERA_DATA_ROLE"] = "evaluator" if evaluator else "analyzer"
            steps[run_id] = {
                **steps.get(run_id, {}),
                "status": "RUNNING",
                "started_at": utc_now(),
                "command": shlex.join(command),
                "output": output + "/" + run_id,
            }
            atomic_json(work / "steps.json", steps)
            print(f"{utc_now()} START {run_id}", flush=True)
            policy = config.get("recovery", {})
            while True:
                with (work / (run_id + ".log")).open("a") as log:
                    process = subprocess.run(
                        command,
                        cwd=root,
                        env=env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        check=False,
                    )
                if process.returncode != 75:
                    break
                retries = steps[run_id].get("transport_retries", 0)
                if retries >= int(policy.get("max_stage_retries", 0)):
                    raise RuntimeError(
                        f"{run_id}: retryable API cooldown limit reached; checkpoint retained"
                    )
                delay = min(
                    int(policy["stage_cooldown_seconds"]) * 2**retries,
                    int(policy["stage_cooldown_max_seconds"]),
                )
                steps[run_id].update(
                    status="WAITING_FOR_API", transport_retries=retries + 1, cooldown_seconds=delay
                )
                atomic_json(work / "steps.json", steps)
                print(f"{utc_now()} API COOLDOWN {run_id}: {delay}s; budgets retained", flush=True)
                time.sleep(delay)
                steps[run_id]["status"] = "RUNNING"
                atomic_json(work / "steps.json", steps)
                if "--resume" not in command:
                    command.append("--resume")
            if process.returncode:
                raise RuntimeError(
                    f"stage {run_id} failed ({process.returncode}); see {work / (run_id + '.log')}"
                )
        snapshot_run(path)
        manifest = json.loads((path / "manifest.json").read_text())
        if (
            manifest.get("phase") != phase
            or manifest.get("analysis_scope") != "development"
            or manifest.get("protocol_version") != "2.0.0"
            or manifest.get("selected_project_ids") != wanted
            or manifest.get("config_sha256") != expected["config_sha256"]
            or manifest.get("implementation_sha256") != expected["implementation_sha256"]
            or manifest.get("model_config_sha256") != expected["model_config_sha256"]
            or manifest.get("git", {}).get("commit") != git["commit"]
        ):
            raise ValueError("completed stage does not match this frozen controller")
        steps[run_id] = {
            **steps.get(run_id, {}),
            "status": "COMPLETE",
            "completed_at": utc_now(),
            "manifest_sha256": sha256_file(path / "manifest.json"),
            "checksums_sha256": sha256_file(path / "checksums.sha256"),
            "output": path.relative_to(root).as_posix(),
        }
        atomic_json(work / "steps.json", steps)
        print(f"{utc_now()} COMPLETE {run_id}", flush=True)
        return path

    def relative(path: Path) -> str:
        return path.relative_to(root).as_posix()

    try:
        if config.get("recovery"):
            stage(
                "prepare",
                config["recovery"]["database_preparation_run_id"],
                "results/pipeline_v2/database_recovery",
                0,
                [],
            )
        p6 = stage(
            "phase6", f"p6_hyp_dev_full_v2_{suffix}", "results/hypotheses/grounded_v2", 6, []
        )
        p7 = stage(
            "phase7",
            f"p7_program_graph_dev_full_v2_{suffix}",
            "results/graphs/program_v2",
            7,
            ["--phase6-run", relative(p6)],
        )
        p9 = stage(
            "phase9",
            f"p9_useg_dev_full_v2_{suffix}",
            "results/graphs/useg_v2",
            9,
            ["--phase6-run", relative(p6), "--phase7-run", relative(p7)],
        )
        inputs = ["--phase6-run", relative(p6), "--phase9-run", relative(p9)]
        dry_runs = {}
        for baseline in ("B6", "B7", "B8", "B9"):
            path = stage(
                "phase10",
                f"p10_{baseline.lower()}_dev_dry_v2_{suffix}",
                "results/specifications/v2/" + baseline.lower(),
                10,
                [*inputs, "--baseline", baseline, "--dry-run"],
            )
            summary = json.loads((path / "summary.json").read_text())
            if summary["llm_calls"] or summary["rejected_hypotheses"]:
                raise ValueError(f"{baseline} full development dry-run gate failed")
            dry_runs[baseline] = path
        pilots: dict[str, dict[str, Any]] = {}
        for baseline, dry in dry_runs.items():
            eligible = {
                row["project_id"]
                for row in read_jsonl(dry / "dry_run_plan.jsonl")
                if row["status"] == "API_ELIGIBLE"
            }
            if not eligible:
                pilots[baseline] = {
                    "status": "SKIPPED_NO_GROUNDED_HYPOTHESIS",
                    "api_validated": False,
                }
                continue
            project = next(project for project in selected if project in eligible)
            if config.get("recovery"):
                project = config["recovery"]["pilot_project_id"]
                if project not in eligible:
                    raise ValueError("registered recovery pilot is no longer grounded")
            path = stage(
                "phase10",
                f"p10_{baseline.lower()}_dev_pilot_v2_{suffix}",
                "results/specifications/v2/" + baseline.lower(),
                10,
                [
                    *inputs,
                    "--baseline",
                    baseline,
                    "--confirm-api-spend",
                    *(
                        ["--inherit-run", config["recovery"]["phase10_seed_run"]]
                        if baseline == "B6" and config.get("recovery")
                        else []
                    ),
                ],
                project=project,
            )
            summary = json.loads((path / "summary.json").read_text())
            if (
                summary["analysis_failures"]
                or summary["rejected_hypotheses"]
                or not summary["specifications"]
            ):
                api_failures = summary.get("api_fatal_failures", 0) + summary.get(
                    "api_budget_exhaustions", 0
                )
                raise ValueError(
                    f"{baseline} pilot gate failed: "
                    f"{api_failures} API failures/budget exhaustions, "
                    f"{summary['rejected_hypotheses']} grounding rejections"
                )
            pilots[baseline] = {"status": "PASS", "api_validated": True, "run_root": relative(path)}
        atomic_json(work / "api_pilot_gate.json", pilots)
        full_runs = {}
        for baseline in ("B6", "B7", "B8", "B9"):
            full_runs[baseline] = stage(
                "phase10",
                f"p10_{baseline.lower()}_dev_full_v2_{suffix}",
                "results/specifications/v2/" + baseline.lower(),
                10,
                [
                    *inputs,
                    "--baseline",
                    baseline,
                    "--confirm-api-spend",
                    *(
                        ["--inherit-run", pilots[baseline]["run_root"]]
                        if pilots[baseline].get("api_validated")
                        else []
                    ),
                ],
            )
        p11 = stage(
            "phase11",
            f"p11_diff_dev_full_v3_{suffix}",
            "results/verification/v3",
            11,
            ["--phase10-run", relative(full_runs["B9"])],
            evaluator=True,
        )
        p12 = stage(
            "phase12",
            f"p12_calibration_dev_v2_{suffix}",
            "results/calibration/v2",
            12,
            [
                "--phase6-run",
                relative(p6),
                "--phase10-run",
                relative(full_runs["B9"]),
                "--phase11-run",
                relative(p11),
            ],
            evaluator=True,
        )
        calibration = json.loads((p12 / "summary.json").read_text())
        atomic_json(
            work / "development_lock.json",
            {
                "schema_version": 2,
                "frozen_at": utc_now(),
                "implementation_sha256": expected["implementation_sha256"],
                "config_sha256": expected["config_sha256"],
                "stages": steps,
                "calibrated_full": calibration["calibrated_full"],
                "accept_enabled": calibration["accept_enabled"],
                "historical_test_disposition": "diagnostic_only_corrective_incomplete",
                "confirmatory_test_ready": False,
                "reason": "requires a separately registered unopened repository-group holdout",
            },
        )
        (work / "STATUS").write_text("DEVELOPMENT_COMPLETE_NEW_HOLDOUT_REQUIRED\n")
        write_checksums(work)
        work.rename(final)
        print(f"{utc_now()} DEVELOPMENT COMPLETE {final}", flush=True)
        return final
    except BaseException as error:
        atomic_json(
            work / "failure.json",
            {"time": utc_now(), "type": type(error).__name__, "reason": str(error)},
        )
        (work / "STATUS").write_text("STOPPED_AT_GATE\n")
        raise
