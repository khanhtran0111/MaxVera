"""Recover a frozen benchmark checkpoint with an explicitly registered pacing change."""

from __future__ import annotations

import copy
import json
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.provenance import sha256_file, utc_now
from src.experiments.development_audit import snapshot_run
from src.pipeline_v2.b9 import compatible_synthesis
from src.pipeline_v2.runtime import Run, dependency, selection_ids
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def checkpoint(root: Path, config: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    policy = config["benchmark"]["transport_recovery"]
    path = (root / policy["checkpoint"]).resolve()
    if not path.is_relative_to((root / "results/pipeline_v2/benchmark_checkpoints").resolve()):
        raise ValueError("transport checkpoint is outside the registered snapshot namespace")
    if (
        sha256_file(path / "manifest.json") != policy["manifest_sha256"]
        or sha256_file(path / "checksums.sha256") != policy["checksums_sha256"]
        or sha256_file(root / policy["source_config"]) != policy["source_config_sha256"]
    ):
        raise ValueError("transport recovery lock changed")
    snapshot_run(path)
    old = yaml.safe_load((root / policy["source_config"]).read_text())
    normalized = copy.deepcopy(old)
    normalized["execution"]["config_path"] = config["execution"]["config_path"]
    normalized["execution"]["llm_request_interval_seconds"] = 90
    normalized["execution"]["api_retry"]["cooldown_seconds"] = 90
    normalized["benchmark"]["transport_recovery"] = dict(policy)
    if normalized != config:
        raise ValueError("recovery may change only the registered 90-second transport timing")
    manifest = json.loads((path / "manifest.json").read_text())
    if (
        manifest["config_sha256"] != policy["source_config_sha256"]
        or manifest["model_config_sha256"] != sha256_file(root / config["model_config"])
        or manifest["selected_project_ids"] != selection_ids(root, config)
        or manifest["phase"] != 10
        or manifest["analysis_scope"] != "benchmark_diagnostic"
        or manifest["dependencies"]["baseline_id"] != "B9"
        or manifest["dependencies"]["dry_run"]
        or json.loads((path / "checkpoint_snapshot.json").read_text())["kind"]
        != "unfinished_synthesis_checkpoint_only"
    ):
        raise ValueError("transport checkpoint is not the registered actual B9 full cohort")
    compatible_synthesis(root, config, path)
    return path, {
        "run_root": path.relative_to(root).as_posix(),
        "manifest_sha256": policy["manifest_sha256"],
        "checksums_sha256": policy["checksums_sha256"],
    }


def reuse_stage(controller: Run, suffix: str, phase: int, selected: Sequence[str]) -> Path:
    source, source_lock = checkpoint(controller.root, controller.config)
    original = json.loads((source / "controller_manifest.json").read_text())
    steps = json.loads((source / "controller_steps.json").read_text())
    name = original["run_id"] + suffix
    record = steps[name]
    path, lock = dependency(controller.root, record["output"], selected, phase)
    manifest = json.loads((path / "manifest.json").read_text())
    reference = json.loads((source / "manifest.json").read_text())
    if (
        record["status"] != "COMPLETE"
        or manifest["selected_project_ids"] != list(selected)
        or any(record[key] != lock[key] for key in ("manifest_sha256", "checksums_sha256"))
        or any(
            manifest[key] != reference[key]
            for key in ("config_sha256", "model_config_sha256", "implementation_sha256")
        )
    ):
        raise ValueError("transport recovery upstream stage changed")
    destination = controller.work / "steps.json"
    current = json.loads(destination.read_text()) if destination.exists() else {}
    current[name] = {**record, "reused_at": utc_now(), "transport_recovery": source_lock}
    atomic_json(destination, current)
    print(f"{utc_now()} REUSED {name}", flush=True)
    return path


def restore_synthesis(run: Run) -> None:
    """Restore all terminal/pending states and budgets, including rejected hypotheses."""
    manifest = json.loads((run.work / "manifest.json").read_text())
    dependencies = manifest["dependencies"]
    if (
        dependencies.get("baseline_id") != "B9"
        or dependencies.get("dry_run")
        or run.selected != selection_ids(run.root, run.config)
    ):
        return
    source, lock = checkpoint(run.root, run.config)
    marker = run.work / "transport_recovery.json"
    if marker.exists():
        if json.loads(marker.read_text())["source"] != lock:
            raise ValueError("transport recovery lineage changed")
        return
    old_manifest = json.loads((source / "manifest.json").read_text())
    if any(dependencies[key] != old_manifest["dependencies"][key] for key in ("phase6", "phase9")):
        raise ValueError("transport recovery discovery/context inputs changed")
    statuses = read_jsonl(source / "project_status.jsonl")
    if (
        len(statuses) != len(run.selected)
        or {r["project_id"] for r in statuses} != set(run.selected)
        or any(r["status"] not in {"SUCCESS", "ANALYSIS_FAILED", "PENDING"} for r in statuses)
    ):
        raise ValueError("transport recovery status coverage changed")
    for relative in ("projects", "query_pack/generated"):
        if (source / relative).exists():
            shutil.copytree(source / relative, run.work / relative, dirs_exist_ok=True)
    if (source / "llm_calls.jsonl").exists():
        shutil.copyfile(source / "llm_calls.jsonl", run.work / "llm_calls.jsonl")
    atomic_jsonl(run.work / "project_status.jsonl", statuses)
    run.statuses = statuses
    manifest["transport_recovery"] = lock
    atomic_json(run.work / "manifest.json", manifest)
    specifications = sum(
        len(read_jsonl(path)) for path in (source / "projects").glob("*/specifications.jsonl")
    )
    atomic_json(
        marker,
        {
            "source": lock,
            "restored_at": utc_now(),
            "project_status_counts": dict(Counter(row["status"] for row in statuses)),
            "specifications": specifications,
            "request_interval_seconds": 90,
            "budget_reset": False,
        },
    )
    message = (
        f"Restored {specifications} specifications; all reservations and terminal states retained"
    )
    with (run.work / "stdout.log").open("a") as handle:
        handle.write(message + "\n")
    print(message, flush=True)
