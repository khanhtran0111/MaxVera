"""Resumable Phase 13 locked-test analyzer pipeline.

This module deliberately stops before evaluator labels, oracle baselines,
fixed-version verification, calibration application, and paper metrics.  Those
steps form the separate evaluator pass and may only start after this analyzer
pass has produced immutable outputs.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.baselines.validate import validate as validate_baseline
from src.common.envfile import effective_env
from src.common.provenance import collect_git, sha256_file, utc_now
from src.reproduction.common import atomic_json, read_csv, read_jsonl

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$")
TEST_SPLIT = "data/processed/splits/test_locked.csv"
DEV_SPLIT = "data/processed/splits/development.csv"
ANALYSIS_MANIFEST = "data/processed/analysis_input/D_extended_projects.csv"
SOURCE_ROOT = "data/interim/phase6_project_sources"
PHASE8_CONFIG = "configs/experiments/phase8_security_kg.yaml"
PHASE8_RUN = "results/graphs/knowledge/p8_skg_global_full_002"


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _write_yaml(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(dict(value), sort_keys=False), encoding="utf-8", newline="\n")


def _checksums(run_root: Path, files: Mapping[str, str]) -> dict[str, str]:
    return {name: sha256_file(run_root / relative) for name, relative in files.items()}


def _lock(run_root: Path, run_id: str, files: Mapping[str, str]) -> dict[str, Any]:
    if not run_root.is_dir():
        raise FileNotFoundError(f"required immutable run is missing: {run_root}")
    return {
        "run_root": run_root.as_posix(),
        "run_id": run_id,
        **_checksums(run_root, files),
    }


def _run(root: Path, command: Sequence[str], *, allow_analysis_failures: bool = False) -> None:
    print(f"$ {' '.join(command)}", flush=True)
    process = subprocess.run(list(command), cwd=root, check=False)
    if process.returncode and not allow_analysis_failures:
        raise RuntimeError(f"command failed with status {process.returncode}: {command[2]}")


def _phase12_lock(root: Path) -> Mapping[str, Any]:
    main = _mapping(root / "configs/experiments/main.yaml")
    if main.get("status") != "frozen":
        raise ValueError("main experiment protocol is not frozen")
    phases = cast(Mapping[str, Any], main.get("development_stages", {}))
    phase12 = cast(
        Mapping[str, Any], phases.get("phase12_calibration_selective_routing", {})
    )
    lock = cast(Mapping[str, Any], phase12.get("canonical_run", {}))
    if lock.get("run_id") != "p12_calibration_dev_full_001":
        raise ValueError("canonical Phase 12 run lock is missing")
    run_root = root / "results/calibration/phase12" / str(lock["run_id"])
    for name, filename in (
        ("manifest_sha256", "manifest.json"),
        ("model_sha256", "model.json"),
        ("thresholds_sha256", "thresholds.json"),
        ("checksums_index_sha256", "checksums.sha256"),
    ):
        if sha256_file(run_root / filename) != lock[name]:
            raise ValueError(f"canonical Phase 12 lock mismatch: {filename}")
    return lock


def preflight(root: Path) -> dict[str, Any]:
    lock = _phase12_lock(root)
    test_rows = read_csv(root / TEST_SPLIT)
    dev_rows = read_csv(root / DEV_SPLIT)
    test_ids = [row["project_id"] for row in test_rows]
    dev_ids = {row["project_id"] for row in dev_rows}
    if len(test_ids) != 24 or len(set(test_ids)) != 24 or set(test_ids) & dev_ids:
        raise ValueError("locked-test split is not the frozen disjoint 24-project set")
    analysis_rows = read_csv(root / ANALYSIS_MANIFEST)
    known = {row["project_id"] for row in analysis_rows}
    if set(test_ids) - known:
        raise ValueError("locked-test split contains unknown opaque IDs")
    missing_sources = [
        project_id for project_id in test_ids if not (root / SOURCE_ROOT / project_id).is_dir()
    ]
    if missing_sources:
        raise FileNotFoundError(f"{len(missing_sources)} locked-test source aliases are missing")
    machine = effective_env(root / ".env")
    phase8 = root / PHASE8_RUN
    if not phase8.is_dir():
        raise FileNotFoundError("canonical Phase 8 Security KG is missing")
    return {
        "schema_version": 1,
        "checked_at": utc_now(),
        "status": "READY_FOR_LONG_ANALYZER_RUN",
        "locked_test_projects": len(test_ids),
        "development_projects": len(dev_ids),
        "sources_available": len(test_ids),
        "openrouter_key_configured": bool(machine.get("OPENROUTER_API_KEY")),
        "codeql_configured": bool(machine.get("MAXVERA_CODEQL_HOME")),
        "phase8_run": PHASE8_RUN,
        "phase12_run_id": lock["run_id"],
        "phase12_model_sha256": lock["model_sha256"],
        "phase12_thresholds_sha256": lock["thresholds_sha256"],
        "git": collect_git(root),
        "long_running": True,
        "evaluator_labels_opened": False,
    }


class AnalyzerPipeline:
    def __init__(self, root: Path, run_id: str, *, confirm_api_spend: bool) -> None:
        self.root = root
        self.run_id = run_id
        self.confirm_api_spend = confirm_api_spend
        self.run_root = root / "results/phase13" / run_id
        self.config_root = self.run_root / "configs"
        self.analysis_root = self.run_root / "analysis"
        self.db_root = root / "data/interim/phase13_codeql_databases" / run_id
        self.db_manifest = root / "data/interim/phase13_database_manifests" / f"{run_id}.json"
        self.db_status = root / "data/interim/phase13_database_status" / f"{run_id}.jsonl"
        self.db_logs = root / "data/interim/phase13_database_logs" / run_id

    @property
    def p6_id(self) -> str:
        return f"{self.run_id}_p6"

    @property
    def p7_id(self) -> str:
        return f"{self.run_id}_p7"

    @property
    def p9_id(self) -> str:
        return f"{self.run_id}_p9"

    def p10_id(self, baseline: str) -> str:
        return f"{self.run_id}_{baseline.lower()}"

    def _path(self, path: Path) -> str:
        return _relative(self.root, path)

    def _phase6_config(self) -> Path:
        config = copy.deepcopy(_mapping(self.root / "configs/experiments/phase6_hypotheses.yaml"))
        config.update(
            {
                "protocol_version": "1.9.0",
                "experiment_id": "phase13_test_hypotheses",
                "status": "frozen_phase_13_test_analysis",
                "purpose": "locked_test_zero_hint_analysis_without_labels",
                "paper_main_result": True,
                "analysis_scope": "test_locked",
            }
        )
        dataset = cast(dict[str, Any], config["dataset"])
        dataset.pop("development_split", None)
        dataset.pop("forbidden_test_split", None)
        dataset["analysis_split"] = TEST_SPLIT
        dataset["holdout_split"] = DEV_SPLIT
        config.pop("selection_lock", None)
        path = self.config_root / "phase6.yaml"
        _write_yaml(path, config)
        return path

    def foundations(self) -> None:
        p6_config = self._phase6_config()
        p6_root = self.analysis_root / "hypotheses/static" / self.p6_id
        if not p6_root.exists():
            command = [
                sys.executable,
                "-m",
                "src.hypotheses.runner",
                "--repo-root",
                str(self.root),
                "--config",
                self._path(p6_config),
                "--run-id",
                self.p6_id,
                "--mode",
                "full",
                "--generator",
                "static",
                "--output-root",
                self._path(self.analysis_root / "hypotheses"),
            ]
            if (p6_root.parent / f".{self.p6_id}.inprogress").is_dir():
                command.append("--resume")
            _run(
                self.root,
                command,
                allow_analysis_failures=True,
            )
        phase6_lock = _lock(
            p6_root,
            self.p6_id,
            {
                "manifest_sha256": "manifest.json",
                "hypotheses_sha256": "hypotheses.jsonl",
                "project_status_sha256": "project_status.jsonl",
                "checksums_index_sha256": "checksums.sha256",
            },
        )
        phase6_lock.update({"ranking_version": "phase6-family-balanced-v2", "top_k": 10})

        p7_config_data = copy.deepcopy(
            _mapping(self.root / "configs/experiments/phase7_program_graph.yaml")
        )
        p7_config_data.update(
            {
                "protocol_version": "1.9.0",
                "experiment_id": "phase13_test_program_graph",
                "status": "frozen_phase_13_test_analysis",
                "purpose": "locked_test_source_backed_program_graph_without_labels",
                "analysis_scope": "test_locked",
                "phase6_lock": phase6_lock,
            }
        )
        p7_dataset = cast(dict[str, Any], p7_config_data["dataset"])
        p7_dataset.pop("development_split", None)
        p7_dataset.pop("forbidden_test_split", None)
        p7_dataset.update(
            {
                "analysis_split": TEST_SPLIT,
                "holdout_split": DEV_SPLIT,
                "database_root": self._path(self.db_root),
                "database_preparation_manifest": self._path(self.db_manifest),
                "database_build_status": self._path(self.db_status),
            }
        )
        p7_config_data.pop("selection_lock", None)
        p7_config = self.config_root / "phase7.yaml"
        _write_yaml(p7_config, p7_config_data)

        if not self.db_manifest.exists():
            _run(
                self.root,
                [
                    sys.executable,
                    "-m",
                    "src.graphs.program.prepare",
                    "--repo-root",
                    str(self.root),
                    "--analysis-split",
                    TEST_SPLIT,
                    "--target-database-root",
                    self._path(self.db_root),
                    "--preparation-manifest",
                    self._path(self.db_manifest),
                    "--analysis-scope",
                    "test_locked",
                ],
            )
        _run(
            self.root,
            [
                sys.executable,
                "-m",
                "src.graphs.program.build_databases",
                "--repo-root",
                str(self.root),
                "--config",
                self._path(p7_config),
                "--database-root",
                self._path(self.db_root),
                "--status-path",
                self._path(self.db_status),
                "--log-root",
                self._path(self.db_logs),
                "--build-mode",
                "auto",
            ],
            allow_analysis_failures=True,
        )
        p7_root = self.analysis_root / "program_graph" / self.p7_id
        if not p7_root.exists():
            command = [
                sys.executable,
                "-m",
                "src.graphs.program.runner",
                "--repo-root",
                str(self.root),
                "--config",
                self._path(p7_config),
                "--run-id",
                self.p7_id,
                "--mode",
                "full",
                "--output-root",
                self._path(self.analysis_root / "program_graph"),
            ]
            if (p7_root.parent / f".{self.p7_id}.inprogress").is_dir():
                command.append("--resume")
            _run(
                self.root,
                command,
                allow_analysis_failures=True,
            )
        p7_lock = _lock(
            p7_root,
            self.p7_id,
            {
                "manifest_sha256": "manifest.json",
                "graph_summary_sha256": "graph_summary.json",
                "project_status_sha256": "project_status.jsonl",
                "checksums_index_sha256": "checksums.sha256",
            },
        )
        statuses = read_jsonl(p7_root / "project_status.jsonl")
        successes = sum(row.get("status") == "SUCCESS" for row in statuses)

        p9_config_data = copy.deepcopy(_mapping(self.root / "configs/experiments/phase9_useg.yaml"))
        p9_config_data.update(
            {
                "status": "frozen_phase_13_test_analysis",
                "purpose": "locked_test_cross_layer_evidence_graph_without_labels",
                "analysis_scope": "test_locked",
            }
        )
        phase8_base = cast(
            Mapping[str, Any],
            cast(Mapping[str, Any], p9_config_data["development_dependencies"])["phase8"],
        )
        p9_config_data["development_dependencies"] = {
            "phase6": phase6_lock,
            "phase7": p7_lock,
            "phase8": dict(phase8_base),
        }
        p9_config_data["coverage"] = {
            "expected_full_projects": 24,
            "expected_phase7_successes": successes,
            "expected_phase7_failures": 24 - successes,
            "failures_count_as_miss": True,
        }
        p9_config = self.config_root / "phase9.yaml"
        _write_yaml(p9_config, p9_config_data)
        p9_root = self.analysis_root / "useg" / self.p9_id
        if not p9_root.exists():
            _run(
                self.root,
                [
                    sys.executable,
                    "-m",
                    "src.graphs.useg.runner",
                    "--repo-root",
                    str(self.root),
                    "--config",
                    self._path(p9_config),
                    "--run-id",
                    self.p9_id,
                    "--mode",
                    "full",
                    "--output-root",
                    self._path(self.analysis_root / "useg"),
                ],
            )

    def specifications(self) -> None:
        p9_root = self.analysis_root / "useg" / self.p9_id
        p9_lock = _lock(
            p9_root,
            self.p9_id,
            {
                "manifest_sha256": "manifest.json",
                "useg_summary_sha256": "useg_summary.json",
                "trace_audit_sha256": "trace_audit.json",
                "project_status_sha256": "project_status.jsonl",
                "nodes_sha256": "useg/nodes.jsonl",
                "edges_sha256": "useg/edges.jsonl",
                "checksums_index_sha256": "checksums.sha256",
            },
        )
        statuses = read_jsonl(p9_root / "project_status.jsonl")
        successes = sum(row.get("status") == "SUCCESS" for row in statuses)
        config = copy.deepcopy(
            _mapping(self.root / "configs/experiments/phase10_retrieval_specification.yaml")
        )
        config.update(
            {
                "status": "frozen_phase_13_test_analysis",
                "purpose": "locked_test_retrieval_and_specification_without_labels",
                "analysis_scope": "test_locked",
                "development_dependency": {"phase9": p9_lock},
            }
        )
        cast(dict[str, Any], config["dataset"])["forbidden_test_split"] = DEV_SPLIT
        config["coverage"] = {
            "expected_full_projects": 24,
            "expected_phase9_successes": successes,
            "expected_phase9_failures": 24 - successes,
            "failures_count_as_miss": True,
        }
        config_path = self.config_root / "phase10.yaml"
        _write_yaml(config_path, config)
        if not self.confirm_api_spend:
            raise ValueError("specification stage requires --confirm-api-spend")
        for baseline in ("B6", "B7", "B8", "B9"):
            name = {
                "B6": "program_graph_only",
                "B7": "security_kg_only",
                "B8": "useg_no_pruning",
                "B9": "full_useg",
            }[baseline]
            final = self.analysis_root / "specifications" / name / self.p10_id(baseline)
            if final.exists():
                continue
            baseline_config = self.root / {
                "B6": "configs/baselines/b6_program_graph_only.yaml",
                "B7": "configs/baselines/b7_security_kg_only.yaml",
                "B8": "configs/baselines/b8_useg_no_pruning.yaml",
                "B9": "configs/baselines/b9_full_useg.yaml",
            }[baseline]
            command = [
                    sys.executable,
                    "-m",
                    "src.specification.runner",
                    "--repo-root",
                    str(self.root),
                    "--baseline-id",
                    baseline,
                    "--config",
                    self._path(baseline_config),
                    "--experiment",
                    self._path(config_path),
                    "--run-id",
                    self.p10_id(baseline),
                    "--mode",
                    "full",
                    "--budget-mode",
                    "budget_matched",
                    "--confirm-api-spend",
                    "--output-root",
                    self._path(self.analysis_root / "specifications"),
                ]
            if (final.parent / f".{self.p10_id(baseline)}.inprogress").is_dir():
                command.append("--resume")
            _run(self.root, command, allow_analysis_failures=True)

    def controlled_baselines(self) -> None:
        b0_root = self.analysis_root / "b0" / f"{self.run_id}_b0"
        if not b0_root.exists():
            command = [
                sys.executable,
                "-m",
                "src.experiments.phase13_b0",
                "--repo-root",
                str(self.root),
                "--run-id",
                f"{self.run_id}_b0",
                "--database-root",
                self._path(self.db_root),
                "--output-root",
                self._path(self.analysis_root / "b0"),
            ]
            if (b0_root.parent / f".{self.run_id}_b0.inprogress").is_dir():
                command.append("--resume")
            _run(
                self.root,
                command,
            )
        config = copy.deepcopy(_mapping(self.root / "configs/experiments/phase5_baselines.yaml"))
        config.update(
            {
                "protocol_version": "1.9.0",
                "experiment_id": "phase13_test_controlled_baselines",
                "status": "frozen_phase_13_test_analysis",
                "purpose": "locked_test_zero_hint_controlled_comparison",
                "paper_main_result": True,
                "analysis_scope": "test_locked",
            }
        )
        config["dataset"] = {
            "id": "D_extended",
            "analysis_manifest": ANALYSIS_MANIFEST,
            "source_root": SOURCE_ROOT,
            "default_split": TEST_SPLIT,
            "holdout_split": DEV_SPLIT,
        }
        config_path = self.config_root / "phase13_baselines.yaml"
        _write_yaml(config_path, config)
        for baseline, filename, name in (
            ("B5", "configs/baselines/b5_static_hypothesis.yaml", "static_hypothesis"),
            ("B3", "configs/baselines/b3_raw_context.yaml", "raw_context_gptoss20b"),
            ("B4", "configs/baselines/b4_text_rag.yaml", "text_rag_gptoss20b"),
        ):
            run_id = f"{self.run_id}_{baseline.lower()}"
            final = self.analysis_root / "baselines" / name / run_id
            if final.exists():
                continue
            if baseline in {"B3", "B4"} and not self.confirm_api_spend:
                raise ValueError("B3/B4 stages require --confirm-api-spend")
            command = [
                sys.executable,
                "-m",
                "src.baselines.runner",
                "--repo-root",
                str(self.root),
                "--baseline-id",
                baseline,
                "--config",
                filename,
                "--experiment",
                self._path(config_path),
                "--split",
                TEST_SPLIT,
                "--run-id",
                run_id,
                "--mode",
                "full",
                "--budget-mode",
                "budget_matched",
                "--output-root",
                self._path(self.analysis_root / "baselines"),
            ]
            if baseline in {"B3", "B4"}:
                command.append("--confirm-api-spend")
            if (final.parent / f".{run_id}.inprogress").is_dir():
                command.append("--resume")
            _run(self.root, command, allow_analysis_failures=True)

            # A recorded project failure is valid; a runner setup error is not.
            print(validate_baseline(final, require_metrics=False), flush=True)

    def snapshot(self, stage: str) -> None:
        self.run_root.mkdir(parents=True, exist_ok=True)
        atomic_json(
            self.run_root / "analyzer_status.json",
            {
                "schema_version": 1,
                "updated_at": utc_now(),
                "run_id": self.run_id,
                "last_requested_stage": stage,
                "analysis_scope": "test_locked",
                "locked_test_labels_opened": False,
                "evaluator_pass_started": False,
                "phase12_lock": dict(_phase12_lock(self.root)),
                "outputs": {
                    "phase6": self._path(self.analysis_root / "hypotheses/static" / self.p6_id),
                    "phase7": self._path(self.analysis_root / "program_graph" / self.p7_id),
                    "phase9": self._path(self.analysis_root / "useg" / self.p9_id),
                    "phase10_root": self._path(self.analysis_root / "specifications"),
                    "controlled_baselines_root": self._path(self.analysis_root / "baselines"),
                    "b0": self._path(self.analysis_root / "b0" / f"{self.run_id}_b0"),
                },
            },
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument(
        "--stage",
        choices=("preflight", "foundations", "specifications", "baselines", "all"),
        default="preflight",
    )
    parser.add_argument("--confirm-open-locked-test", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    if not RUN_ID.fullmatch(args.run_id):
        parser.error("run ID must be 1-50 safe filename characters")
    try:
        report = preflight(root)
        if args.stage == "preflight":
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if not args.confirm_open_locked_test:
            raise ValueError("analysis stages require --confirm-open-locked-test")
        if os.environ.get("MAXVERA_DATA_ROLE") != "analyzer":
            raise ValueError("export MAXVERA_DATA_ROLE=analyzer before locked-test analysis")
        git = cast(Mapping[str, Any], report["git"])
        if git.get("dirty") is not False:
            raise RuntimeError("Phase 13 full analysis requires a clean Git worktree")
        pipeline = AnalyzerPipeline(root, args.run_id, confirm_api_spend=args.confirm_api_spend)
        if args.stage in {"foundations", "all"}:
            pipeline.foundations()
        if args.stage in {"specifications", "all"}:
            pipeline.specifications()
        if args.stage in {"baselines", "all"}:
            pipeline.controlled_baselines()
        pipeline.snapshot(args.stage)
        print(f"Phase 13 analyzer stage completed: {pipeline.run_root}")
        return 0
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
