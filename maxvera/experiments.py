"""Trusted prospective exploratory protocols, separate from scientific approval."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
from pathlib import Path

import yaml

from maxvera.contracts import digest, safe_id
from maxvera.orchestration import verify_checksums
from maxvera.preflight import input_preflight
from src.common.provenance import sha256_file, utc_now
from src.reproduction.common import read_csv, read_jsonl

PURPOSE = "exploratory_full_execution"
POLICY = "prospective-exploratory-v1"


def _trusted():
    if os.environ.get("MAXVERA_DATA_ROLE") == "analysis":
        raise ValueError("experiment registration is unavailable inside the analyzer")


def _tree_identity(path):
    if not path.is_dir():
        return None
    return digest(
        {
            p.relative_to(path).as_posix(): sha256_file(p)
            for p in sorted(path.rglob("*"))
            if p.is_file()
        }
    )


def _runtime_inputs(root, config, cases):
    tools = {
        name: sha256_file(root / config.codeql[name])
        for name in ("research_binary", "generic_suite")
        if name in config.codeql
    }
    if config.codeql.get("research_binary"):
        distribution = (root / config.codeql["research_binary"]).resolve().parent
        for name in ("tools", "java", "qlpacks/codeql"):
            tools[name] = _tree_identity(distribution / name)
    executables, homes = {}, set()
    analysis = root / "data/processed/analysis_input"
    install = (root / ".cache/toolchains").resolve()
    for case in cases:
        source = analysis / case["source_dir"]
        recipe = json.loads((source / "build.runtime.json").read_text())
        for attempt in recipe["attempts"]:
            executable = attempt["command"][0]
            if "/" not in executable:
                executable = shutil.which(
                    executable, path=attempt["environment"].get("PATH", os.environ.get("PATH"))
                )
            if executable is None:
                executables[attempt["command"][0]] = "UNAVAILABLE"
                continue
            path = Path(executable)
            if not path.is_absolute():
                path = source / path
            executables[str(path)] = sha256_file(path) if path.is_file() else "UNAVAILABLE"
            if path.resolve().is_relative_to(install):
                homes.add(path.resolve().parent.parent)
            if attempt["environment"].get("JAVA_HOME"):
                java = Path(attempt["environment"]["JAVA_HOME"]).resolve()
                for name in ("java", "javac"):
                    if (java / "bin" / name).is_file():
                        executables[str(java / "bin" / name)] = sha256_file(java / "bin" / name)
                if java.is_relative_to(install):
                    homes.add(java)
    tools["build_executables"] = digest(executables)
    tools["build_runtime_libraries"] = {
        str(home): {
            name: _tree_identity(home / name)
            for name in ("bin", "lib", "jre", "conf", "boot", "init.d")
        }
        for home in sorted(homes)
    }
    return tools


def _model_runtime(root, config, variant):
    if not variant.get("llm_enabled") or not config.llm.get("model_config"):
        return None
    from src.llm.providers.openrouter import OpenRouterSettings

    settings = OpenRouterSettings.load(root, Path(config.llm["model_config"]))
    if (
        settings.model != config.llm["model"]
        or settings.provider != config.llm["provider_route"]
        or settings.max_tokens != config.llm["max_output_tokens"]
    ):
        raise ValueError("experiment model/profile runtime identity mismatch")
    return {key: value for key, value in dataclasses.asdict(settings).items() if key != "api_key"}


def _condition(root, config, variant, cases, run_id):
    from maxvera.cli import implementation_hash, input_fingerprints
    from maxvera.dataset import select_cases

    if cases != select_cases(root, config.dataset, "full"):
        raise ValueError("experiment input identity must retain the full configured cohort")
    inputs = input_preflight(root, cases)
    if not inputs["ready"]:
        raise ValueError("experiment input snapshots must all pass preflight")
    return {
        "run_id": safe_id(run_id),
        "config": config.resolved(),
        "variant": variant,
        "cases": input_fingerprints(root, cases, research=True),
        "implementation_hash": implementation_hash(root),
        "tool_inputs": _runtime_inputs(root, config, cases),
        "model_runtime": _model_runtime(root, config, variant),
        "development_split_sha256": sha256_file(root / "data/processed/splits/development.csv"),
        "pilot_split_sha256": sha256_file(root / "configs/pipelines/research_pilot10.csv"),
    }


def _development(root, evaluations):
    if len(evaluations) != 2:
        raise ValueError("two paired development evaluations are required")
    allowed = {
        row["project_id"] for row in read_csv(root / "data/processed/splits/development.csv")
    }
    pilot = {row["project_id"] for row in read_csv(root / "configs/pipelines/research_pilot10.csv")}
    receipts, conditions, variants = [], [], []
    for supplied in evaluations:
        output = (root / supplied).resolve()
        base = (root / "results/evaluations").resolve()
        if not output.is_relative_to(base):
            raise ValueError("development evaluation must be an immutable evaluator output")
        verify_checksums(output)
        metrics = json.loads((output / "metrics_aggregate.json").read_text())
        evaluator = json.loads((output / "evaluator_manifest.json").read_text())
        ids = metrics.get("case_ids", [])
        if not ids or len(set(ids)) != len(ids) or set(ids) != pilot or not set(ids) <= allowed:
            raise ValueError(
                "development measurement must retain the fixed pilot and exclude locked cases"
            )
        condition = metrics.get("condition_manifest")
        if (
            metrics.get("panel") != "zero_hint"
            or evaluator.get("protocol") != "zero_hint"
            or not condition
            or metrics.get("condition_hash") != digest(condition)
            or condition.get("mode") != "full"
            or set(condition.get("case_ids", [])) != set(ids)
            or metrics.get("cases") != len(ids)
            or metrics.get("evaluable_subset", {}).get("denominator", 0) < 1
        ):
            raise ValueError(
                "development measurement requires explicit evaluable paired conditions"
            )
        run_id = output.relative_to(base).parts[0]
        run = root / "results/research" / safe_id(run_id)
        verify_checksums(run)
        manifest = json.loads((run / "manifest.json").read_text())
        status = (run / "STATUS").read_text().strip()
        settings = yaml.safe_load((run / "config.resolved.yaml").read_text())
        variant = settings.get("selected_variant", {}).get("name")
        if (
            manifest.get("pipeline") != "research"
            or manifest.get("mode") != "full"
            or set(manifest.get("case_ids", [])) != set(ids)
            or status not in {"COMPLETED", "COMPLETED_WITH_CASE_FAILURES"}
            or evaluator.get("run_hash") != sha256_file(run / "checksums.sha256")
            or variant not in {"static_only", "graph_only"}
            or settings.get("selected_variant", {}).get("llm_enabled") is not False
        ):
            raise ValueError(
                "paired static_only and graph_only frozen development runs are required"
            )
        from maxvera.evaluation import condition_manifest

        expected = condition_manifest(
            run,
            manifest,
            settings,
            evaluator["evaluator_identity"],
            evaluator["labels_hash"],
            evaluator["truth_hash"],
            "zero_hint",
        )
        alignment_cases = metrics.get("truth_coverage", {}).get("alignment", {}).get("cases", [])
        if (
            len(alignment_cases) != len(ids)
            or {row["case_id"] for row in alignment_cases} != set(ids)
            or evaluator.get("missing_truth_policy") not in {"error", "report"}
        ):
            raise ValueError("development evaluation condition lacks complete alignment accounting")
        expected.update(
            {
                "missing_truth_policy": evaluator["missing_truth_policy"],
                "truth_alignment": evaluator["truth_alignment"],
                "aligned_source_identities": {
                    row["case_id"]: {
                        key: row[key]
                        for key in (
                            "source_commit",
                            "source_inventory_sha256",
                            "preparation_manifest_sha256",
                        )
                        if key in row
                    }
                    for row in alignment_cases
                },
            }
        )
        if condition != expected or evaluator.get("condition_hash") != digest(expected):
            raise ValueError("development evaluation condition differs from its frozen run")
        per_case = read_jsonl(output / "metrics_per_case.jsonl")
        if (
            len(per_case) != len(ids)
            or {row["case_id"] for row in per_case} != set(ids)
            or any(type(row.get("ground_truth_evaluable")) is not bool for row in per_case)
            or metrics["evaluable_subset"]["denominator"]
            != sum(row["ground_truth_evaluable"] for row in per_case)
        ):
            raise ValueError("development evaluable count differs from complete per-case rows")
        receipts.append(
            {
                "evaluation": output.relative_to(root).as_posix(),
                "run_id": run_id,
                "variant": variant,
                "run_sha256": evaluator["run_hash"],
                "evaluation_sha256": sha256_file(output / "checksums.sha256"),
                "condition_hash": metrics["condition_hash"],
                "cases": len(ids),
                "evaluable_cases": metrics["evaluable_subset"]["denominator"],
                "whole_cohort_recall_at_5": (metrics.get("discovery_recall_at_k") or {}).get("5"),
                "status": status,
            }
        )
        conditions.append(metrics["condition_hash"])
        variants.append(variant)
    if set(variants) != {"static_only", "graph_only"} or len(set(conditions)) != 1:
        raise ValueError("static_only and graph_only development measurements must be paired")
    return receipts


def register_experiment(
    root, config, variant, cases, *, run_id, output, development_evaluations, rationale
):
    """Freeze an explicit policy amendment before its run exists; never approve a signal."""
    _trusted()
    root, output = Path(root).resolve(), Path(output)
    if not output.is_absolute():
        output = root / output
    if output.exists() or output.is_symlink():
        raise ValueError("experiment protocol is immutable; choose a new output")
    safe_id(run_id)
    if any(
        (root / "results" / area / run_id).exists()
        for area in ("research", "_smoke/research", "reproduction", "_smoke/reproduction")
    ):
        raise ValueError("prospective experiment run ID already exists")
    if (
        config.pipeline != "research"
        or not isinstance(rationale, str)
        or len(rationale.strip()) < 20
    ):
        raise ValueError("research experiment requires an explicit development review rationale")
    development = _development(root, development_evaluations)
    condition = _condition(root, config, variant, cases, run_id)
    record = {
        "schema_version": "1.0",
        "policy": POLICY,
        "purpose": PURPOSE,
        "created_at": utc_now(),
        "scientific_approved": False,
        "condition": condition,
        "condition_sha256": digest(condition),
        "development_measurement": development,
        "review_rationale": rationale.strip(),
        "policy_amendment": "Exploratory execution after development measurement; positive pilot "
        "expansion criteria remain unsatisfied and confer no scientific approval.",
        "unknown_truth_policy": "KEEP_COHORT_REPORT_NULL",
        "locked_case_policy": "NO_TUNING_FROM_LOCKED_RESULTS",
        "failure_policy": "KEEP_EVERY_SELECTED_CASE_AND_TERMINAL_FAILURE",
    }
    # Exclusive creation makes the registration immutable even if two CLI
    # invocations target the same path. A partial write cannot validate.
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
        handle.write("\n")
    return output


def validate_experiment(root, config, variant, cases, *, run_id, protocol):
    _trusted()
    root, protocol = Path(root).resolve(), Path(protocol)
    if not protocol.is_absolute():
        protocol = root / protocol
    if protocol.is_symlink() or not protocol.is_file():
        raise ValueError("experiment protocol missing or unsafe")
    record = json.loads(protocol.read_text())
    if (
        record.get("schema_version") != "1.0"
        or record.get("policy") != POLICY
        or record.get("purpose") != PURPOSE
        or record.get("scientific_approved") is not False
        or record.get("unknown_truth_policy") != "KEEP_COHORT_REPORT_NULL"
        or record.get("locked_case_policy") != "NO_TUNING_FROM_LOCKED_RESULTS"
        or record.get("failure_policy") != "KEEP_EVERY_SELECTED_CASE_AND_TERMINAL_FAILURE"
    ):
        raise ValueError("unsupported exploratory experiment protocol")
    condition = _condition(root, config, variant, cases, run_id)
    if record.get("condition") != condition or record.get("condition_sha256") != digest(condition):
        raise ValueError("experiment identity changed; register a new prospective run")
    evaluations = [Path(r["evaluation"]) for r in record["development_measurement"]]
    if _development(root, evaluations) != record["development_measurement"]:
        raise ValueError("development evidence identity changed")
    # No evaluator paths, labels, per-case metrics or review text cross the firewall.
    return {
        "schema_version": "1.0",
        "policy": POLICY,
        "purpose": PURPOSE,
        "protocol_sha256": sha256_file(protocol),
        "scientific_approved": False,
        "model_runtime_sha256": digest(condition["model_runtime"]),
    }
