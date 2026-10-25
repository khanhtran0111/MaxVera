"""Read-only input validation, with a separate trusted evaluator readiness report."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
from pathlib import Path

from maxvera.contracts import ORACLE_PATTERN, redact
from maxvera.dataset import validate_snapshot_manifest
from maxvera.graph import relative_file


def build_recipe_issues(source: Path, build: object) -> list[dict]:
    """Check recipe shape and executable availability without running build commands."""
    issues = []

    def issue(code, message):
        issues.append({"code": code, "message": message})

    if (
        not isinstance(build, dict)
        or "attempts" not in build
        or set(build) - {"attempts", "recipe", "dependencies", "not_benchmark_maven_build"}
        or not isinstance(build.get("attempts"), list)
        or not build["attempts"]
    ):
        issue("BUILD_RECIPE_INVALID", "build.runtime.json requires a nonempty attempts array")
        return issues
    if any(
        not isinstance(build[name], str) or not build[name] or len(build[name]) > 2048
        for name in ("recipe", "dependencies")
        if name in build
    ) or (
        "not_benchmark_maven_build" in build
        and type(build["not_benchmark_maven_build"]) is not bool
    ):
        issue("BUILD_RECIPE_INVALID", "build recipe informational metadata invalid")
    usable = 0
    unavailable = []
    for index, attempt in enumerate(build["attempts"]):
        if (
            not isinstance(attempt, dict)
            or set(attempt) != {"command", "environment"}
            or not isinstance(attempt["command"], list)
            or not attempt["command"]
            or any(not isinstance(v, str) or not v or "\0" in v for v in attempt["command"])
            or not isinstance(attempt["environment"], dict)
            or set(attempt["environment"]) - {"JAVA_HOME", "PATH", "MAVEN_OPTS"}
            or any(
                not isinstance(v, str) or not v or "\0" in v
                for v in attempt["environment"].values()
            )
        ):
            issue(
                "BUILD_RECIPE_INVALID",
                f"attempt {index} requires argv and trusted string environment",
            )
            continue
        if "MAVEN_OPTS" in attempt["environment"]:
            try:
                options = shlex.split(attempt["environment"]["MAVEN_OPTS"])
            except ValueError:
                options = []
            if (
                not options
                or len(options) > 8
                or any(
                    not re.fullmatch(
                        r"-Xmx[1-9][0-9]*[mMgG]|-Djava\.net\.preferIPv4Stack=(?:true|false)", option
                    )
                    for option in options
                )
            ):
                issue("BUILD_RECIPE_INVALID", f"attempt {index} has unsupported MAVEN_OPTS")
                continue
        if ORACLE_PATTERN.search(json.dumps(attempt)) or "evaluator_only" in json.dumps(attempt):
            issue("BUILD_RECIPE_INVALID", f"attempt {index} contains protected analyzer metadata")
            continue
        executable = attempt["command"][0]
        if "/" in executable:
            path = Path(executable)
            resolved = path if path.is_absolute() else source / path
            available = resolved.is_file() and os.access(resolved, os.X_OK)
        else:
            available = (
                shutil.which(executable, path=attempt["environment"].get("PATH")) is not None
            )
        java = attempt["environment"].get("JAVA_HOME")
        if java:
            available = available and (Path(java) / "bin/java").is_file()
        if available:
            usable += 1
        else:
            unavailable.append(index)
    if not usable:
        issue(
            "BUILD_TOOL_UNAVAILABLE",
            f"no usable prepared build attempt; unavailable indexes={unavailable}",
        )
    return issues


def input_preflight(root: Path, cases: list[dict]) -> dict:
    """Validate every selected analyzer input; never access evaluator metadata or execute tools."""
    view = (root / "data/processed/analysis_input").resolve()
    rows = []
    for case in cases:
        row = {"case_id": case["case_id"], "ready": False, "issues": []}
        issues = row["issues"]
        try:
            relative = relative_file(case["source_dir"])
            candidate = view / relative
            if any(
                p.is_symlink() for p in (candidate, *candidate.parents) if p.is_relative_to(view)
            ):
                raise ValueError("source path contains a symlink")
            source = candidate.resolve()
            if not source.is_relative_to(view):
                raise ValueError("source path escapes analysis_input")
        except (KeyError, ValueError, OSError) as error:
            issues.append({"code": "SOURCE_PATH_INVALID", "message": redact(str(error))})
            rows.append(row)
            continue
        if not source.is_dir():
            issues.append(
                {"code": "SOURCE_MISSING", "message": "prepared source directory missing"}
            )
            rows.append(row)
            continue
        recipe = source / "build.runtime.json"
        if not recipe.is_file() or recipe.is_symlink():
            issues.append(
                {"code": "BUILD_RECIPE_MISSING", "message": "trusted build.runtime.json missing"}
            )
        else:
            try:
                issues.extend(build_recipe_issues(source, json.loads(recipe.read_text())))
            except (ValueError, OSError) as error:
                issues.append({"code": "BUILD_RECIPE_INVALID", "message": redact(str(error))})
        manifest = source / "snapshot.files.json"
        if not manifest.is_file() or manifest.is_symlink():
            issues.append(
                {
                    "code": "SNAPSHOT_MANIFEST_MISSING",
                    "message": ("snapshot needs verified preparation provenance; source preserved"),
                }
            )
        else:
            try:
                verified = validate_snapshot_manifest(source, case["case_id"])
                row["semantic_snapshot_id"] = verified["semantic_snapshot_id"]
                row["source_files"] = len(verified["files"])
                row["preparation_policy"] = verified["provenance"]["preparation_policy"]
            except (ValueError, OSError, TypeError, KeyError) as error:
                code = (
                    "LEGACY_PROVENANCE_REQUIRED" if "legacy" in str(error) else "SNAPSHOT_INVALID"
                )
                issues.append({"code": code, "message": redact(str(error))})
        row["ready"] = not issues
        rows.append(row)
    return {
        "schema_version": "1.0",
        "ready": bool(rows) and all(r["ready"] for r in rows),
        "selected_cases": len(rows),
        "ready_cases": sum(r["ready"] for r in rows),
        "cases": rows,
        "network_requests": 0,
        "tool_invocations": 0,
        "evaluator_inputs_read": False,
    }


def readiness_preflight(
    root, config, cases, variant, mode, *, truth_alignment=None, experiment_protocol=None
):
    """Trusted standalone report: combine pure inputs with evaluator and experiment gates."""
    if os.environ.get("MAXVERA_DATA_ROLE") == "analysis":
        raise ValueError("trusted readiness preflight is unavailable inside the analyzer")
    from maxvera.evaluation import _range
    from maxvera.truth_alignment import alignment_report, load_mapping
    from src.common.provenance import sha256_file
    from src.reproduction.common import read_csv, read_jsonl

    inputs = input_preflight(root, cases)
    issues = []
    ids = {case["case_id"] for case in cases}
    dataset = config.dataset
    prefix = "D_extended" if "extended" in dataset.get("config", "") else "D_repro_v1"
    truth_report = {
        "selected_cases": len(ids),
        "label_cases": 0,
        "truth_cases": 0,
        "truth_record_cases": 0,
        "aligned_truth_cases": 0,
        "missing_label_case_ids": sorted(ids),
        "missing_truth_case_ids": sorted(ids),
        "missing_span_case_ids": [],
        "ready": False,
    }
    try:
        labels = read_csv(root / f"data/processed/evaluator_only/{prefix}_labels.csv")
        labeled = {r["project_id"] for r in labels if r.get("ground_truth_cwe")}
        truth_path = root / f"data/processed/evaluator_only/{prefix}_fix_locations.jsonl"
        truths = read_jsonl(truth_path)
        present = {r["project_id"] for r in truths if r.get("project_id")}
        located = {
            r["project_id"]
            for r in truths
            if r.get("project_id") and r.get("file") and _range(r)[1] is not None
        }
        truth_report.update(
            {
                "label_cases": len(ids & labeled),
                "truth_cases": len(ids & located),
                "truth_record_cases": len(ids & present),
                "missing_label_case_ids": sorted(ids - labeled),
                "missing_truth_case_ids": sorted(ids - present),
                "missing_span_case_ids": sorted((ids & present) - located),
                "ready": ids <= labeled and ids <= present,
            }
        )
        if not truth_report["ready"]:
            issues.append(
                {
                    "code": "GROUND_TRUTH_INCOMPLETE",
                    "message": "selected evaluator coverage incomplete",
                }
            )
        from collections import defaultdict

        truth_index = defaultdict(list)
        for row in truths:
            truth_index[row["project_id"]].append(row)
        mapping, identity = load_mapping(truth_alignment, sha256_file(truth_path))
        alignment, _ = alignment_report(
            root, cases, {r["project_id"]: r for r in labels}, truth_index, mapping=mapping
        )
        truth_report["aligned_truth_cases"] = alignment["aligned_cases"]
        truth_report["alignment"] = alignment
        truth_report["alignment_identity"] = identity
        truth_report["ready"] = truth_report["ready"] and alignment["ready"]
        if not alignment["ready"]:
            issues.append(
                {
                    "code": "GROUND_TRUTH_UNALIGNED",
                    "message": "selected annotations are not verified against vulnerable source",
                }
            )
    except (ValueError, OSError, KeyError, TypeError) as error:
        issues.append({"code": "GROUND_TRUTH_UNAVAILABLE", "message": redact(str(error))})
    for name in ("research_binary", "generic_suite"):
        value = config.codeql.get(name)
        if not value or not (root / value).is_file():
            issues.append({"code": "TOOL_INPUT_MISSING", "message": f"configured {name} missing"})
    approved = config.research.get("graph_signal_approved") is True
    approval_required = mode == "full" and variant.get("llm_enabled")
    if approval_required and not approved and experiment_protocol is None:
        issues.append(
            {
                "code": "GRAPH_SIGNAL_NOT_APPROVED",
                "message": "full LLM research requires reviewed frozen development signal",
            }
        )
    return {
        "schema_version": "1.0",
        "ready": inputs["ready"] and not issues,
        "execution_ready": inputs["ready"]
        and not any(
            issue["code"] in {"TOOL_INPUT_MISSING", "GRAPH_SIGNAL_NOT_APPROVED"} for issue in issues
        ),
        "evaluation_ready": truth_report["ready"],
        "scientific_approved": False,
        "execution_policy": experiment_protocol["purpose"]
        if experiment_protocol
        else "reviewed_signal",
        "mode": mode,
        "variant": variant["name"],
        "input_preflight": inputs,
        "ground_truth_coverage": truth_report,
        "graph_signal": {"approved": approved, "required_for_execution": bool(approval_required)},
        "issues": issues,
        "network_requests": 0,
        "tool_invocations": 0,
    }
