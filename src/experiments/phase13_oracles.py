"""Resumable B1/B2 oracle references for the sealed Phase 13 test split."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.baselines.runner import _usage
from src.baselines.validate import _verify_checksums
from src.common.envfile import effective_env
from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.experiments.phase13 import RUN_ID
from src.experiments.phase13_snapshot import validate_snapshot
from src.llm.providers.openrouter import OpenRouterSettings
from src.reproduction.common import (
    aggregate_metrics,
    atomic_json,
    atomic_jsonl,
    evaluate_sarif,
    read_csv,
    read_jsonl,
    write_checksums,
)
from src.reproduction.runner import (
    IRIS_COMMIT,
    _codeql_binary,
    _codeql_version,
    _git_head,
    _resolve_query,
)


def workspace(root: Path, run_id: str, projects: list[str], databases: Path) -> dict[str, Path]:
    base = root / "data/interim/phase13_oracles" / run_id
    paths = {
        key: base / value
        for key, value in {
            "source": "project-sources",
            "database": "codeql-dbs",
            "packages": "package-names",
            "queries": "query-pack",
        }.items()
    }
    for directory in paths.values():
        directory.mkdir(parents=True, exist_ok=True)
    (paths["queries"] / "myqueries").mkdir(exist_ok=True)
    (paths["queries"] / "ext").mkdir(exist_ok=True)
    (paths["queries"] / "qlpack.yml").write_text(
        "name: maxvera/iris-phase13-adapter\nversion: 0.0.1\n"
        "extractor: java\ndependencies:\n  codeql/java-all: 9.2.2\n"
    )
    for project in projects:
        slug = "maxvera__" + project  # IRIS's fourth underscore component is opaque, never a CVE.
        source = root / "data/interim/phase6_project_sources" / project
        for link, target in (
            (paths["source"] / slug, source),
            (paths["database"] / slug, databases / project),
        ):
            if link.is_symlink():
                if link.resolve() != target.resolve():
                    raise ValueError("IRIS workspace symlink target changed")
            elif link.exists():
                raise ValueError("IRIS workspace path must be a symlink")
            else:
                link.symlink_to(target.resolve(), target_is_directory=True)
        packages = set()
        for file in source.rglob("*.java"):
            text = file.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
            if match:
                packages.add(match[1])
        (paths["packages"] / f"{slug}.txt").write_text("\n".join(sorted(packages)) + "\n")
    # Give IRIS no fix-location/advisory input. Its internal evaluation is disabled;
    # the parent evaluator scores the final SARIF after all analysis stages finish.
    paths["project_info"] = base / "project_info.csv"
    paths["fix_info"] = base / "fix_info.csv"
    paths["project_info"].write_text("cve_id,fix_commit_ids\n")
    paths["fix_info"].write_text("project_slug,file,class,method,method_start,method_end\n")
    return paths


def run(root: Path, parent_id: str, baseline: str, *, resume: bool = False) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("oracle baselines require evaluator role")
    if not RUN_ID.fullmatch(parent_id) or baseline not in {"B1", "B2"}:
        raise ValueError("invalid oracle run/baseline")
    parent = root / "results/phase13" / parent_id
    snapshot_path = parent / "analyzer_snapshot.json"
    snapshot = validate_snapshot(root, snapshot_path)
    run_id = f"{parent_id}_{baseline.lower()}_oracle"
    final = parent / "evaluation/oracles" / run_id
    work = final.parent / f".{run_id}.inprogress"
    if final.exists():
        _verify_checksums(final)
        validate(final, root)
        return final
    if collect_git(root)["dirty"]:
        raise RuntimeError("canonical oracle execution requires a clean Git worktree")
    if work.exists() and not resume:
        raise FileExistsError("unfinished oracle run exists; use --resume")
    machine = effective_env(root / ".env")
    codeql = _codeql_binary(machine.get("MAXVERA_CODEQL_HOME", ""))
    if not codeql.is_file():
        raise FileNotFoundError("CodeQL is not configured")
    if baseline == "B2":
        OpenRouterSettings.load(root)
        if _git_head(root / "third_party/iris") != IRIS_COMMIT:
            raise ValueError("IRIS upstream commit differs from the frozen pin")
    selected = snapshot["selected_project_ids"]
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    truth_path = root / "data/processed/evaluator_only/D_extended_fix_locations.jsonl"
    labels = {r["project_id"]: r for r in read_csv(labels_path)}
    truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(truth_path):
        truth[row["project_id"]].append(row)
    if set(selected) - labels.keys():
        raise ValueError("oracle test labels have incomplete coverage")
    databases = root / "data/interim/phase13_codeql_databases" / parent_id
    inputs = {
        "analyzer_snapshot_sha256": sha256_file(snapshot_path),
        "labels_sha256": sha256_file(labels_path),
        "fix_locations_sha256": sha256_file(truth_path),
    }
    implementation = {
        "src/experiments/phase13_oracles.py": sha256_file(
            root / "src/experiments/phase13_oracles.py"
        )
    }
    if baseline == "B2":
        implementation["src/experiments/phase13_iris.py"] = sha256_file(
            root / "src/experiments/phase13_iris.py"
        )
    if work.exists():
        manifest = json.loads((work / "manifest.json").read_text())
        if (
            any(manifest.get(k) != v for k, v in inputs.items())
            or manifest["implementation_sha256"] != implementation
        ):
            raise ValueError("oracle resume inputs/implementation changed")
        statuses = read_jsonl(work / "project_status.jsonl")
    else:
        work.mkdir(parents=True)
        statuses = [{"project_id": p, "status": "PENDING"} for p in selected]
        atomic_json(
            work / "manifest.json",
            {
                "schema_version": 1,
                "run_id": run_id,
                "parent_run_id": parent_id,
                "baseline_id": baseline,
                "analysis_scope": "test_locked",
                "hint_condition": "oracle_cwe",
                "fair_zero_hint_comparator": False,
                "selected_project_ids": selected,
                "created_at": utc_now(),
                "git": collect_git(root),
                "implementation_sha256": implementation,
                **inputs,
                "codeql_version": _codeql_version(codeql),
                "iris_commit": IRIS_COMMIT if baseline == "B2" else None,
                "budget": {
                    "max_calls": 30,
                    "max_input_tokens_per_call": 8192,
                    "max_output_tokens_per_call": 2048,
                    "max_total_input_tokens": 160000,
                },
                "model_config_sha256": sha256_file(
                    root / "configs/models/gpt_oss_20b_openrouter.yaml"
                )
                if baseline == "B2"
                else None,
                "provider_route": "akashml" if baseline == "B2" else None,
                "temperature": 0.0,
                "seed": 1234,
                "patch_hints_to_iris": False,
                "toolchain_substitution": "main_CodeQL_2.26.2_with_mechanical_IRIS_API_adapter",
                "exact_numerical_reproduction_claim": False,
            },
        )
        atomic_json(work / "environment.json", collect_environment(root))
        (work / "command.txt").write_text(shlex.join(sys.argv) + "\n")
        atomic_jsonl(work / "project_status.jsonl", statuses)
    iris_workspace = workspace(root, run_id, selected, databases) if baseline == "B2" else {}
    resources = read_jsonl(work / "resource_usage.jsonl")
    for position, status in enumerate(statuses, 1):
        if status["status"] in {"SUCCESS", "ANALYSIS_FAILED"}:
            continue
        project = status["project_id"]
        project_root = work / "projects" / project
        project_root.mkdir(parents=True, exist_ok=True)
        database = databases / project
        sarif = project_root / "results.sarif"
        cwe = labels[project]["ground_truth_cwe"]
        log = project_root / "analysis.log"
        started = time.monotonic()
        try:
            if not (database / "codeql-database.yml").is_file():
                raise FileNotFoundError("opaque vulnerable CodeQL database unavailable")
            environment = dict(os.environ)
            if baseline == "B1":
                command = [
                    str(codeql),
                    "database",
                    "analyze",
                    "--rerun",
                    "--threads=4",
                    "--ram=16384",
                    "--format=sarif-latest",
                    f"--output={sarif}",
                    str(database),
                    _resolve_query(root, baseline, cwe, codeql),
                ]
            else:
                slug = "maxvera__" + project
                upstream = work / "upstream_output"
                command = [
                    sys.executable,
                    "-m",
                    "src.experiments.phase13_iris",
                    "--iris-root",
                    str(root / "third_party/iris"),
                    "--project",
                    slug,
                    "--cwe",
                    cwe.split("-")[1],
                    "--run-id",
                    run_id,
                    "--codeql-home",
                    str(codeql.parent),
                    "--codeql-ram-mb",
                    "16384",
                    "--database-root",
                    str(iris_workspace["database"]),
                    "--source-root",
                    str(iris_workspace["source"]),
                    "--package-root",
                    str(iris_workspace["packages"]),
                    "--output-root",
                    str(upstream),
                    "--query-pack",
                    str(iris_workspace["queries"]),
                    "--project-info",
                    str(iris_workspace["project_info"]),
                    "--fix-info",
                    str(iris_workspace["fix_info"]),
                ]
                environment["MAXVERA_IRIS_LLM_LOG"] = str(project_root / "llm_calls.jsonl")
                environment["PATH"] = str(codeql.parent) + os.pathsep + environment.get("PATH", "")
                sarif = (
                    upstream
                    / slug
                    / run_id
                    / f"cwe-{int(cwe.split('-')[1]):03d}wLLM-posthoc-filter/results.sarif"
                )
            with log.open("a") as handle:
                handle.write(f"started_at={utc_now()}\ncommand={shlex.join(command)}\n")
                handle.flush()
                process = subprocess.run(
                    command,
                    cwd=root,
                    env=environment,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    timeout=21600,
                    check=False,
                )
                handle.write(f"exit_code={process.returncode}\nfinished_at={utc_now()}\n")
            if process.returncode or not sarif.is_file():
                raise RuntimeError(f"{baseline} exited {process.returncode}; see analysis.log")
            if baseline == "B2":
                if any(
                    row.get("status") == "BUDGET_EXCEEDED"
                    for row in read_jsonl(project_root / "llm_calls.jsonl")
                ):
                    raise RuntimeError("IRIS recorded a budget gate failure")
                base = sarif.parent.parent
                prefix = f"cwe-{int(cwe.split('-')[1]):03d}"
                required = [
                    base / prefix / name
                    for name in ("MySources.qll", "MySinks.qll", "MySummaries.qll", "Spec.yml")
                ]
                required += [
                    base / (prefix + "wLLM") / name
                    for name in ("results.sarif", "results_pp.sarif")
                ]
                if any(not p.is_file() for p in required):
                    raise RuntimeError("IRIS pipeline has missing intermediate stages")
            status.update(
                {
                    "status": "SUCCESS",
                    "reason": "oracle analysis completed",
                    "sarif": sarif.relative_to(work).as_posix(),
                }
            )
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            status.update(
                {"status": "ANALYSIS_FAILED", "reason": f"{type(error).__name__}: {error}"}
            )
        status["updated_at"] = utc_now()
        resources = [r for r in resources if r["project_id"] != project]
        resources.append(
            {
                "project_id": project,
                "wall_seconds": time.monotonic() - started,
                **_usage(read_jsonl(project_root / "llm_calls.jsonl")),
            }
        )
        atomic_jsonl(work / "resource_usage.jsonl", resources)
        atomic_jsonl(work / "project_status.jsonl", statuses)
        print(f"{baseline} [{position}/{len(selected)}] {project}: {status['status']}", flush=True)
    metrics = [
        evaluate_sarif(
            s["project_id"],
            s["status"],
            work / s["sarif"] if s.get("sarif") else None,
            truth[s["project_id"]],
        )
        for s in statuses
    ]
    atomic_jsonl(work / "project_metrics.jsonl", metrics)
    atomic_json(work / "metrics_aggregate.json", aggregate_metrics(metrics))
    (work / "STATUS").write_text(
        "SUCCESS\n" if all(s["status"] == "SUCCESS" for s in statuses) else "FAILED\n"
    )
    write_checksums(work)
    os.replace(work, final)
    print(validate(final, root), flush=True)
    return final


def validate(output: Path, root: Path) -> str:
    _verify_checksums(output)
    manifest = json.loads((output / "manifest.json").read_text())
    parent = root / "results/phase13" / manifest["parent_run_id"]
    snapshot_path = parent / "analyzer_snapshot.json"
    snapshot = validate_snapshot(root, snapshot_path)
    labels_path = root / "data/processed/evaluator_only/D_extended_labels.csv"
    truth_path = root / "data/processed/evaluator_only/D_extended_fix_locations.jsonl"
    for key, path in (
        ("analyzer_snapshot_sha256", snapshot_path),
        ("labels_sha256", labels_path),
        ("fix_locations_sha256", truth_path),
    ):
        if manifest[key] != sha256_file(path):
            raise ValueError("oracle sealed input checksum mismatch")
    if manifest["hint_condition"] != "oracle_cwe" or manifest["fair_zero_hint_comparator"]:
        raise ValueError("oracle result must retain its information-advantage classification")
    rows = read_jsonl(output / "project_status.jsonl")
    ids = manifest["selected_project_ids"]
    if ids != snapshot["selected_project_ids"]:
        raise ValueError("oracle selected projects differ from the sealed snapshot")
    if [row["project_id"] for row in rows] != ids or len(set(ids)) != 24:
        raise ValueError("oracle project coverage mismatch")
    if any(row["status"] not in {"SUCCESS", "ANALYSIS_FAILED"} for row in rows):
        raise ValueError("oracle output has non-final project states")
    failed = sum(row["status"] != "SUCCESS" for row in rows)
    if (output / "STATUS").read_text().strip() != ("FAILED" if failed else "SUCCESS"):
        raise ValueError("oracle STATUS mismatch")
    metrics = read_jsonl(output / "project_metrics.jsonl")
    if [row["project_id"] for row in metrics] != ids:
        raise ValueError("oracle metric coverage mismatch")
    truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in read_jsonl(truth_path):
        truth[item["project_id"]].append(item)
    expected = [
        evaluate_sarif(
            row["project_id"],
            row["status"],
            output / row["sarif"] if row.get("sarif") else None,
            truth[row["project_id"]],
        )
        for row in rows
    ]
    if expected != metrics:
        raise ValueError("oracle metrics do not reproduce from raw project outputs")
    if aggregate_metrics(metrics) != json.loads((output / "metrics_aggregate.json").read_text()):
        raise ValueError("oracle aggregate does not reproduce")
    for relative, digest in manifest["implementation_sha256"].items():
        if sha256_file(root / relative) != digest:
            raise ValueError("oracle implementation checksum mismatch")
    qualifier = "PASS_WITH_ANALYSIS_FAILURES" if failed else "PASS"
    return f"{qualifier}: {manifest['baseline_id']} oracle ({24 - failed}/24 successful)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", default="p13_test_analysis_001")
    parser.add_argument("--baseline", choices=("B1", "B2"), required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    run(args.repo_root.resolve(), args.run_id, args.baseline, resume=args.resume)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
