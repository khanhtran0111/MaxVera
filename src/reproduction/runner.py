"""Run Phase 4 CodeQL and IRIS reproduction baselines with resumable status files."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file, utc_now
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums

IRIS_COMMIT = "67140e84e6a01da2b44803a6208be2ea7bd4bd51"
DATASET_COMMIT = "698fb7248ae30cb7f7782d59c841f05ad70ea9cc"
JAVA_QUERIES_VERSION = "1.11.7"
JAVA_ALL_VERSION = "9.2.2"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
BASELINE_ROOTS = {
    "B0": "codeql_zero_hint",
    "B1": "codeql_v1",
    "B2": "iris_gptoss20b",
}
ORACLE_QUERY_FOLDERS = {
    "CWE-22": "CWE-022",
    "CWE-78": "CWE-078",
    "CWE-79": "CWE-079",
    "CWE-94": "CWE-094",
}


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    log: Path,
    environment: Mapping[str, str] | None = None,
    timeout: int = 21600,
) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    with log.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"started_at={started}\ncommand={json.dumps(list(command))}\n")
        handle.flush()
        try:
            process = subprocess.run(
                list(command),
                cwd=cwd,
                env=dict(environment) if environment is not None else None,
                stdout=handle,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            handle.write(f"finished_at={utc_now()}\nexit=124\nreason=timeout\n")
            return 124
        handle.write(f"finished_at={utc_now()}\nexit={process.returncode}\n")
    return process.returncode


def _git_head(path: Path) -> str:
    process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
    )
    return process.stdout.strip() if process.returncode == 0 else "UNAVAILABLE"


def _codeql_binary(home: str) -> Path:
    candidate = Path(home).expanduser().resolve()
    return candidate / "codeql" if candidate.is_dir() else candidate


def _codeql_version(binary: Path) -> str:
    process = subprocess.run(
        [str(binary), "version", "--format=terse"],
        check=False,
        capture_output=True,
        text=True,
    )
    return (process.stdout or process.stderr).strip().splitlines()[0]


def _load_inputs(
    root: Path, baseline_id: str
) -> tuple[list[dict[str, str]], dict[str, dict[str, Any]]]:
    input_path = (
        root / "data/processed/analysis_input/D_repro_v1_projects.csv"
        if baseline_id == "B0"
        else root / "data/processed/manifests/cwe_bench_v1.csv"
    )
    projects = read_csv(input_path)
    statuses = {
        str(item["project_id"]): item
        for item in read_jsonl(root / "data/interim/build_info/build_status.jsonl")
    }
    if len(projects) != 120 or len(statuses) != 120:
        raise RuntimeError(
            f"Phase 4 requires 120 project/status rows; found {len(projects)}/{len(statuses)}"
        )
    return projects, statuses


def _selected_ids(root: Path, mode: str, build: Mapping[str, Mapping[str, Any]]) -> list[str]:
    if mode == "full":
        return sorted(
            project_id for project_id, item in build.items() if item["status"] == "SUCCESS"
        )
    smoke = read_csv(root / "data/processed/manifests/smoke.csv")
    return [row["project_id"] for row in smoke if build[row["project_id"]]["status"] == "SUCCESS"]


def _initial_statuses(
    canonical: Sequence[Mapping[str, str]],
    build: Mapping[str, Mapping[str, Any]],
    selected: set[str],
    mode: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in canonical:
        project_id = item["project_id"]
        phase2 = str(build[project_id]["status"])
        if phase2 != "SUCCESS":
            status = phase2
            reason = str(build[project_id].get("reason", "Phase 2 did not produce a database"))
        elif project_id not in selected:
            status = "EXCLUDED_WITH_REASON"
            reason = f"not selected by Phase 4 {mode} project set"
        else:
            status = "PENDING"
            reason = "selected and waiting for analysis"
        rows.append(
            {
                "schema_version": 1,
                "project_id": project_id,
                "status": status,
                "reason": reason,
                "updated_at": utc_now(),
            }
        )
    return rows


def _manifest(
    root: Path,
    baseline_id: str,
    mode: str,
    run_id: str,
    selected: Sequence[str],
    codeql: Path,
) -> dict[str, Any]:
    model_config = root / "configs/models/gpt_oss_20b_openrouter.yaml"
    model = cast(dict[str, Any], yaml.safe_load(model_config.read_text(encoding="utf-8")))
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "phase": 4,
        "baseline_id": baseline_id,
        "run_id": run_id,
        "mode": mode,
        "created_at": utc_now(),
        "dataset": {
            "id": "D_repro_v1",
            "commit": DATASET_COMMIT,
            "canonical_rows": 120,
            "analysis_manifest_sha256": sha256_file(
                root / "data/processed/analysis_input/D_repro_v1_projects.csv"
            ),
        },
        "selected_database_count": len(selected),
        "selected_project_ids": list(selected),
        "codeql": {
            "version": _codeql_version(codeql),
            "java_queries": JAVA_QUERIES_VERSION,
            "java_all": JAVA_ALL_VERSION,
            "database_origin": "Phase 2 CodeQL 2.26.2 databases",
        },
        "toolchain_variance": {
            "requested": "IRIS patched CodeQL artifact",
            "effective": "CodeQL 2.26.2 against existing databases",
            "reason": "user-authorized reuse; patched IRIS CLI cannot read the newer databases",
            "paper_compatible": False,
        },
        "claim": "IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter"
        if baseline_id == "B2"
        else "CodeQL reference under the effective Phase 2 toolchain",
    }
    manifest["data_access"] = (
        "opaque_analysis_input_only; evaluator labels forbidden"
        if baseline_id == "B0"
        else "oracle CWE baseline; canonical metadata authorized"
    )
    implementation_files = (
        "src/reproduction/runner.py",
        "src/reproduction/iris_subprocess.py",
        "src/reproduction/common.py",
        "src/reproduction/evaluation.py",
        "src/reproduction/validate.py",
    )
    manifest["implementation_sha256"] = {
        relative: sha256_file(root / relative)
        for relative in implementation_files
        if (root / relative).is_file()
    }
    if baseline_id == "B2":
        machine = effective_env(root / ".env")
        manifest["iris"] = {"commit": IRIS_COMMIT}
        manifest["model"] = {
            "id": model["model_id"],
            "backend": model["backend"],
            "base_url": machine.get("MAXVERA_OPENROUTER_BASE_URL"),
            "provider_route": machine.get("MAXVERA_OPENROUTER_PROVIDER"),
            "hosted_model_weight_sha256": None,
            "routing": model["routing"],
            "reasoning_effort": model["reasoning_effort"],
            "max_output_tokens": model["max_output_tokens"],
            "paper_max_output_tokens": 2048,
            "effective_max_output_tokens": 2048,
        }
    return manifest


def _resolve_query(root: Path, baseline_id: str, cwe: str, codeql: Path) -> str:
    home = codeql.parent
    query_pack = home / "qlpacks/codeql/java-queries" / JAVA_QUERIES_VERSION
    if baseline_id == "B0":
        return str(query_pack / "codeql-suites/java-security-extended.qls")
    folder = ORACLE_QUERY_FOLDERS[cwe]
    return str(query_pack / "Security/CWE" / folder)


def _analyze_codeql(
    root: Path,
    run_root: Path,
    baseline_id: str,
    item: Mapping[str, str],
    codeql: Path,
    *,
    cwe_override: str | None = None,
) -> tuple[str, str, Path | None]:
    project_id = item["project_id"]
    project_root = run_root / "projects" / project_id
    cwe = cwe_override or item.get("ground_truth_cwe", "")
    sarif = project_root / (f"results-{cwe.lower()}.sarif" if cwe_override else "results.sarif")
    log = project_root / (f"analysis-{cwe.lower()}.log" if cwe_override else "analysis.log")
    query = _resolve_query(root, baseline_id, cwe, codeql)
    command = [
        str(codeql),
        "database",
        "analyze",
        "--rerun",
        "--threads=4",
        "--ram=16384",
        "--format=sarif-latest",
        f"--output={sarif}",
        str(root / "data/interim/codeql_databases" / project_id),
        query,
    ]
    exit_code = _run(command, cwd=root, log=log)
    if exit_code == 0 and sarif.is_file():
        return "SUCCESS", "CodeQL analysis completed", sarif
    return "ANALYSIS_FAILED", f"CodeQL exited {exit_code}; see {log.relative_to(root)}", None


def _prepare_iris_workspace(
    root: Path, run_root: Path, items: Sequence[Mapping[str, str]]
) -> dict[str, Path]:
    workspace = root / "data/interim/reproduction" / run_root.name / "B2"
    source_root = workspace / "project-sources"
    database_root = workspace / "codeql-dbs"
    query_pack = workspace / "query-pack"
    for directory in (source_root, database_root, query_pack / "myqueries", query_pack / "ext"):
        directory.mkdir(parents=True, exist_ok=True)
    for item in items:
        slug = item["project_slug"]
        project_id = item["project_id"]
        links = (
            (source_root / slug, root / "data/interim/project_sources" / project_id),
            (database_root / slug, root / "data/interim/codeql_databases" / project_id),
        )
        for link, target in links:
            if link.is_symlink():
                if link.resolve() != target.resolve():
                    raise RuntimeError(f"workspace symlink target changed: {link}")
            elif link.exists():
                raise RuntimeError(f"workspace path is not a symlink: {link}")
            else:
                link.symlink_to(target.resolve(), target_is_directory=True)
    qlpack = query_pack / "qlpack.yml"
    if not qlpack.exists():
        qlpack.write_text(
            "name: maxvera/iris-phase4-adapter\n"
            "version: 0.0.1\n"
            "extractor: java\n"
            "dependencies:\n"
            f"  codeql/java-all: {JAVA_ALL_VERSION}\n",
            encoding="utf-8",
        )
    return {
        "workspace": workspace,
        "source_root": source_root,
        "database_root": database_root,
        "query_pack": query_pack,
    }


def _iris_final_sarif(upstream: Path, slug: str, adapter_run: str, cwe: str) -> Path:
    query = f"cwe-{int(cwe.split('-')[1]):03d}wLLM"
    return upstream / slug / adapter_run / f"{query}-posthoc-filter" / "results.sarif"


def _validate_iris_stages(upstream: Path, slug: str, adapter_run: str, cwe: str) -> list[str]:
    number = int(cwe.split("-")[1])
    query = f"cwe-{number:03d}wLLM"
    base = upstream / slug / adapter_run
    required = [
        base / f"cwe-{number:03d}" / "MySources.qll",
        base / f"cwe-{number:03d}" / "MySinks.qll",
        base / f"cwe-{number:03d}" / "MySummaries.qll",
        base / f"cwe-{number:03d}" / "Spec.yml",
        base / query / "results.sarif",
        base / query / "results_pp.sarif",
        base / f"{query}-posthoc-filter" / "results.sarif",
        base / f"{query}-final" / "results.json",
    ]
    return [str(path) for path in required if not path.is_file()]


def _analyze_iris(
    root: Path,
    run_root: Path,
    item: Mapping[str, str],
    codeql: Path,
    llm_environment: Mapping[str, str],
    workspace: Mapping[str, Path],
    *,
    cwe_override: str | None = None,
) -> tuple[str, str, Path | None]:
    project_id = item["project_id"]
    cwe = cwe_override or item["ground_truth_cwe"]
    suffix = f"-artifact-{cwe.lower()}" if cwe_override else ""
    adapter_run = f"{run_root.name}-{project_id}{suffix}"
    upstream = run_root / "upstream_output"
    project_root = run_root / "projects" / project_id
    log = project_root / (f"iris-{cwe.lower()}.log" if cwe_override else "iris.log")
    llm_log = project_root / (
        f"llm-calls-{cwe.lower()}.jsonl" if cwe_override else "llm-calls.jsonl"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "MAXVERA_IRIS_LLM_LOG": str(llm_log),
            "PATH": f"{codeql.parent}{os.pathsep}{environment.get('PATH', '')}",
            **llm_environment,
        }
    )
    command = [
        sys.executable,
        str(root / "src/reproduction/iris_subprocess.py"),
        "--iris-root",
        str(root / "third_party/iris"),
        "--project",
        item["project_slug"],
        "--cwe",
        cwe.split("-")[1],
        "--run-id",
        adapter_run,
        "--codeql-home",
        str(codeql.parent),
        "--database-root",
        str(workspace["database_root"]),
        "--source-root",
        str(workspace["source_root"]),
        "--package-root",
        str(root / "data/raw/cwe_bench_java_v1/package-names"),
        "--output-root",
        str(upstream),
        "--query-pack",
        str(workspace["query_pack"]),
        "--project-info",
        str(root / "data/raw/cwe_bench_java_v1/data/project_info.csv"),
        "--fix-info",
        str(root / "data/raw/cwe_bench_java_v1/data/fix_info.csv"),
    ]
    exit_code = _run(command, cwd=root, log=log, environment=environment)
    sarif = _iris_final_sarif(upstream, item["project_slug"], adapter_run, cwe)
    missing = _validate_iris_stages(upstream, item["project_slug"], adapter_run, cwe)
    stage_record = {
        "schema_version": 1,
        "project_id": project_id,
        "cwe": cwe,
        "adapter_run_id": adapter_run,
        "exit_code": exit_code,
        "missing_required_artifacts": missing,
        "status": "SUCCESS" if exit_code == 0 and not missing else "ANALYSIS_FAILED",
    }
    stage_path = project_root / (f"stages-{cwe.lower()}.json" if cwe_override else "stages.json")
    atomic_json(stage_path, stage_record)
    if exit_code == 0 and not missing:
        return "SUCCESS", "all IRIS stages completed", sarif
    return (
        "ANALYSIS_FAILED",
        f"IRIS exited {exit_code}; {len(missing)} required artifacts missing; "
        f"see {log.relative_to(root)}",
        None,
    )


def _save_statuses(run_root: Path, statuses: Sequence[Mapping[str, Any]]) -> None:
    atomic_jsonl(run_root / "project_status.jsonl", statuses)
    counts = Counter(str(item["status"]) for item in statuses)
    atomic_json(
        run_root / "status_summary.json",
        {"schema_version": 1, "total": len(statuses), "counts": dict(sorted(counts.items()))},
    )


def run_baseline(args: argparse.Namespace) -> int:
    root = args.repo_root.resolve()
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise ValueError("run ID must be 1-80 safe filename characters")
    env = effective_env(root / ".env")
    codeql_setting = env.get("MAXVERA_CODEQL_HOME", "")
    if not codeql_setting:
        raise RuntimeError("MAXVERA_CODEQL_HOME is missing from .env")
    codeql = _codeql_binary(codeql_setting)
    llm_environment: dict[str, str] = {}
    if args.baseline_id == "B2":
        for key in (
            "OPENROUTER_API_KEY",
            "MAXVERA_OPENROUTER_BASE_URL",
            "MAXVERA_OPENROUTER_PROVIDER",
        ):
            value = env.get(key, "")
            if not value:
                raise RuntimeError(f"{key} is missing from .env")
            llm_environment[key] = value
    canonical, build = _load_inputs(root, args.baseline_id)
    selected = _selected_ids(root, args.mode, build)
    if args.limit is not None:
        if args.mode == "full":
            raise ValueError("--limit is only allowed in pilot mode")
        selected = selected[: args.limit]
    run_root = root / "results/reproduction" / BASELINE_ROOTS[args.baseline_id] / args.run_id
    status_path = run_root / "project_status.jsonl"
    if run_root.exists() and not args.resume:
        raise FileExistsError(f"run already exists; use --resume: {run_root}")
    run_root.mkdir(parents=True, exist_ok=True)
    manifest_path = run_root / "manifest.json"
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("selected_project_ids") != selected or existing.get("mode") != args.mode:
            raise RuntimeError("resume parameters do not match the existing manifest")
    else:
        atomic_json(
            manifest_path,
            _manifest(root, args.baseline_id, args.mode, args.run_id, selected, codeql),
        )
    statuses = (
        read_jsonl(status_path)
        if status_path.exists()
        else _initial_statuses(canonical, build, set(selected), args.mode)
    )
    _save_statuses(run_root, statuses)
    if args.dry_run:
        atomic_json(
            run_root / "dry_run.json",
            {"schema_version": 1, "selected": selected, "baseline_id": args.baseline_id},
        )
        write_checksums(run_root)
        return 0

    canonical_by_id = {row["project_id"]: row for row in canonical}
    workspace: dict[str, Path] | None = None
    if args.baseline_id == "B2":
        iris_root = root / "third_party/iris"
        if _git_head(iris_root) != IRIS_COMMIT:
            raise RuntimeError("IRIS checkout is absent or not at the pinned commit")
        workspace = _prepare_iris_workspace(
            root, run_root, [canonical_by_id[project_id] for project_id in selected]
        )

    statuses_by_id = {str(item["project_id"]): item for item in statuses}
    for position, project_id in enumerate(selected, start=1):
        status_row = statuses_by_id[project_id]
        if status_row["status"] not in {"PENDING", "ANALYSIS_FAILED"}:
            print(f"[{position}/{len(selected)}] {project_id}: {status_row['status']} (resume)")
            continue
        if status_row["status"] == "ANALYSIS_FAILED":
            print(f"[{position}/{len(selected)}] {project_id}: retrying failed analysis")
        item = canonical_by_id[project_id]
        print(f"[{position}/{len(selected)}] {project_id}: running {args.baseline_id}", flush=True)
        started = time.monotonic()
        if args.baseline_id in {"B0", "B1"}:
            status, reason, sarif = _analyze_codeql(root, run_root, args.baseline_id, item, codeql)
            if (
                args.baseline_id == "B1"
                and status == "SUCCESS"
                and item["cve_id"] == "CVE-2021-21345"
            ):
                variant_status, variant_reason, variant_sarif = _analyze_codeql(
                    root,
                    run_root,
                    args.baseline_id,
                    item,
                    codeql,
                    cwe_override="CWE-94",
                )
                atomic_json(
                    run_root / "projects" / project_id / "artifact_row_121.json",
                    {
                        "schema_version": 1,
                        "cwe": "CWE-94",
                        "status": variant_status,
                        "reason": variant_reason,
                        "sarif": str(variant_sarif.relative_to(root)) if variant_sarif else None,
                    },
                )
                if variant_status != "SUCCESS":
                    status = "ANALYSIS_FAILED"
                    reason = (
                        f"canonical analysis passed but artifact row 121 failed: {variant_reason}"
                    )
        else:
            assert workspace is not None
            status, reason, sarif = _analyze_iris(
                root, run_root, item, codeql, llm_environment, workspace
            )
            if status == "SUCCESS" and item["cve_id"] == "CVE-2021-21345":
                variant_status, variant_reason, variant_sarif = _analyze_iris(
                    root,
                    run_root,
                    item,
                    codeql,
                    llm_environment,
                    workspace,
                    cwe_override="CWE-94",
                )
                atomic_json(
                    run_root / "projects" / project_id / "artifact_row_121.json",
                    {
                        "schema_version": 1,
                        "cwe": "CWE-94",
                        "status": variant_status,
                        "reason": variant_reason,
                        "sarif": str(variant_sarif.relative_to(root)) if variant_sarif else None,
                    },
                )
                if variant_status != "SUCCESS":
                    status = "ANALYSIS_FAILED"
                    reason = (
                        f"canonical analysis passed but artifact row 121 failed: {variant_reason}"
                    )
        status_row.update(
            {
                "status": status,
                "reason": reason,
                "seconds": round(time.monotonic() - started, 3),
                "sarif": str(sarif.relative_to(root)) if sarif else None,
                "updated_at": utc_now(),
            }
        )
        _save_statuses(run_root, statuses)
        print(f"[{position}/{len(selected)}] {project_id}: {status}", flush=True)

    write_checksums(run_root)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-id", choices=tuple(BASELINE_ROOTS), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be positive")
    return run_baseline(args)


if __name__ == "__main__":
    raise SystemExit(main())
