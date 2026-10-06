"""Development recovery with immutable lineage and unchanged discovery contracts."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import zipfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from src.common.provenance import sha256_file
from src.graphs.program.runner import _run_command
from src.pipeline_v2.runtime import Run, codeql, dependency, implementation_hashes
from src.reproduction.common import atomic_json, read_jsonl

INFRASTRUCTURE_FILES = {
    "src/pipeline_v2/runtime.py",
    "src/pipeline_v2/specifications.py",
    "src/pipeline_v2/orchestrator.py",
    "src/pipeline_v2/__main__.py",
    "src/llm/providers/openrouter.py",
    "scripts/tools/run_pipeline_v2_tmux.sh",
}


def ast_contract(source: str, name: str, *, loop_only: bool = False) -> str:
    module = ast.parse(source)
    body = module.body
    if "." in name:
        class_name, name = name.split(".", 1)
        body = next(
            item.body for item in body if isinstance(item, ast.ClassDef) and item.name == class_name
        )
    node: ast.AST = next(
        item
        for item in body
        if isinstance(item, (ast.FunctionDef, ast.Assign))
        and (
            getattr(item, "name", None) == name
            or (
                isinstance(item, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in item.targets)
            )
        )
    )
    if loop_only:
        assert isinstance(node, ast.FunctionDef)
        node = next(item for item in node.body if isinstance(item, ast.For))
    return ast.dump(node, include_attributes=False)


def compatible_history(root: Path, config: Mapping[str, Any], path: Path) -> None:
    """Reject scientific drift; infrastructure changes cannot authorize new semantics."""
    manifest = json.loads((path / "manifest.json").read_text())
    current = implementation_hashes(root)
    for name, value in manifest["implementation_sha256"].items():
        if name not in INFRASTRUCTURE_FILES and current.get(name) != value:
            raise ValueError(f"historical scientific asset changed: {name}")
    original = root / "configs/experiments/pipeline_v2_execution.yaml"
    if sha256_file(original) != manifest["config_sha256"]:
        raise ValueError("historical execution configuration changed")
    old = yaml.safe_load(original.read_text())
    for key in ("top_k", "codeql", "budget", "phase8", "model_config"):
        if old[key] != config[key]:
            raise ValueError(f"historical scientific policy changed: {key}")
    if manifest["model_config_sha256"] != sha256_file(root / config["model_config"]):
        raise ValueError("historical model/provider configuration changed")
    revision = manifest["git"]["commit"]
    checks = {
        "src/pipeline_v2/runtime.py": [
            "endpoint_inventory",
            "archive_sources",
            "source_text_fingerprint",
            "entity_rows",
            "unique_inventory_rows",
            "query_csv",
            "codeql",
            "phase6",
        ],
        "src/pipeline_v2/specifications.py": [
            "context_plan",
            "_inventory_unchanged",
            "_checkpoint",
            "SYSTEM",
            "STRATEGIES",
        ],
        "src/llm/providers/openrouter.py": ["OpenRouterClient._payload"],
    }
    for name, functions in checks.items():
        previous = subprocess.check_output(["git", "show", f"{revision}:{name}"], cwd=root).decode()
        import hashlib

        if hashlib.sha256(previous.encode()).hexdigest() != manifest["implementation_sha256"][name]:
            raise ValueError("historical Git source does not match its implementation lock")
        source = (root / name).read_text()
        for function in functions:
            if ast_contract(previous, function, loop_only=function == "phase6") != ast_contract(
                source, function, loop_only=function == "phase6"
            ):
                raise ValueError(f"historical analysis contract changed: {function}")


def inherited_phase6(run: Run, config: Mapping[str, Any]) -> None:
    source, lock = dependency(run.root, config["recovery"]["phase6_run"], run.selected, 6)
    if lock["manifest_sha256"] != config["recovery"]["phase6_manifest_sha256"]:
        raise ValueError("Phase 6 recovery manifest does not match its registered lock")
    compatible_history(run.root, config, source)
    lineage = run.work / "recovery_lineage.json"
    inherited = json.loads(lineage.read_text())["inherited_projects"] if lineage.exists() else []
    statuses = {r["project_id"]: r for r in read_jsonl(source / "project_status.jsonl")}
    for project in run.pending():
        record = statuses[project]
        if record["status"] != "SUCCESS":
            continue
        old = source / "projects" / project
        provenance = json.loads((old / "database_provenance.json").read_text())
        database = run.root / config["dataset"]["vulnerable_database_root"] / project
        if (
            sha256_file(database / "codeql-database.yml") != provenance["database_metadata_sha256"]
            or sha256_file(database / "src.zip") != provenance["source_archive_sha256"]
        ):
            raise ValueError("inherited inventory database changed")
        destination = run.work / "projects" / project
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(old, destination)
        fields = {
            k: v
            for k, v in record.items()
            if k not in {"project_id", "status", "reason", "updated_at"}
        }
        run.status(
            project,
            "SUCCESS",
            "inherited checksum-verified Phase 6 discovery",
            **fields,
            inherited_from=lock,
        )
        inherited.append(project)
    atomic_json(
        run.work / "recovery_lineage.json", {"source": lock, "inherited_projects": inherited}
    )


def cleanup_cache(run: Run, project: str, config: Mapping[str, Any]) -> None:
    roots = [config["dataset"]["vulnerable_database_root"]]
    if run.phase == 11:
        roots.append(config["dataset"]["fixed_database_root"])
    for number, relative in enumerate(roots):
        database = run.root / relative / project
        if not (database / "codeql-database.yml").is_file():
            continue
        log = run.work / "cache_cleanup" / f"{project}_{number}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = _run_command(
                [
                    str(codeql(run.root, config["codeql"])),
                    "database",
                    "cleanup",
                    "--cache-cleanup=clear",
                    str(database),
                ],
                timeout=120,
            )
            log.write_text(f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}")
            internal = database / "log"
            removed = 0
            if internal.is_dir():
                for trace in internal.iterdir():
                    if (
                        trace.is_file()
                        and not trace.is_symlink()
                        and trace.name.startswith(("execute-queries-", "query-run-"))
                        and trace.suffix == ".log"
                    ):
                        removed += trace.stat().st_size
                        trace.unlink()
            with log.open("a") as handle:
                handle.write(f"removed_internal_debug_bytes={removed}\n")
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            log.write_text(f"cache cleanup unavailable: {type(error).__name__}: {error}\n")


def prepare_databases(
    root: Path, config: Mapping[str, Any], config_path: Path, *, resume: bool
) -> Path:
    from src.pipeline_v2.runtime import development_ids

    recovery = config["recovery"]
    selected = development_ids(root)
    source, lock = dependency(root, recovery["phase6_run"], selected, 6)
    if lock["manifest_sha256"] != recovery["phase6_manifest_sha256"]:
        raise ValueError("database recovery input lock changed")
    compatible_history(root, config, source)
    run = Run(
        root,
        "results/pipeline_v2/database_recovery",
        recovery["database_preparation_run_id"],
        0,
        config_path,
        selected,
        resume=resume,
        require_clean=True,
        dependencies={"historical_phase6": lock},
    )
    destination = root / config["dataset"]["vulnerable_database_root"]
    destination.mkdir(parents=True, exist_ok=True)
    previous_config = yaml.safe_load(
        (root / "configs/experiments/pipeline_v2_execution.yaml").read_text()
    )
    previous_root = root / previous_config["dataset"]["vulnerable_database_root"]
    binary = codeql(root, config["codeql"])
    for project in run.pending():
        target = destination / project
        previous = previous_root / project
        if (previous / "codeql-database.yml").is_file():
            if not target.exists():
                target.symlink_to(previous.resolve(), target_is_directory=True)
            if target.resolve() != previous.resolve():
                raise ValueError("database recovery destination changed")
            run.status(
                project, "SUCCESS", "reused original vulnerable database", build_mode="historical"
            )
            continue
        source_tree = root / recovery["source_root"] / project
        work = run.work / "builds" / project
        work.mkdir(parents=True, exist_ok=True)
        database = work / "database"
        try:
            if shutil.disk_usage(root).free < int(recovery["minimum_free_disk_gib"]) * 1024**3:
                raise RuntimeError("database recovery disk reserve exhausted")
            revision = subprocess.check_output(
                ["git", "-C", str(source_tree), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(["git", "-C", str(source_tree), "diff", "--quiet", "HEAD"], check=True)
            java = subprocess.check_output(
                ["git", "-C", str(source_tree), "ls-files", "*.java"], text=True
            )
            if not java.strip():
                raise ValueError("source snapshot has no tracked Java input")
            saved_provenance = work / "build_provenance.json"
            if target.exists():
                saved = json.loads(saved_provenance.read_text())
                if (
                    saved["source_git_commit"] != revision
                    or saved["source_archive_sha256"] != sha256_file(target / "src.zip")
                    or saved["database_metadata_sha256"]
                    != sha256_file(target / "codeql-database.yml")
                ):
                    raise ValueError("recovered database checkpoint changed")
                run.status(project, "SUCCESS", "resumed completed no-build extraction", **saved)
                continue
            if database.exists():
                shutil.rmtree(database)
            command = [
                str(binary),
                "database",
                "create",
                str(database),
                "--language=java",
                "--build-mode=none",
                "--threads=2",
                "--ram=8192",
                f"--source-root={source_tree}",
            ]
            result = _run_command(
                command, cwd=source_tree, timeout=int(recovery["database_build_timeout_seconds"])
            )
            (work / "build.log").write_text(
                f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}"
            )
            if result.returncode or not (database / "src.zip").is_file():
                raise RuntimeError("no-build extraction failed; see build.log")
            with zipfile.ZipFile(database / "src.zip") as archive:
                extracted = sum(name.endswith(".java") for name in archive.namelist())
            if not extracted:
                raise ValueError("database has no archived Java sources")
            if target.exists() or target.is_symlink():
                raise FileExistsError("database destination already exists")
            atomic_json(
                saved_provenance,
                {
                    "source_git_commit": revision,
                    "build_mode": "none",
                    "archived_java_files": extracted,
                    "source_archive_sha256": sha256_file(database / "src.zip"),
                    "database_metadata_sha256": sha256_file(database / "codeql-database.yml"),
                },
            )
            shutil.move(str(database), str(target))
            run.status(
                project,
                "SUCCESS",
                "recovered vulnerable database; grounding checked in Phase 6",
                source_git_commit=revision,
                build_mode="none",
                archived_java_files=extracted,
                source_archive_sha256=sha256_file(target / "src.zip"),
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
            zipfile.BadZipFile,
        ) as error:
            run.status(project, "ANALYSIS_FAILED", f"{type(error).__name__}: {error}")
    zero = []
    for status in read_jsonl(source / "project_status.jsonl"):
        if status["status"] != "SUCCESS" or status.get("hypotheses"):
            continue
        directory = source / "projects" / status["project_id"]
        endpoints = read_jsonl(directory / "endpoints.jsonl")
        counts = Counter(role for endpoint in endpoints for role in endpoint["roles"])
        zero.append(
            {
                "project_id": status["project_id"],
                "endpoint_roles": dict(counts),
                "discovery_flow_pairs": status.get("flow_pairs", 0),
                "rejection_reasons": dict(
                    Counter(r["reason"] for r in read_jsonl(directory / "rejected.jsonl"))
                ),
                "interpretation": "grounding coverage audit; no vulnerability verdict",
            }
        )
    atomic_json(run.work / "zero_hypothesis_audit.json", {"projects": zero})
    return run.finalize(
        {
            "zero_hypothesis_projects": len(zero),
            "llm_calls": 0,
            "recovered_databases": sum(r.get("build_mode") == "none" for r in run.statuses),
        }
    )
