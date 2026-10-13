"""Coverage-directed Java extraction with separate class origins for modules."""

from __future__ import annotations

import csv
import hashlib
import subprocess
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.common.provenance import sha256_file
from src.graphs.program.runner import _run_command
from src.pipeline_v2.coverage import application_java, executable_missing, extraction_options
from src.reproduction.common import atomic_json


def source_group(name: str) -> str:
    """Use a source root as the compilation context; preserve original paths."""
    parts = Path(name).parts
    for index in range(len(parts) - 2):
        if parts[index] == "src" and parts[index + 1] == "main":
            return Path(*parts[: index + 3]).as_posix()
    return Path(name).parent.as_posix()


def create_complete_database(
    binary: Path,
    checkout: Path,
    database: Path,
    logs: Path,
    policy: dict[str, Any],
    environment: dict[str, str],
    *,
    cancelled: threading.Event | None = None,
) -> None:
    """Run native extraction, supplement gaps, and verify modeled source types.

    Origin tracking is required: indexing duplicate FQNs into a single default
    output silently overwrites the first type's methods. Each supplement gets a
    distinct compiler output, without rewriting source or hand-editing TRAP/ZIP.
    """
    logs.mkdir(parents=True, exist_ok=True)
    driver = Path(environment["JAVA_HOME"]) / "bin/java"
    if not driver.is_file():
        raise ValueError("pinned Java extraction driver unavailable")
    provenance = {
        "extraction_policy_sha256": sha256_file(Path(__file__)),
        "compiler_driver_java_home": environment["JAVA_HOME"],
        "compiler_driver_sha256": sha256_file(driver),
        "compiler_driver_pinned": True,
    }
    environment = {**environment, "ODASA_JAVA_CLASS_ORIGIN_TRACKING": "true"}
    resources = [f"--threads={policy['threads']}", f"--ram={policy['ram_mb']}"]
    tracked = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=checkout, text=True
    ).splitlines()
    expected = sorted(name for name in tracked if application_java(name))
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
    ).strip()
    large = policy.get("large_repository_resources", {})
    if len(expected) >= large.get("minimum_application_files", float("inf")):
        policy = {**policy, **large}
        resources = [f"--threads={policy['threads']}", f"--ram={policy['ram_mb']}"]
    steps: list[dict[str, Any]] = []

    def run(name: str, arguments: list[str], cwd: Path = checkout) -> None:
        if cancelled is not None and cancelled.is_set():
            raise RuntimeError("extraction cancelled")
        command = [str(binary), *arguments]
        print(f"EXTRACTION_STEP {name} ram={policy['ram_mb']}", flush=True)
        result = _run_command(
            command,
            cwd=cwd,
            env=environment,
            timeout=policy["timeout_seconds"],
            cancelled=cancelled,
        )
        (logs / f"{name}.log").write_text(
            f"exit_code={result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        steps.append({"step": name, "exit_code": result.returncode, "command": command})
        atomic_json(
            logs / "extraction_steps.json",
            {
                "steps": steps,
                "policy": policy,
                **provenance,
            },
        )
        if result.returncode:
            raise RuntimeError(f"CodeQL extraction step {name} failed; see {name}.log")

    run(
        "init",
        [
            "database",
            "init",
            str(database),
            "--language=java",
            "--build-mode=none",
            f"--source-root={checkout}",
        ],
    )
    run(
        "extraction",
        [
            "database",
            "trace-command",
            str(database),
            "--use-build-mode",
            *resources,
            *extraction_options(),
        ],
    )
    archived = {
        path.relative_to(database / "src" / checkout.as_posix().lstrip("/")).as_posix()
        for path in (database / "src" / checkout.as_posix().lstrip("/")).rglob("*.java")
    }
    missing, excluded = executable_missing(checkout, revision, sorted(set(expected) - archived))
    groups: dict[str, list[str]] = defaultdict(list)
    for name in missing:
        groups[source_group(name)].append(name)
    atomic_json(
        logs / "supplement_plan.json",
        {
            "revision": revision,
            "origin_tracking": True,
            "groups": dict(groups),
            "unextracted_non_executable_files": excluded,
            "resources": policy,
            **provenance,
        },
    )
    for number, (group, names) in enumerate(sorted(groups.items()), 1):
        key = hashlib.sha256(group.encode()).hexdigest()[:16]
        file_list = logs / f"supplement-{key}.list"
        file_list.write_text("".join(f"{checkout / name}\n" for name in names))
        # The wrapper must run on the pinned project JDK. It configures the
        # bundled extraction JVM with that JDK's language level and boot classes.
        run(
            f"supplement-{number:03}",
            [
                "database",
                "trace-command",
                str(database),
                *resources,
                "--",
                str(driver),
                "-cp",
                str(binary.parent / "java/tools/codeql-java-agent.jar"),
                "com.semmle.extractor.java.Extractor",
                str(file_list),
                "-d",
                str(database / "working/module-classes" / key),
                "-sourcepath",
                str(checkout / group),
            ],
        )
    if missing:
        atomic_json(
            database / "supplement_model_check.json",
            {
                "status": "PENDING",
                "required_files": missing,
                **provenance,
            },
        )
    run("finalize", ["database", "finalize", str(database), *resources])
    if missing:
        query_dir = logs / "model-query"
        query_dir.mkdir()
        (query_dir / "qlpack.yml").write_text(
            "name: maxvera/extraction-model-check\nversion: 0.0.1\n"
            f"dependencies:\n  codeql/java-all: {policy['java_pack']}\n"
        )
        (query_dir / "types.ql").write_text(
            "import java\nfrom RefType t\nwhere t.fromSource()\n"
            "select t.getLocation().getFile().getRelativePath()\n"
        )
        bqrs = logs / "modeled-types.bqrs"
        output = logs / "modeled-types.csv"
        run(
            "model-query",
            [
                "query",
                "run",
                str(query_dir / "types.ql"),
                f"--database={database}",
                f"--output={bqrs}",
                *resources,
            ],
        )
        run("model-decode", ["bqrs", "decode", str(bqrs), "--format=csv", f"--output={output}"])
        with output.open() as handle:
            rows = csv.reader(handle)
            next(rows, None)
            modeled = {row[0] for row in rows}
        unmodeled = sorted(set(missing) - modeled)
        model_check = {
            "required_files": missing,
            "unmodeled_files": unmodeled,
            "status": "PASS" if not unmodeled else "BLOCKED",
            "api_calls": 0,
            **provenance,
        }
        atomic_json(logs / "supplement_model_check.json", model_check)
        atomic_json(database / "supplement_model_check.json", model_check)
        if unmodeled:
            raise ValueError(f"supplement types missing from CodeQL model: {unmodeled[:10]}")
