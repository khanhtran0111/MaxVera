"""Real IRIS v1 stage adapter and an independent oracle-CWE CodeQL reference."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from pathlib import Path

import yaml

from maxvera.contracts import digest
from maxvera.orchestration import Context, Stage, StageFailure
from maxvera.process import command
from src.common.envfile import effective_env
from src.common.provenance import sha256_file
from src.data.build_projects import _fetch_source, build_command_and_env
from src.reproduction.common import atomic_json, atomic_jsonl, sarif_paths
from src.reproduction.runner import IRIS_COMMIT, IRIS_PACKAGE_ALIASES, _git_head


def _binary(ctx):
    binary = (ctx.root / ctx.config["codeql"]["repro_binary"]).resolve()
    if not binary.is_file():
        raise StageFailure("CODEQL_DB_FAILED", "configured reproduction CodeQL binary missing")
    return binary


def prepare(ctx: Context) -> dict:
    row = {**ctx.case, "project_id": ctx.case["case_id"]}
    raw = ctx.root / ctx.config["reproduction"]["raw_root"]
    # Run-local source; oracle-dependent outputs never become research cache.
    source_root = ctx.stage_dir / "sources"
    ok, reason, seconds = _fetch_source(
        row, raw, source_root, ctx.stage_dir, ctx.config["budgets"]["timeout_case_s"]
    )
    if not ok:
        raise StageFailure("FETCH_FAILED", reason)
    source = source_root / row["project_id"]
    toolchains = yaml.safe_load((ctx.root / ctx.config["reproduction"]["toolchains"]).read_text())
    machine = effective_env(ctx.root / ".env")
    attempts = []
    selected = None
    for i, option in enumerate(toolchains["build_attempts"]):
        try:
            args, env = build_command_and_env(ctx.root, source, option, toolchains, machine)
            command(
                args,
                cwd=source,
                log=ctx.stage_dir / f"build-{i}.log",
                env=env,
                timeout=ctx.remaining_seconds(ctx.config["budgets"]["timeout_case_s"]),
                failure="BUILD_FAILED",
            )
            selected = {"option": option, "command": args}
            break
        except (ValueError, StageFailure) as e:
            attempts.append({"option": option, "status": str(e)})
    if selected is None:
        atomic_json(ctx.stage_dir / "build_attempts.json", {"attempts": attempts})
        raise StageFailure("BUILD_FAILED", "all pinned build attempts failed/unavailable")
    # Hash source inputs, excluding build products and VCS. Build-only patches are recorded.
    hashes = {
        p.relative_to(source).as_posix(): sha256_file(p)
        for p in source.rglob("*")
        if p.is_file() and not {".git", "target", "build"} & set(p.relative_to(source).parts)
    }
    snapshot = {
        "source": str(source),
        "source_hash": digest(hashes),
        "files": hashes,
        "selected_build": selected,
        "fetch_seconds": seconds,
    }
    atomic_json(ctx.stage_dir / "snapshot.json", snapshot)
    return {
        **snapshot,
        "artifacts": [
            "snapshot.json",
            *[(Path("sources") / row["project_id"] / rel).as_posix() for rel in hashes],
            *[p.name for p in ctx.stage_dir.glob("build-*.log")],
        ],
    }


def database_artifacts(stage_dir: Path, database: Path) -> list[str]:
    roots = [database / "codeql-database.yml", database / "src.zip", database / "db-java"]
    paths = []
    for base in roots:
        files = list(base.rglob("*")) if base.is_dir() else [base]
        for p in files:
            if p.is_symlink():
                raise ValueError("database checkpoint must not contain symlinks")
            if p.is_file():
                rel = p.relative_to(database)
                # Query evaluation owns cache and dynamic-entity pools; original
                # relations/schema/strings/source archive remain the DB identity.
                if {"cache", "pools", "log"} & set(rel.parts):
                    continue
                paths.append(p.relative_to(stage_dir).as_posix())
    return sorted(paths)


def restore_upstream(ctx: Context, workspace: Path) -> None:
    """Discard mutable/partial output and restore only hashed upstream-stage input."""
    output = workspace / "output"
    if output.exists():
        shutil.rmtree(output)
    order = ["candidate_extract", "llm_specs", "static_taint", "context_filter"]
    predecessors = order[: order.index(ctx.stage_dir.name)]
    previous = next(
        (
            name
            for name in reversed(predecessors)
            if ctx.results.get(name, {}).get("status") == "SUCCESS"
        ),
        None,
    )
    if previous is None:
        output.mkdir(parents=True)
        return
    record = ctx.results[previous]
    relative = record["result"]["upstream_snapshot"]
    folder = ctx.run_dir / "stages" / ctx.case["case_id"] / previous
    snapshot = folder / relative
    if not snapshot.resolve().is_relative_to(folder.resolve()):
        raise ValueError("unsafe upstream snapshot path")
    expected = {
        rel[len(relative) + 1 :]: checksum
        for rel, checksum in record["artifact_hashes"].items()
        if rel.startswith(relative + "/")
    }
    actual = {p.relative_to(snapshot).as_posix() for p in snapshot.rglob("*") if p.is_file()}
    if actual != set(expected):
        raise ValueError("upstream snapshot artifact inventory mismatch")
    for rel, checksum in expected.items():
        p = snapshot / rel
        if p.is_symlink() or sha256_file(p) != checksum:
            raise ValueError("upstream snapshot checksum mismatch")
    shutil.copytree(snapshot, output)


def codeql_db(ctx: Context) -> dict:
    prep = ctx.output("prepare")
    prepared_source = Path(prep["source"])
    source = ctx.stage_dir / "source"
    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(
        prepared_source,
        source,
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "target", "build", ".gradle", "classes"),
    )
    toolchains = yaml.safe_load((ctx.root / ctx.config["reproduction"]["toolchains"]).read_text())
    build_args, env = build_command_and_env(
        ctx.root,
        source,
        prep["selected_build"]["option"],
        toolchains,
        effective_env(ctx.root / ".env"),
    )
    binary = _binary(ctx)
    database = ctx.stage_dir / "database"
    if database.exists():
        # Failed/incomplete database never qualifies as a reusable cache.
        shutil.rmtree(database)
    args = [
        str(binary),
        "database",
        "create",
        str(database),
        "--language=java",
        f"--threads={ctx.config['codeql']['threads']}",
        f"--ram={ctx.config['codeql']['ram_mb']}",
        f"--source-root={source}",
        "--command=" + shlex.join(build_args),
    ]
    command(
        args,
        cwd=source,
        env=env,
        log=ctx.stage_dir / "codeql_db.log",
        timeout=ctx.remaining_seconds(ctx.config["budgets"]["timeout_case_s"]),
        failure="CODEQL_DB_FAILED",
    )
    command(
        [str(binary), "version", "--format=json"],
        cwd=ctx.root,
        log=ctx.stage_dir / "codeql_version.log",
        timeout=ctx.remaining_seconds(30),
    )
    from maxvera.snapshots import source_inventory

    analyzed_files = source_inventory(source, include_generated=True)
    metadata = {
        "database": str(database),
        "source": str(source),
        "source_hash": digest(analyzed_files),
        "prepared_source_hash": prep["source_hash"],
        "analyzed_files": analyzed_files,
        "binary_sha256": sha256_file(binary),
        "label_free_before_queries": True,
    }
    atomic_json(ctx.stage_dir / "database.json", metadata)
    return {
        **metadata,
        "artifacts": [
            "database.json",
            *database_artifacts(ctx.stage_dir, database),
            *["source/" + rel for rel in analyzed_files],
            "codeql_db.log",
            "codeql_version.log",
        ],
    }


def reference(ctx: Context) -> dict:
    binary = _binary(ctx)
    number = int(ctx.case["ground_truth_cwe"].split("-")[1])
    suite = ctx.config["codeql"]["reference_suite"].replace("{cwe}", f"{number:03d}")
    suite = str((ctx.root / suite).resolve())
    output = ctx.stage_dir / "reference.sarif"
    command(
        [
            str(binary),
            "database",
            "analyze",
            ctx.output("codeql_db")["database"],
            suite,
            "--rerun",
            "--format=sarif-latest",
            f"--output={output}",
            f"--ram={ctx.config['codeql']['ram_mb']}",
            f"--threads={ctx.config['codeql']['threads']}",
        ],
        cwd=ctx.root,
        log=ctx.stage_dir / "reference.log",
        timeout=ctx.remaining_seconds(ctx.config["codeql"]["per_query_timeout_s"]),
        failure="REFERENCE_QUERY_FAILED",
    )
    sarif_paths(output)  # Reject invalid output; zero paths is successful analysis.
    # Each branch carries its own program-point inventories; IRIS failures never
    # prevent the reference branch from being evaluated independently.
    inventory_pack = ctx.stage_dir / "inventory-queries"
    inventory_pack.mkdir(exist_ok=True)
    version = ctx.config["codeql"].get("repro_java_all_version", "0.8.3")
    (inventory_pack / "qlpack.yml").write_text(
        "name: maxvera/repro-inventories\nversion: 0.0.1\ndependencies:\n"
        f"  codeql/java-all: {version}\n"
    )
    for name, target in [
        ("fetch_class_locs", "class_locs_path.csv"),
        ("fetch_func_locs", "func_locs_path.csv"),
    ]:
        original_query = (
            ctx.root / ctx.config["reproduction"]["iris_root"] / "src/queries" / (name + ".ql")
        )
        query = inventory_pack / original_query.name
        shutil.copyfile(original_query, query)
        bqrs = ctx.stage_dir / (name + ".bqrs")
        command(
            [
                str(binary),
                "query",
                "run",
                str(query),
                "--database=" + ctx.output("codeql_db")["database"],
                "--output=" + str(bqrs),
                "--ram=" + str(ctx.config["codeql"]["ram_mb"]),
            ],
            cwd=ctx.root,
            log=ctx.stage_dir / (name + ".log"),
            timeout=ctx.remaining_seconds(ctx.config["codeql"]["per_query_timeout_s"]),
            failure="REFERENCE_QUERY_FAILED",
        )
        command(
            [
                str(binary),
                "bqrs",
                "decode",
                str(bqrs),
                "--format=csv",
                "--output=" + str(ctx.stage_dir / target),
            ],
            cwd=ctx.root,
            log=ctx.stage_dir / (name + "-decode.log"),
            timeout=ctx.remaining_seconds(60),
            failure="REFERENCE_QUERY_FAILED",
        )
    return {
        "sarif": output.name,
        "query": suite,
        "artifacts": [
            "reference.sarif",
            "reference.log",
            "class_locs_path.csv",
            "func_locs_path.csv",
            "inventory-queries/qlpack.yml",
            "inventory-queries/fetch_class_locs.ql",
            "inventory-queries/fetch_func_locs.ql",
        ],
    }


def iris_stage(ctx: Context) -> dict:
    iris = ctx.root / ctx.config["reproduction"]["iris_root"]
    if _git_head(iris) != IRIS_COMMIT:
        raise StageFailure("CANDIDATE_FAILED", "IRIS checkout differs from pinned v1 commit")
    workspace = ctx.run_dir / "iris_workspace" / ctx.case["case_id"]
    workspace.mkdir(parents=True, exist_ok=True)
    restore_upstream(ctx, workspace)
    slug = ctx.case["project_slug"]
    for base, target in [
        ("sources", ctx.output("codeql_db")["source"]),
        ("databases", ctx.output("codeql_db")["database"]),
    ]:
        directory = workspace / base
        directory.mkdir(exist_ok=True)
        link = directory / slug
        if link.is_symlink():
            if link.resolve() != Path(target).resolve():
                raise ValueError("IRIS workspace target changed")
        elif not link.exists():
            link.symlink_to(Path(target).resolve(), target_is_directory=True)
    raw = ctx.root / ctx.config["reproduction"]["raw_root"]
    packages = workspace / "package-names"
    packages.mkdir(exist_ok=True)
    for p in (raw / "package-names").glob("*.txt"):
        if not (packages / p.name).exists():
            (packages / p.name).symlink_to(p.resolve())
    for alias, name in IRIS_PACKAGE_ALIASES.items():
        if (raw / "package-names" / name).is_file() and not (packages / alias).exists():
            (packages / alias).symlink_to((raw / "package-names" / name).resolve())
    pack = workspace / "query-pack"
    for directory in (pack, workspace / "iris-src-codeql-2.26"):
        if directory.exists():
            shutil.rmtree(directory)
    (pack / "myqueries").mkdir(parents=True, exist_ok=True)
    (pack / "ext").mkdir(exist_ok=True)
    version = ctx.config["codeql"]["repro_java_all_version"]
    (pack / "qlpack.yml").write_text(
        f"name: maxvera/iris-v1\nversion: 0.0.1\ndependencies:\n  codeql/java-all: {version}\n"
    )
    response = ctx.stage_dir / "response.json"
    request = {
        "root": str(ctx.root),
        "stage": ctx.stage_dir.name,
        "slug": slug,
        "cwe": ctx.case["ground_truth_cwe"],
        "iris_root": str(iris),
        "codeql": str(_binary(ctx)),
        "source_root": str(workspace / "sources"),
        "database_root": str(workspace / "databases"),
        "package_root": str(packages),
        "output_root": str(workspace / "output"),
        "adapter_run": "iris",
        "query_pack": str(pack),
        "workspace": str(workspace),
        "project_info": str(raw / "data/project_info.csv"),
        "fix_info": str(raw / "data/fix_info.csv"),
        "compatibility": ctx.config["codeql"]["compatibility"],
        "ram_mb": ctx.config["codeql"]["ram_mb"],
        "response": str(response),
        "journal": str(workspace / "llm_journal"),
        "budgets": ctx.config["budgets"],
        "model_config": str(ctx.root / ctx.config["llm"]["model_config"]),
    }
    atomic_json(ctx.stage_dir / "request.json", request)
    command(
        [
            sys.executable,
            "-m",
            "maxvera.iris_worker",
            "--request",
            str(ctx.stage_dir / "request.json"),
        ],
        cwd=ctx.root,
        log=ctx.stage_dir / "iris.log",
        env=dict(os.environ),
        timeout=ctx.remaining_seconds(ctx.config["budgets"]["timeout_case_s"]),
        failure={
            "candidate_extract": "CANDIDATE_FAILED",
            "llm_specs": "LLM_SPEC_FAILED",
            "static_taint": "QUERY_FAILED",
            "context_filter": "FILTER_FAILED",
        }[ctx.stage_dir.name],
    )
    outputs = json.loads(response.read_text())
    archive = ctx.stage_dir / "upstream_snapshot"
    if archive.exists():
        shutil.rmtree(archive)
    if any(p.is_symlink() for p in (workspace / "output").rglob("*")):
        raise ValueError("upstream output symlinks cannot enter checkpoint")
    shutil.copytree(workspace / "output", archive)
    archive_files = [
        p.relative_to(ctx.stage_dir).as_posix() for p in archive.rglob("*") if p.is_file()
    ]
    copied = {}
    for name, source in outputs.items():
        target = ctx.stage_dir / (name + Path(source).suffix)
        shutil.copyfile(source, target)
        copied[name] = target.name
    return {
        "outputs": copied,
        "upstream_snapshot": "upstream_snapshot",
        "artifacts": [
            "request.json",
            "response.json",
            "iris.log",
            *copied.values(),
            *archive_files,
        ],
    }


def normalize(ctx: Context) -> dict:
    outputs = ctx.output("context_filter")["outputs"]
    previous = ctx.run_dir / "stages" / ctx.case["case_id"] / "context_filter"
    source = previous / outputs["posthoc_filtering_output_result_sarif_path"]
    shutil.copyfile(source, ctx.stage_dir / "findings.sarif")
    for name in ("class_locs_path", "func_locs_path"):
        shutil.copyfile(previous / outputs[name], ctx.stage_dir / (name + ".csv"))
    findings = normalize_sarif(source, ctx.case["case_id"], "iris")
    atomic_jsonl(ctx.stage_dir / "findings.jsonl", findings)
    return {
        "findings": findings,
        "sarif": "findings.sarif",
        "artifacts": [
            "findings.sarif",
            "findings.jsonl",
            "class_locs_path.csv",
            "func_locs_path.csv",
        ],
    }


def normalize_sarif(path: Path, case_id: str, branch: str) -> list[dict]:
    raw = json.loads(path.read_text())
    by_path = {}
    for run in raw.get("runs", []):
        for result in run.get("results", []):
            # Reuse the existing SARIF parser per result, retaining the evidence distinction.
            for flow in result.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    points = []
                    for entry in thread.get("locations", []):
                        physical = entry.get("location", {}).get("physicalLocation", {})
                        file = physical.get("artifactLocation", {}).get("uri")
                        line = physical.get("region", {}).get("startLine")
                        if file and isinstance(line, int):
                            from src.reproduction.common import normalize_uri

                            points.append((normalize_uri(file), line))
                    if points:
                        by_path[tuple(points)] = "CODEQL_FLOW"
            if not result.get("codeFlows"):
                for loc in result.get("locations", []):
                    physical = loc.get("physicalLocation", {})
                    file = physical.get("artifactLocation", {}).get("uri")
                    line = physical.get("region", {}).get("startLine")
                    if file and isinstance(line, int):
                        from src.reproduction.common import normalize_uri

                        by_path.setdefault(((normalize_uri(file), line),), "LOCATION_ONLY")
    return [
        {
            "schema_version": "2.0",
            "case_id": case_id,
            "branch": branch,
            "finding_id": "finding-" + digest([case_id, branch, points])[:24],
            "locations": [{"file": f, "start_line": line, "end_line": line} for f, line in points],
            "path_evidence": evidence,
            "decision": "STATIC_PATH" if evidence == "CODEQL_FLOW" else "REVIEW",
            "provenance": {"sarif_sha256": sha256_file(path)},
        }
        for points, evidence in sorted(by_path.items())
    ]


def stages() -> list[Stage]:
    return [
        Stage("prepare", prepare),
        Stage("codeql_db", codeql_db, ("prepare",)),
        Stage("codeql_reference", reference, ("codeql_db",)),
        Stage("candidate_extract", iris_stage, ("prepare", "codeql_db")),
        Stage("llm_specs", iris_stage, ("candidate_extract",), paid=True),
        Stage("static_taint", iris_stage, ("llm_specs",)),
        Stage("context_filter", iris_stage, ("static_taint",), paid=True),
        Stage("finalize", normalize, ("context_filter",)),
    ]


def finalize(path: Path, cases: list[dict]) -> None:
    findings, refs, calls = [], [], []
    for case in cases:
        base = path / "stages" / case["case_id"]
        for name, branch, dest in [
            ("finalize", "iris", findings),
            ("codeql_reference", "codeql_reference", refs),
        ]:
            record = base / name / "stage.json"
            if record.is_file():
                info = json.loads(record.read_text())
                if info["status"] == "SUCCESS":
                    sarif = base / name / info["result"]["sarif"]
                    dest.extend(normalize_sarif(sarif, case["case_id"], branch))
        journal = path / "iris_workspace" / case["case_id"] / "llm_journal/llm_calls.jsonl"
        if journal.exists():
            calls.extend(
                {"case_id": case["case_id"], **json.loads(line)}
                for line in journal.read_text().splitlines()
                if line.strip()
            )
    atomic_jsonl(path / "findings.jsonl", findings)
    atomic_jsonl(path / "reference_findings.jsonl", refs)
    atomic_jsonl(path / "llm_calls.jsonl", calls)
    atomic_jsonl(
        path / "usage.jsonl",
        [{"case_id": c["case_id"], "usage": c.get("usage", {})} for c in calls],
    )
    atomic_json(
        path / "reproduction_deviations.json",
        {
            "model_substitution": "IRIS v1 + openai/gpt-oss-20b via pinned OpenRouter provider",
            "numerical_paper_reproduction_claimed": False,
            "deviations": [
                "temperature/sampling/output caps are provider configuration",
                "sequential requests; durable request cache and bounded JSON retry",
                "explicit HTTP 429 rejections use bounded identical-prompt backoff; "
                "rejected attempts count toward the call budget without token reservations",
                "completion-based request spacing and HTTP 429 backoff are pinned in model config; "
                "provider Retry-After can extend the local backoff cap within the case deadline",
                "repository-local README instead of mutable remote README",
                "package filename aliases from original adapter",
            ],
            "query_compatibility": (
                "See config.resolved.yaml; modern_2_26 is an explicit semantic deviation"
            ),
        },
    )
