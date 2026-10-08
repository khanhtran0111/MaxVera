"""Immutable development runs and sequential CodeQL execution for pipeline v2."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import zipfile
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import collect_environment, collect_git, sha256_file, utc_now
from src.experiments.development_audit import snapshot_run
from src.graphs.program.runner import _assert_database_cache_unlocked, _run_command
from src.pipeline_v2.model import candidates_from_flows, inventory_records
from src.reproduction.common import atomic_json, atomic_jsonl, read_csv, read_jsonl, write_checksums
from src.verification.runner import _codeql

QUERY_ROOT = "src/static_analysis/queries/v2"


def configuration(root: Path, path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("analysis_scope") not in {
        "development",
        "benchmark_diagnostic",
    }:
        raise ValueError("pipeline v2 execution scope is not registered")
    status = (
        "benchmark_diagnostic_v2"
        if value["analysis_scope"] == "benchmark_diagnostic"
        else "development_v2"
    )
    if value.get("protocol_version") != "2.0.0" or value.get("status") != status:
        raise ValueError("pipeline v2 execution policy is not registered")
    dataset = value["dataset"]
    split = root / "data/processed/splits/development.csv"
    if dataset["development_split_sha256"] != sha256_file(split):
        raise ValueError("development split checksum mismatch")
    if value["analysis_scope"] == "benchmark_diagnostic":
        selection_ids(root, value)
    return cast(dict[str, Any], value)


def development_ids(root: Path, *, project_id: str | None = None) -> list[str]:
    identifiers = [
        row["project_id"] for row in read_csv(root / "data/processed/splits/development.csv")
    ]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("development split contains duplicate IDs")
    if project_id is not None:
        if project_id not in identifiers:
            raise ValueError("project is outside development")
        return [project_id]
    return identifiers


def selection_ids(
    root: Path,
    config: Mapping[str, Any],
    *,
    project_id: str | None = None,
) -> list[str]:
    if config.get("analysis_scope") == "development":
        return development_ids(root, project_id=project_id)
    if config.get("analysis_scope") != "benchmark_diagnostic":
        raise ValueError("unregistered selection scope")
    policy, dataset = config["benchmark"], config["dataset"]
    if (
        policy.get("confirmatory") is not False
        or policy.get("calibration_fit_scope") != "development"
        or config["execution"].get("historical_test_allowed") is not True
    ):
        raise ValueError("benchmark requires diagnostic disposition and development-only fitting")
    identifiers = development_ids(root)
    test_path = root / "data/processed/splits/test_locked.csv"
    if sha256_file(test_path) != dataset["test_split_sha256"]:
        raise ValueError("benchmark test split checksum mismatch")
    identifiers += [row["project_id"] for row in read_csv(test_path)]
    population = root / dataset["population"]
    if (
        sha256_file(population) != dataset["population_sha256"]
        or len(identifiers) != 120
        or len(set(identifiers)) != 120
        or set(identifiers) != {r["project_id"] for r in read_csv(population)}
    ):
        raise ValueError("benchmark must cover the exact 120-case release without split overlap")
    if project_id is not None:
        if project_id not in identifiers:
            raise ValueError("project is outside benchmark")
        return [project_id]
    return identifiers


def implementation_hashes(root: Path) -> dict[str, str]:
    paths = [
        *sorted((root / "src/pipeline_v2").glob("*.py")),
        *sorted((root / QUERY_ROOT).glob("*.ql")),
        *sorted((root / QUERY_ROOT).glob("*.qll")),
        root / QUERY_ROOT / "qlpack.yml",
        root / QUERY_ROOT / "codeql-pack.lock.yml",
        root / "src/specification/schema.py",
        root / "src/retrieval/graph.py",
        root / "src/llm/providers/openrouter.py",
        root / "src/llm/prompts/phase10.py",
        root / "src/graphs/program/runner.py",
        root / "src/graphs/evidence/model.py",
        root / "src/verification/remap.py",
        root / "src/verification/runner.py",
        root / "src/verification/query.py",
        root / "src/calibration/model.py",
        root / "src/reproduction/common.py",
        root / "src/common/provenance.py",
        root / "src/common/envfile.py",
        root / "pyproject.toml",
        root / "uv.lock",
        root / "scripts/tools/run_pipeline_v2_tmux.sh",
        root / "scripts/tools/run_pipeline_v2_recovery_tmux.sh",
        root / "scripts/tools/run_pipeline_v2_recovery_003_tmux.sh",
        root / "configs/toolchains/cwe_bench_java.yaml",
        root / "src/verification/prepare_fixed.py",
        root / "src/data/build_projects.py",
        root / "src/graphs/program/build_databases.py",
        root / "src/cli/run_baseline.py",
        root / "scripts/tools/run_b9_v2_tmux.sh",
        root / "scripts/10_run_b9_full_useg.sh",
    ]
    return {
        path.relative_to(root).as_posix(): sha256_file(path) for path in paths if path.is_file()
    }


class Run:
    def __init__(
        self,
        root: Path,
        output: str,
        run_id: str,
        phase: int,
        config_path: Path,
        selected: Sequence[str],
        *,
        resume: bool = False,
        dependencies: Mapping[str, Any] | None = None,
        require_clean: bool = False,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", run_id):
            raise ValueError("invalid run ID")
        self.config = yaml.safe_load(config_path.read_text())
        self.config.setdefault("analysis_scope", "development")
        if self.config["analysis_scope"] == "benchmark_diagnostic":
            self.config = configuration(root, config_path)
        allowed = selection_ids(root, self.config)
        if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(allowed):
            raise ValueError("run selection must contain unique registered cohort IDs only")
        if require_clean and list(selected) != allowed:
            raise ValueError("canonical full run must account for the entire development split")
        self.root, self.run_id, self.phase = root, run_id, phase
        self.final = root / output / run_id
        self.work = self.final.with_name("." + run_id + ".inprogress")
        self.selected = list(selected)
        if self.final.exists():
            raise FileExistsError(f"immutable run exists: {self.final}")
        git = collect_git(root)
        if require_clean and git["dirty"]:
            raise ValueError("canonical full v2 run requires a clean implementation snapshot")
        expected: dict[str, Any] = {
            "config_sha256": sha256_file(config_path),
            "model_config_sha256": sha256_file(
                root / yaml.safe_load(config_path.read_text())["model_config"]
            ),
            "selected_project_ids": list(selected),
            "implementation_sha256": implementation_hashes(root),
            "dependencies": dict(dependencies or {}),
        }
        diagnostic = self.config["analysis_scope"] == "benchmark_diagnostic"
        if diagnostic:
            expected["cohort_sha256"] = {
                key: self.config["dataset"][key]
                for key in ("development_split_sha256", "test_split_sha256", "population_sha256")
            }
            if phase == 6:
                expected["dependencies"]["benchmark_seed"] = self.config["benchmark"]["phase6_seed"]
        if self.work.exists():
            if not resume:
                raise FileExistsError(f"use --resume for unfinished run: {self.work}")
            manifest = json.loads((self.work / "manifest.json").read_text())
            if any(manifest.get(key) != value for key, value in expected.items()):
                raise ValueError(
                    "resume implementation, configuration, selection or inputs changed"
                )
        else:
            self.work.mkdir(parents=True)
            atomic_json(
                self.work / "manifest.json",
                {
                    "schema_version": 2,
                    "phase": phase,
                    "protocol_version": "2.0.0",
                    "run_id": run_id,
                    "analysis_scope": self.config["analysis_scope"],
                    "git": git,
                    "created_at": utc_now(),
                    "canonical_result": require_clean and not diagnostic,
                    "confirmatory_result": False,
                    "data_access": (
                        "development evaluator labels/groups"
                        if phase == 12
                        else "opaque development projects and source-backed artifacts"
                    ),
                    **expected,
                },
            )
            atomic_json(self.work / "environment.json", collect_environment(root))
            (self.work / "command.txt").write_text(shlex.join(sys.argv) + "\n")
            (self.work / "stdout.log").write_text("")
            (self.work / "stderr.log").write_text("")
            atomic_jsonl(
                self.work / "project_status.jsonl",
                [
                    {
                        "project_id": project,
                        "status": "PENDING",
                        "reason": "awaiting development analysis",
                    }
                    for project in selected
                ],
            )
            shutil.copytree(
                root / QUERY_ROOT,
                self.work / "query_pack",
                ignore=shutil.ignore_patterns("*.qlx", ".cache"),
            )
        self.statuses = read_jsonl(self.work / "project_status.jsonl")
        if diagnostic and phase == 6:
            from src.pipeline_v2.benchmark_inputs import inherit_discovery

            inherit_discovery(self)

    def status(self, project: str, status: str, reason: str, **fields: Any) -> None:
        if project not in self.selected:
            raise ValueError("status project is outside the frozen run selection")
        record = {
            "project_id": project,
            "status": status,
            "reason": reason,
            "updated_at": utc_now(),
            **fields,
        }
        self.statuses = [record if row["project_id"] == project else row for row in self.statuses]
        atomic_jsonl(self.work / "project_status.jsonl", self.statuses)
        line = f"{utc_now()} {project} {status}: {reason}\n"
        with (self.work / "stdout.log").open("a") as handle:
            handle.write(line)
        print(line, end="", flush=True)
        if (
            self.phase in {6, 10, 11}
            and self.config.get("execution", {}).get(
                "cache_cleanup_after_project",
                self.config.get("recovery", {}).get("cache_cleanup_after_project"),
            )
            and "inherited_from" not in fields
        ):
            from src.pipeline_v2.recovery import cleanup_cache

            cleanup_cache(self, project, self.config)

    def pending(self) -> list[str]:
        return [row["project_id"] for row in self.statuses if row["status"] == "PENDING"]

    def finalize(self, summary: Mapping[str, Any]) -> Path:
        if self.pending():
            raise ValueError("cannot finalize a run with pending projects")
        atomic_json(
            self.work / "summary.json",
            {
                "schema_version": 2,
                "phase": self.phase,
                "run_id": self.run_id,
                "analysis_scope": self.config["analysis_scope"],
                "projects": len(self.selected),
                "analysis_successes": sum(row["status"] == "SUCCESS" for row in self.statuses),
                "analysis_failures": sum(row["status"] != "SUCCESS" for row in self.statuses),
                **summary,
            },
        )
        (self.work / "STATUS").write_text(
            "PASS_WITH_ANALYSIS_FAILURES\n"
            if any(row["status"] != "SUCCESS" for row in self.statuses)
            else "PASS\n"
        )
        write_checksums(self.work)
        self.work.rename(self.final)
        return self.final


def dependency(
    root: Path, relative: str, selected: Sequence[str], phase: int
) -> tuple[Path, dict[str, Any]]:
    path = (root / relative).resolve()
    if not path.is_relative_to((root / "results").resolve()):
        raise ValueError("dependency is outside the results directory")
    manifest = json.loads((path / "manifest.json").read_text())
    scope = manifest.get("analysis_scope")
    if scope == "development":
        allowed = development_ids(root)
    elif scope == "benchmark_diagnostic":
        hashes = manifest.get("cohort_sha256", {})
        paths = {
            "development_split_sha256": "data/processed/splits/development.csv",
            "test_split_sha256": "data/processed/splits/test_locked.csv",
            "population_sha256": "data/processed/analysis_input/D_extended_projects.csv",
        }
        if manifest.get("confirmatory_result") is not False or any(
            hashes.get(key) != sha256_file(root / value) for key, value in paths.items()
        ):
            raise ValueError("diagnostic dependency cohort changed")
        allowed = development_ids(root) + [
            r["project_id"] for r in read_csv(root / paths["test_split_sha256"])
        ]
    else:
        raise ValueError("dependency scope is not registered")
    if (
        manifest.get("phase") != phase
        or not set(selected) <= set(allowed)
        or manifest.get("protocol_version") != "2.0.0"
        or not set(selected) <= set(manifest.get("selected_project_ids", []))
    ):
        raise ValueError("pipeline v2 dependency is not a compatible development run")
    snapshot_run(path)
    return path, {
        "run_id": manifest["run_id"],
        "run_root": path.relative_to(root).as_posix(),
        "manifest_sha256": sha256_file(path / "manifest.json"),
        "checksums_sha256": sha256_file(path / "checksums.sha256"),
    }


def query_csv(
    binary: Path,
    database: Path,
    query: Path,
    output: Path,
    policy: Mapping[str, Any],
    before_query: Callable[[], None] | None = None,
    *,
    entity_ids: bool = False,
) -> list[dict[str, str]]:
    _assert_database_cache_unlocked(database)
    output.parent.mkdir(parents=True, exist_ok=True)
    bqrs, decoded = output.with_suffix(".bqrs"), output.with_suffix(".csv")
    command = [
        str(binary),
        "query",
        "run",
        f"--threads={policy['threads']}",
        f"--ram={policy['ram_mb']}",
        f"--database={database}",
        f"--output={bqrs}",
        str(query),
    ]
    if before_query is not None:
        before_query()
    log_path = output.with_suffix(".log")
    log_path.write_text(f"command={shlex.join(command)}\nstatus=STARTED\n")
    try:
        process = _run_command(command, timeout=int(policy["timeout_seconds"]))
    except subprocess.TimeoutExpired as error:
        with log_path.open("a") as handle:
            handle.write(f"status=TIMEOUT\n{error.output!r}\n{error.stderr!r}")
        raise
    output.with_suffix(".log").write_text(
        f"command={shlex.join(command)}\nexit_code={process.returncode}\n"
        f"{process.stdout}\n{process.stderr}"
    )
    if process.returncode:
        raise RuntimeError(f"CodeQL query failed; see {output.with_suffix('.log')}")
    json_path = output.with_suffix(".entities.json")
    process = _run_command(
        [
            str(binary),
            "bqrs",
            "decode",
            "--format=json" if entity_ids else "--format=csv",
            "--result-set=#select",
            "--entities=id,string" if entity_ids else "--entities=string",
            f"--output={json_path if entity_ids else decoded}",
            str(bqrs),
        ],
        timeout=300,
    )
    if process.returncode:
        raise RuntimeError("CodeQL result decode failed")
    if entity_ids:
        payload = json.loads(json_path.read_text())
        rows = entity_rows(payload)
        fields = (
            list(rows[0])
            if rows
            else [str(col.get("name", f"col{i}")) for i, col in enumerate(payload["columns"])]
        )
        with decoded.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return rows
    return read_csv(decoded)


def entity_rows(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    fields = [str(col.get("name", f"col{i}")) for i, col in enumerate(payload["columns"])]
    records = []
    for values in payload["tuples"]:
        if len(values) != len(fields):
            raise ValueError("CodeQL entity result width mismatch")
        row = {}
        for field, value in zip(fields, values, strict=True):
            if isinstance(value, dict):
                if "id" not in value:
                    raise ValueError("CodeQL entity result lacks an internal ID")
                row[field] = str(value.get("label", value["id"]))
                row[field + "_entity_id"] = str(value["id"])
            else:
                row[field] = str(value)
        records.append(row)
    return records


def unique_inventory_rows(
    rows: Sequence[Mapping[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    fields = (
        "role",
        "file",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "enclosing_callable",
        "expression_kind",
        "dataflow_kind",
        "slot",
        "target_signature",
        "expression",
    )
    entities: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for row in rows:
        entity = row.get("resolved_node_entity_id")
        if not entity:
            raise ValueError("typed inventory lacks an internal CodeQL node ID")
        entities[tuple(row[field] for field in fields)].add(entity)
    eligible: list[dict[str, str]] = []
    ambiguous: list[dict[str, str]] = []
    for row in rows:
        (
            eligible if len(entities[tuple(row[field] for field in fields)]) == 1 else ambiguous
        ).append(dict(row))
    return eligible, ambiguous


def codeql(root: Path, policy: Mapping[str, Any]) -> Path:
    binary = _codeql(root)
    process = _run_command([str(binary), "version", "--format=json"], timeout=60)
    if process.returncode or json.loads(process.stdout).get("version") != policy["version"]:
        raise ValueError("CodeQL executable does not match the frozen tool version")
    library = binary.parent / "qlpacks/codeql/java-all" / str(policy["java_pack"]) / "qlpack.yml"
    if (
        not library.is_file()
        or str(yaml.safe_load(library.read_text()).get("version")) != policy["java_pack"]
    ):
        raise ValueError("pinned Java CodeQL library is unavailable")
    return binary


def endpoint_inventory(
    project: str,
    database: Path,
    binary: Path,
    pack: Path,
    directory: Path,
    policy: Mapping[str, Any],
    before_query: Callable[[], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not (database / "codeql-database.yml").is_file():
        raise FileNotFoundError("vulnerable/fixed database is unavailable")
    rows = query_csv(
        binary,
        database,
        pack / "endpoints.ql",
        directory / "endpoints",
        policy,
        before_query,
        entity_ids=True,
    )
    rows, ambiguous = unique_inventory_rows(rows)
    atomic_jsonl(directory / "ambiguous_endpoints.jsonl", ambiguous)
    archive = database / "src.zip"
    database_metadata = yaml.safe_load((database / "codeql-database.yml").read_text())
    column_kind = database_metadata.get("columnKind")
    if column_kind != "utf16":
        raise ValueError("endpoint source fingerprints require the pinned UTF-16 column contract")
    sources = archive_sources(archive, sorted({r["file"] for r in rows}))
    source_hashes = {file: value[0] for file, value in sources.items()}
    for row in rows:
        lines = sources[row["file"]][1]
        start, end = int(row["start_line"]), int(row["end_line"])
        if not 1 <= start <= end <= len(lines):
            raise ValueError("endpoint span is outside its source archive")
        row["source_text_sha256"] = source_text_fingerprint(lines, row)
    provenance = {
        "producer": "typed-codeql-endpoint-inventory-v2",
        "query_sha256": sha256_file(pack / "endpoints.ql"),
        "library_sha256": sha256_file(pack / "Grounding.qll"),
        "inventory_bqrs_sha256": sha256_file(directory / "endpoints.bqrs"),
        "database_metadata_sha256": sha256_file(database / "codeql-database.yml"),
        "source_archive_sha256": sha256_file(archive),
        "tool_version": "2.26.2",
        "java_pack": "codeql/java-all@9.2.2",
        "column_kind": column_kind,
        "extractor_cli_version": str(
            database_metadata.get("creationMetadata", {}).get("cliVersion", "")
        ),
        "ambiguous_inventory_rows": len(ambiguous),
        "ambiguous_inventory_sha256": sha256_file(directory / "ambiguous_endpoints.jsonl"),
    }
    return inventory_records(project, rows, source_hashes, provenance), provenance


def source_text_fingerprint(lines: Sequence[str], row: Mapping[str, str]) -> str:
    start, end = int(row["start_line"]), int(row["end_line"])
    excerpt = [line.encode("utf-16-le") for line in lines[start - 1 : end]]
    if not excerpt:
        raise ValueError("source fingerprint has no source lines")
    first, last = int(row["start_column"]), int(row["end_column"])
    if first < 1 or 2 * (first - 1) >= len(excerpt[0]) or last < 1 or 2 * last > len(excerpt[-1]):
        raise ValueError("endpoint UTF-16 column is outside the source line")
    excerpt[-1] = excerpt[-1][: 2 * last]
    excerpt[0] = excerpt[0][2 * (first - 1) :]
    try:
        text = "\n".join(line.decode("utf-16-le") for line in excerpt)
    except UnicodeError as error:
        raise ValueError("endpoint splits a UTF-16 character") from error
    if not text:
        raise ValueError("empty endpoint source fingerprint")
    return hashlib.sha256(text.encode()).hexdigest()


def archive_sources(archive: Path, files: Sequence[str]) -> dict[str, tuple[str, list[str]]]:
    """Open the archive once while retaining the exact unique suffix-match contract."""
    result = {}
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        for file in files:
            relative = Path(file)
            if relative.is_absolute() or ".." in relative.parts or "\\" in file or not file:
                raise ValueError("source file must be a safe relative path")
            matches = [name for name in names if name == file or name.endswith("/" + file)]
            if len(matches) != 1:
                raise ValueError(
                    f"source archive requires one match for {file}; found {len(matches)}"
                )
            data = handle.read(matches[0])
            result[file] = (
                hashlib.sha256(data).hexdigest(),
                data.decode("utf-8", errors="replace").splitlines(),
            )
    return result


def phase6(
    root: Path,
    config: Mapping[str, Any],
    config_path: Path,
    selected: Sequence[str],
    run_id: str,
    *,
    resume: bool = False,
    full: bool = False,
) -> Path:
    if os.environ.get("MAXVERA_DATA_ROLE") == "evaluator":
        raise ValueError("Phase 6 must run at the analyzer process boundary")
    run = Run(
        root,
        "results/hypotheses/grounded_v2",
        run_id,
        6,
        config_path,
        selected,
        resume=resume,
        require_clean=full,
        dependencies=(
            {
                "historical_phase6": {
                    "run_root": config["recovery"]["phase6_run"],
                    "manifest_sha256": config["recovery"]["phase6_manifest_sha256"],
                }
            }
            if config.get("recovery")
            else None
        ),
    )
    binary = codeql(root, config["codeql"])
    policy = config["codeql"]
    if config.get("recovery"):
        from src.pipeline_v2.recovery import inherited_phase6

        inherited_phase6(run, config)
    for project in run.pending():
        started = time.monotonic()
        directory = run.work / "projects" / project
        try:
            database = root / str(config["dataset"]["vulnerable_database_root"]) / project
            endpoints, provenance = endpoint_inventory(
                project, database, binary, run.work / "query_pack", directory, policy
            )
            flows = query_csv(
                binary, database, run.work / "query_pack/flows.ql", directory / "flows", policy
            )
            hypotheses, rejected = candidates_from_flows(
                project, endpoints, flows, top_k=int(config["top_k"])
            )
            sinks_with_flow = {
                endpoint["node_id"]
                for hypothesis in hypotheses
                for endpoint in hypothesis["sink_candidates"]
            }
            for endpoint in endpoints:
                if "sink" in endpoint["roles"] and endpoint["node_id"] not in sinks_with_flow:
                    rejected.append(
                        {
                            "project_id": project,
                            "node_id": endpoint["node_id"],
                            "reason": "NOT_SELECTED_OR_NO_GROUNDED_CANDIDATE_RELATION",
                        }
                    )
            atomic_jsonl(directory / "endpoints.jsonl", endpoints)
            atomic_jsonl(directory / "hypotheses.jsonl", hypotheses)
            atomic_jsonl(directory / "rejected.jsonl", rejected)
            atomic_json(directory / "database_provenance.json", provenance)
            run.status(
                project,
                "SUCCESS",
                "typed endpoints and discovery complete; hypotheses remain unverified",
                endpoints=len(endpoints),
                flow_pairs=len(flows),
                hypotheses=len(hypotheses),
                wall_seconds=round(time.monotonic() - started, 3),
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            zipfile.BadZipFile,
            subprocess.TimeoutExpired,
        ) as error:
            # Completed project records are authoritative; partial query outputs remain diagnostic.
            run.status(
                project,
                "ANALYSIS_FAILED",
                f"{type(error).__name__}: {error}",
                hypotheses=0,
                wall_seconds=round(time.monotonic() - started, 3),
            )
    hypotheses = [
        row
        for status in run.statuses
        if status["status"] == "SUCCESS"
        for row in read_jsonl(run.work / "projects" / status["project_id"] / "hypotheses.jsonl")
    ]
    atomic_jsonl(run.work / "hypotheses.jsonl", hypotheses)
    return run.finalize(
        {
            "hypotheses": len(hypotheses),
            "llm_calls": 0,
            "verified_findings": 0,
            "generator": "typed_codeql_candidate_discovery_v2",
        }
    )
