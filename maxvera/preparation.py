"""Prepare versioned, label-free source views without rewriting frozen releases.

Only trusted preparation reads canonical repository/commit metadata. Git object
caches contain exact shallow commits; analyzer snapshots never contain Git data.
"""

from __future__ import annotations

import csv
import fcntl
import io
import json
import math
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import yaml

from maxvera.contracts import ORACLE_PATTERN, digest, redact, safe_id
from maxvera.dataset import validate_snapshot_manifest, write_snapshot_manifest
from maxvera.graph import relative_file
from maxvera.preflight import build_recipe_issues
from src.common.envfile import effective_env
from src.common.provenance import sha256_file
from src.data.build_projects import build_command_and_env
from src.data.phase2 import (
    ANALYSIS_COLUMNS,
    assert_analysis_rows_safe,
    load_dataset_config,
    validate_checkout,
    verify_checksum_index,
)
from src.graphs.program.runner import _run_command
from src.reproduction.common import atomic_json, read_csv


def _disk_space(path: Path, minimum: float) -> None:
    if shutil.disk_usage(path).free < minimum * 1024**3:
        raise ValueError(f"insufficient disk space; at least {minimum:g} GiB must remain free")


def _git(directory: Path, arguments: list[str], timeout: int) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        }
    }
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            # Archive targets are nested inside MaxVera. Without this ceiling,
            # git apply can report success while ignoring every source-relative path.
            "GIT_CEILING_DIRECTORIES": str(directory.resolve().parent),
        }
    )
    process = _run_command(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=directory,
        env=environment,
        timeout=timeout,
    )
    if process.returncode:
        # Canonical metadata and patch names remain outside analyzer inputs.
        raise RuntimeError(redact(process.stderr.strip() or "pinned Git operation failed"))
    return process.stdout.strip()


def _source_path(analysis: Path, reference: str) -> Path:
    reference = relative_file(reference)
    path = analysis / reference
    if any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(analysis)):
        raise ValueError("source reference contains a symlink")
    if not path.resolve().is_relative_to(analysis):
        raise ValueError("source reference escapes analysis_input")
    if ORACLE_PATTERN.search(reference) or "evaluator_only" in reference:
        raise ValueError("protected source reference")
    return path


def _provenance(row: dict, cfg, patch: Path) -> dict:
    return {
        "dataset_id": cfg.dataset_id,
        "dataset_revision": cfg.revision,
        "source_commit": row["buggy_commit_id"],
        "build_patch_sha256": sha256_file(patch) if patch.is_file() else None,
    }


def _validated(source: Path, case_id: str, provenance: dict) -> dict:
    record = validate_snapshot_manifest(source, case_id, provenance=provenance)
    if record["provenance"]["preparation_policy"] != "pinned-git-archive-normalized-v2":
        raise ValueError(
            "new preparation views require tracked archive v2 inputs; old snapshot preserved"
        )
    issues = build_recipe_issues(source, json.loads((source / "build.runtime.json").read_text()))
    if issues:
        raise ValueError("snapshot build recipe is invalid or its configured tools are unavailable")
    return record


def _object_cache(root: Path, row: dict, timeout: int, offline: bool) -> Path:
    url, commit = row["github_url"], row["buggy_commit_id"]
    if not url or url.startswith("-") or "\0" in url:
        raise ValueError("invalid pinned repository URL")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ValueError("source commit must be an exact pinned SHA")
    cache = root / ".cache/source_preparation/git" / (digest(url) + ".git")
    cache.parent.mkdir(parents=True, exist_ok=True)
    with (cache.parent / (cache.name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not cache.exists():
            if offline:
                raise ValueError("pinned source is unavailable in the offline object cache")
            cache.mkdir()
            _git(cache, ["init", "--bare", "--quiet"], timeout)
        if cache.is_symlink() or not cache.is_dir():
            raise ValueError("unsafe source object cache")
        available = (
            subprocess.run(
                ["git", "cat-file", "-e", commit + "^{commit}"],
                cwd=cache,
                check=False,
                capture_output=True,
                timeout=timeout,
            ).returncode
            == 0
        )
        if not available:
            if offline:
                raise ValueError("pinned commit is unavailable in the offline object cache")
            owned_locks = [
                cache / name
                for name in ("shallow.lock", "FETCH_HEAD.lock", "packed-refs.lock", "config.lock")
                if not (cache / name).exists()
            ]
            try:
                _git(cache, ["fetch", "--depth=1", "--no-tags", "--", url, commit], timeout)
            except subprocess.TimeoutExpired:
                # _run_command has killed the entire owned process group. Only
                # locks created by this exact fetch may be cleaned under flock.
                for stale in owned_locks:
                    stale.unlink(missing_ok=True)
                raise
        resolved = _git(cache, ["rev-parse", commit + "^{commit}"], timeout)
        if resolved != commit:
            raise ValueError("fetched source identity differs from pinned commit")
    return cache


def _archive(cache: Path, target: Path, commit: str, patch: Path, timeout: int) -> dict:
    import hashlib

    archive = target.parent / (target.name + ".tar")
    languages = {".java", ".kt", ".groovy", ".scala"}
    documents = {".adoc", ".md", ".txt", ".rst", ".html", ".pdf", ".odt", ".asc"}
    try:
        _git(cache, ["archive", "--format=tar", "--output=" + str(archive), commit], timeout)
        materialized, omitted, advisories, policy_omissions = [], [], [], []
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            by_name = {member.name.rstrip("/"): member for member in members}
            excluded = set()
            for member in members:
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not (member.isfile() or member.isdir() or member.issym())
                ):
                    raise ValueError("source archive contains unsafe path; audit required")
                if (
                    member.issym()
                    and path.suffix.lower() not in languages
                    and any(
                        path.parts[i : i + 3] == ("src", "test", "resources")
                        for i in range(len(path.parts) - 2)
                    )
                ):
                    # Raw test fixture names/targets can themselves carry labels.
                    # Only trusted transformation receipts receive those strings.
                    omitted.append({"path": member.name, "target": member.linkname})
                    continue
                if member.isfile() and path.suffix.lower() in {".patch", ".diff"}:
                    checksum = hashlib.sha256()
                    with stream.extractfile(member) as document:
                        for block in iter(lambda: document.read(1024 * 1024), b""):
                            checksum.update(block)
                    policy_omissions.append({"path": member.name, "sha256": checksum.hexdigest()})
                    excluded.add(member.name)
                    continue
                if ORACLE_PATTERN.search(member.name):
                    if member.isdir():
                        excluded.add(member.name)
                        continue
                    if not member.isfile() or path.suffix.lower() not in documents:
                        raise ValueError(
                            "oracle identifier in executable/source path requires audit"
                        )
                    checksum = hashlib.sha256()
                    with stream.extractfile(member) as document:
                        for block in iter(lambda: document.read(1024 * 1024), b""):
                            checksum.update(block)
                    advisories.append({"path": member.name, "sha256": checksum.hexdigest()})
                    excluded.add(member.name)
                if not member.issym():
                    continue
                resolved = posixpath.normpath(str(path.parent / member.linkname))
                referent = by_name.get(resolved)
                if (
                    member.linkname.startswith("/")
                    or resolved == ".."
                    or resolved.startswith("../")
                    or referent is None
                    or referent.issym()
                    or path.suffix.lower() in languages
                    or Path(resolved).suffix.lower() in languages
                    or ORACLE_PATTERN.search(resolved)
                ):
                    raise ValueError("source symlink requires independent audit")
                if referent.isdir():
                    descendants = [m for m in members if m.name.startswith(resolved + "/")]
                    if any(
                        m.issym() or Path(m.name).suffix.lower() in languages for m in descendants
                    ):
                        raise ValueError("source directory symlink requires independent audit")
                elif not referent.isfile():
                    raise ValueError("unsupported source symlink target")
                materialized.append({"path": member.name, "target": resolved})
            stream.extractall(
                target, members=[m for m in members if not m.issym() and m.name not in excluded]
            )
        if patch.is_file():
            _git(target, ["apply", str(patch.resolve())], timeout)
        for link in materialized:
            origin, destination = target / link["target"], target / link["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            if origin.is_dir():
                shutil.copytree(origin, destination)
                link["files"] = {
                    p.relative_to(destination).as_posix(): sha256_file(p)
                    for p in sorted(destination.rglob("*"))
                    if p.is_file()
                }
            else:
                shutil.copy2(origin, destination)
                link["sha256"] = sha256_file(destination)
        proof = target / "archive.materialization.json"
        if proof.exists():
            raise ValueError("reserved archive materialization metadata already exists")
        transformations = {
            "materialized_symlinks": materialized,
            "omitted_test_resource_symlinks": omitted,
            "omitted_advisory_documents": advisories,
            "omitted_policy_files": policy_omissions,
        }
        atomic_json(
            proof,
            {
                "schema_version": "2.0",
                "inventory_policy": "tracked-archive-v2",
                **{
                    name: {"count": len(records), "receipt_digest": digest(records)}
                    for name, records in transformations.items()
                },
            },
        )
        return {
            "preparation_policy": "pinned-git-archive-normalized-v2",
            "materialization_sha256": sha256_file(proof),
            "_trusted_omissions": transformations,
        }
    finally:
        archive.unlink(missing_ok=True)


def _recipe(
    root: Path, source: Path, target: Path, row: dict, toolchains: dict, machine: dict
) -> dict:
    recorded = {"jdk": row["jdk_version"]}
    if row.get("maven_version") not in {None, "", "n/a"}:
        recorded["maven"] = row["maven_version"]
    elif row.get("gradle_version") not in {None, "", "n/a"}:
        recorded["gradle"] = row["gradle_version"]
    elif row.get("use_gradlew") in {"1", "true", "True"}:
        recorded["gradlew"] = True
    attempts = []
    options = [recorded, *toolchains["build_attempts"]]
    seen = set()
    for option in options:
        identity = digest(option)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            command, environment = build_command_and_env(root, source, option, toolchains, machine)
            # The historical helper used only clean, which never extracted Java.
            if option.get("gradlew") and "build" not in command:
                command.extend(["build", "-x", "test"])
            attempt = {
                "command": command,
                "environment": {k: v for k, v in environment.items() if k in {"JAVA_HOME", "PATH"}},
            }
            if build_recipe_issues(source, {"attempts": [attempt]}):
                continue
            attempts.append(
                {
                    "command": [arg.replace(str(source), str(target)) for arg in command],
                    "environment": {
                        k: v.replace(str(source), str(target))
                        for k, v in attempt["environment"].items()
                    },
                }
            )
        except (ValueError, KeyError):
            continue
    if not attempts:
        raise ValueError("no available trusted build attempts; install configured toolchains")
    return {"attempts": attempts}


def _manifest(path: Path, rows: list[dict]) -> None:
    assert_analysis_rows_safe(rows)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=ANALYSIS_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    content = output.getvalue()
    if path.exists():
        if path.is_symlink() or path.read_text() != content:
            raise ValueError("prepared view manifest is immutable; choose a new view name")
        return
    descriptor, name = tempfile.mkstemp(prefix=".manifest-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
        os.rename(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_sources(
    root: Path,
    config: Path,
    *,
    view_name: str,
    reuse_manifest: Path | None = None,
    selected_ids: list[str] | None = None,
    timeout: int = 600,
    offline: bool = False,
    min_free_gib: float = 20,
) -> dict:
    """Prepare exact commits in a new resumable view, preserving all release artifacts.

    A selected subset limits work only: the output manifest always retains every
    canonical row. Availability of a source/build recipe does not prove a build.
    The machine-readable progress journal lives outside the analyzer view.
    """
    if os.environ.get("MAXVERA_DATA_ROLE") == "analysis":
        raise ValueError("trusted source preparation is unavailable inside the analyzer")
    root = root.resolve()
    safe_id(view_name)
    if ORACLE_PATTERN.search(view_name) or "evaluator_only" in view_name:
        raise ValueError("protected preparation view name")
    if type(timeout) is not int or timeout < 1 or timeout > 7200:
        raise ValueError("fetch timeout must be between 1 and 7200 seconds")
    if not math.isfinite(min_free_gib) or min_free_gib < 0:
        raise ValueError("minimum free disk space must be nonnegative and finite")
    _disk_space(root, min_free_gib)
    cfg = load_dataset_config(config if config.is_absolute() else root / config)
    suffix = "cwe_bench_java_v1" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_java_extended"
    raw = root / "data/raw" / suffix
    validate_checkout(raw, cfg)
    processed = root / "data/processed"
    for index, base in (
        (processed / f"manifests/{cfg.dataset_id}_checksums.sha256", root),
        (processed / f"manifests/{cfg.dataset_id}_source_checksums.sha256", raw),
    ):
        failures = verify_checksum_index(index, base)
        if failures:
            raise ValueError("frozen dataset checksum validation failed: " + "; ".join(failures))
    canonical = (
        processed
        / "manifests"
        / ("cwe_bench_v1.csv" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_extended.csv")
    )
    rows = read_csv(canonical)
    ids = [safe_id(row["project_id"]) for row in rows]
    if not rows or len(set(ids)) != len(ids):
        raise ValueError("canonical source cohort must have unique nonempty cases")
    if any(
        row["dataset_id"] != cfg.dataset_id or row["upstream_revision"] != cfg.revision
        for row in rows
    ):
        raise ValueError("canonical source cohort differs from pinned dataset identity")
    selected = set(ids) if selected_ids is None else {safe_id(case) for case in selected_ids}
    if (
        not selected
        or (selected_ids is not None and len(selected) != len(selected_ids))
        or selected - set(ids)
    ):
        raise ValueError("preparation selection must contain unique canonical case IDs")
    analysis = processed / "analysis_input"
    view = _source_path(analysis, view_name)
    manifest = view / f"{cfg.dataset_id}_projects.csv"
    reuse = {}
    if reuse_manifest is not None:
        reuse_path = reuse_manifest if reuse_manifest.is_absolute() else root / reuse_manifest
        for row in read_csv(reuse_path):
            if set(row) - set(ANALYSIS_COLUMNS) or row["project_id"] in reuse:
                raise ValueError("reuse manifest must contain unique label-free source references")
            _source_path(analysis, row["source_dir"])
            reuse[row["project_id"]] = row["source_dir"]
    existing = {row["project_id"]: row for row in read_csv(manifest)} if manifest.is_file() else {}
    output_rows = []
    for row in rows:
        case_id = row["project_id"]
        reference = f"{view_name}/projects/{case_id}"
        patch = raw / "patches" / f"{row['project_slug']}.patch"
        if case_id in existing:
            reference = existing[case_id]["source_dir"]
        elif case_id in reuse:
            try:
                _validated(
                    _source_path(analysis, reuse[case_id]), case_id, _provenance(row, cfg, patch)
                )
                reference = reuse[case_id]
            except (ValueError, OSError, TypeError, KeyError):
                pass
        output_rows.append(
            {
                "project_id": case_id,
                "source_dir": reference,
                "source_required": "true",
                **{key: row[key] for key in ANALYSIS_COLUMNS[3:]},
            }
        )
    toolchains = yaml.safe_load((root / "configs/toolchains/cwe_bench_java.yaml").read_text())
    machine = effective_env(root / ".env")
    view.mkdir(parents=True, exist_ok=True)
    logs = root / "logs/source_preparation" / view_name
    logs.mkdir(parents=True, exist_ok=True)
    with (logs / "preparation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        identity = {
            "dataset_id": cfg.dataset_id,
            "dataset_revision": cfg.revision,
            "canonical_sha256": sha256_file(canonical),
            "analysis_rows_sha256": digest(output_rows),
        }
        identity_path = logs / "identity.json"
        if identity_path.exists():
            if identity_path.is_symlink() or json.loads(identity_path.read_text()) != identity:
                raise ValueError("prepared view identity is immutable; choose a new view name")
        elif manifest.exists():
            raise ValueError(
                "existing manifest has no immutable preparation identity; choose a new view name"
            )
        else:
            atomic_json(identity_path, identity)
        _manifest(manifest, output_rows)
        report = {
            "schema_version": "1.0",
            "dataset_id": cfg.dataset_id,
            "dataset_revision": cfg.revision,
            "manifest": str(manifest),
            "manifest_cases": len(rows),
            "requested": len(selected),
            "prepared": 0,
            "reused": 0,
            "failed": 0,
            "ready": False,
            "build_executed": False,
            "cases": [],
        }
        for row, output in zip(rows, output_rows, strict=True):
            if row["project_id"] not in selected:
                continue
            case_id = row["project_id"]
            target = _source_path(analysis, output["source_dir"])
            patch = raw / "patches" / f"{row['project_slug']}.patch"
            provenance = _provenance(row, cfg, patch)
            temporary = None
            try:
                _disk_space(root, min_free_gib)
                if target.exists():
                    record = _validated(target, case_id, provenance)
                    status = "REUSED"
                else:
                    if output["source_dir"] != f"{view_name}/projects/{case_id}":
                        raise ValueError(
                            "referenced verified snapshot is missing; preserved manifest"
                        )
                    cache = _object_cache(root, row, timeout, offline)
                    _disk_space(root, min_free_gib)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    temporary = Path(
                        tempfile.mkdtemp(prefix=f".{case_id}.preparing-", dir=target.parent)
                    )
                    archive_proof = _archive(
                        cache, temporary, row["buggy_commit_id"], patch, timeout
                    )
                    omissions = archive_proof.pop("_trusted_omissions", [])
                    if omissions:
                        atomic_json(logs / "transformations" / f"{case_id}.json", omissions)
                    _disk_space(root, min_free_gib)
                    recipe = _recipe(root, temporary, target, row, toolchains, machine)
                    (temporary / "build.runtime.json").write_text(
                        json.dumps(recipe, sort_keys=True)
                    )
                    record = write_snapshot_manifest(
                        temporary,
                        case_id,
                        {**provenance, **archive_proof},
                    )
                    validate_snapshot_manifest(temporary, case_id, provenance=provenance)
                    if target.exists() or target.is_symlink():
                        raise ValueError(
                            "snapshot appeared during preparation; refusing to overwrite"
                        )
                    os.rename(temporary, target)
                    record = _validated(target, case_id, provenance)
                    status = "PREPARED"
                report[status.lower()] += 1
                report["cases"].append(
                    {
                        "case_id": case_id,
                        "status": status,
                        "source_dir": output["source_dir"],
                        "semantic_snapshot_id": record["semantic_snapshot_id"],
                        "files": len(record["files"]),
                    }
                )
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                report["failed"] += 1
                report["cases"].append(
                    {
                        "case_id": case_id,
                        "status": "FAILED",
                        "source_dir": output["source_dir"],
                        "error": redact(str(error)),
                        "existing_snapshot_preserved": target.exists(),
                    }
                )
            finally:
                if temporary is not None and temporary.exists():
                    shutil.rmtree(temporary)
            atomic_json(logs / "status.json", report)
        report["ready"] = report["prepared"] + report["reused"] == len(selected)
        report["manifest_sha256"] = sha256_file(manifest)
        atomic_json(logs / "status.json", report)
        return report
