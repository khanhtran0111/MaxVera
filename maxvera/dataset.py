"""Trusted metadata preparation and strictly label-free analyzer case selection."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from maxvera.contracts import ORACLE_PATTERN, digest, require_keys, safe_id
from maxvera.graph import relative_file
from src.common.provenance import sha256_file
from src.data.phase2 import acquire_dataset, load_dataset_config, materialize_release
from src.reproduction.common import read_csv


def select_cases(
    root: Path, dataset: dict, mode: str, limit: int | None = None, *, oracle: bool = False
) -> list[dict]:
    if mode == "full" and limit is not None:
        raise ValueError("full mode cannot be truncated by --limit")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    key = "oracle_manifest" if oracle else "analysis_manifest"
    path = (root / dataset[key]).resolve()
    rows = read_csv(path)
    if not oracle:
        allowed = {
            "project_id",
            "case_id",
            "source_dir",
            "source_required",
            "database_dir",
            "jdk_version",
            "maven_version",
            "gradle_version",
            "use_gradlew",
        }
        if any(set(row) - allowed for row in rows):
            raise ValueError("protected field in analysis manifest")
        if ORACLE_PATTERN.search(json.dumps(rows)) or "evaluator_only" in json.dumps(rows):
            raise ValueError("protected label/path in analysis manifest")
    cases = [{**r, "case_id": safe_id(r.get("case_id", r.get("project_id", "")))} for r in rows]
    if len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("duplicate case IDs")
    expected = dataset.get("expected_cases", len(cases))
    if mode == "full" and len(cases) != expected:
        raise ValueError(f"case coverage: expected {expected}, got {len(cases)}")
    if dataset.get("split"):
        split_rows = read_csv(root / dataset["split"])
        if any(set(row) - {"project_id", "case_id", "split"} for row in split_rows):
            raise ValueError("protected field in analysis split")
        selected = {safe_id(r.get("case_id", r.get("project_id", ""))) for r in split_rows}
        if len(selected) != len(split_rows):
            raise ValueError("duplicate case IDs in split")
        cases = [c for c in cases if c["case_id"] in selected]
        if {c["case_id"] for c in cases} != selected:
            raise ValueError("split coverage mismatch")
    if not cases:
        raise ValueError("empty case selection")
    selected_expected = dataset.get("expected_selected_cases")
    if selected_expected is not None and len(cases) != selected_expected:
        raise ValueError(f"selected case coverage: expected {selected_expected}, got {len(cases)}")
    return cases[: limit or 2] if mode == "smoke" else cases


def _snapshot_files(source: Path) -> dict[str, str]:
    from maxvera.snapshots import source_inventory

    return {k: v for k, v in source_inventory(source).items() if k != "snapshot.files.json"}


def _validate_provenance(value: dict) -> None:
    if not isinstance(value, dict):
        raise ValueError("snapshot provenance must be a mapping")
    required = {
        "dataset_id",
        "dataset_revision",
        "source_commit",
        "build_patch_sha256",
        "preparation_policy",
        "build_recipe_sha256",
    }
    require_keys(
        value, required | {"verification", "materialization_sha256"}, "snapshot provenance"
    )
    if not required <= set(value):
        raise ValueError("snapshot provenance incomplete")
    if not isinstance(value["dataset_id"], str):
        raise ValueError("snapshot provenance dataset_id must be a string")
    safe_id(value["dataset_id"])
    for name in ("dataset_revision", "source_commit"):
        if not isinstance(value[name], str) or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value[name]
        ):
            raise ValueError(f"snapshot provenance {name} must be a pinned commit")
    for name in ("build_patch_sha256", "build_recipe_sha256"):
        if value[name] is None and name == "build_patch_sha256":
            continue
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise ValueError(f"snapshot provenance {name} must be SHA256")
    if value["preparation_policy"] not in {
        "pinned-git-archive-v1",
        "audited-snapshot-copy-v1",
        "pinned-git-archive-normalized-v1",
        "pinned-git-archive-normalized-v2",
    }:
        raise ValueError("unknown snapshot preparation policy")
    if value["preparation_policy"] in {
        "pinned-git-archive-normalized-v1",
        "pinned-git-archive-normalized-v2",
    } and (
        not isinstance(value.get("materialization_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["materialization_sha256"])
    ):
        raise ValueError("materialized documentation requires pinned archive proof")
    if value["preparation_policy"] == "audited-snapshot-copy-v1":
        proof = value.get("verification", {})
        if (
            not isinstance(proof, dict)
            or set(proof) != {"kind", "artifact_sha256"}
            or proof.get("kind") not in {"audited-run-ingest", "pinned-source-inventory"}
            or not isinstance(proof.get("artifact_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", proof["artifact_sha256"])
        ):
            raise ValueError("audited snapshot copy requires exact authoritative inventory proof")
    if ORACLE_PATTERN.search(json.dumps(value)) or "evaluator_only" in json.dumps(value):
        raise ValueError("protected oracle metadata in snapshot provenance")


def write_snapshot_manifest(source: Path, case_id: str, provenance: dict) -> dict:
    """Seal a newly prepared snapshot; never replace an existing audited manifest."""
    from maxvera.snapshots import semantic_inventory, tracked_input_policy
    from src.reproduction.common import atomic_json

    safe_id(case_id)
    manifest = source / "snapshot.files.json"
    if manifest.exists() or manifest.is_symlink():
        raise ValueError("snapshot manifest exists; refusing to overwrite")
    files = _snapshot_files(source)
    if "build.runtime.json" not in files:
        raise ValueError("snapshot requires build.runtime.json")
    provenance = {**provenance, "build_recipe_sha256": files["build.runtime.json"]}
    _validate_provenance(provenance)
    if provenance["preparation_policy"] == "pinned-git-archive-normalized-v2" and (
        not tracked_input_policy(source)
        or files.get("archive.materialization.json") != provenance["materialization_sha256"]
    ):
        raise ValueError("tracked archive policy requires exact pinned materialization ledger")
    record = {
        "schema_version": "1.0",
        "case_id": case_id,
        "files": files,
        "semantic_snapshot_id": digest(semantic_inventory(files)),
        "provenance": provenance,
    }
    atomic_json(manifest, record)
    return record


def validate_snapshot_manifest(
    source: Path, case_id: str, *, provenance: dict | None = None
) -> dict:
    """Validate exact content and pinned preparation identity without modifying a snapshot."""
    from maxvera.snapshots import semantic_inventory, tracked_input_policy

    manifest = source / "snapshot.files.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("snapshot manifest missing or unsafe")
    record = json.loads(manifest.read_text())
    if not isinstance(record, dict) or "schema_version" not in record:
        raise ValueError(
            "legacy snapshot requires independently verified provenance; not overwritten"
        )
    if set(record) != {"schema_version", "case_id", "files", "semantic_snapshot_id", "provenance"}:
        raise ValueError("snapshot manifest fields invalid")
    if record["schema_version"] != "1.0" or record["case_id"] != safe_id(case_id):
        raise ValueError("snapshot manifest identity mismatch")
    files = record["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("snapshot manifest files must be a nonempty mapping")
    for name, content_hash in files.items():
        if (
            not isinstance(name, str)
            or relative_file(name) != name
            or name == "snapshot.files.json"
            or not isinstance(content_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", content_hash)
        ):
            raise ValueError("snapshot manifest file/hash invalid")
    if _snapshot_files(source) != files:
        raise ValueError("snapshot inventory/hash mismatch")
    _validate_provenance(record["provenance"])
    if files.get("build.runtime.json") != record["provenance"]["build_recipe_sha256"]:
        raise ValueError("snapshot build recipe hash mismatch")
    if record["provenance"]["preparation_policy"] in {
        "pinned-git-archive-normalized-v1",
        "pinned-git-archive-normalized-v2",
    } and (
        files.get("archive.materialization.json") != record["provenance"]["materialization_sha256"]
    ):
        raise ValueError("snapshot archive materialization proof mismatch")
    if record["provenance"][
        "preparation_policy"
    ] == "pinned-git-archive-normalized-v2" and not tracked_input_policy(source):
        raise ValueError("snapshot tracked archive input policy mismatch")
    if digest(semantic_inventory(files)) != record["semantic_snapshot_id"]:
        raise ValueError("snapshot semantic identity mismatch")
    if provenance and any(record["provenance"].get(k) != v for k, v in provenance.items()):
        raise ValueError("snapshot provenance differs from current pinned dataset")
    return record


def copy_verified_snapshot(
    source: Path, target: Path, case_id: str, expected_files: dict[str, str], provenance: dict
) -> dict:
    """Copy legacy inputs only against a trusted, independently checked exact inventory.

    Callers must verify the audit artifact checksum before supplying its inventory and
    SHA256 proof. The original source and existing destination are never modified.
    """
    if provenance.get("preparation_policy") != "audited-snapshot-copy-v1":
        raise ValueError("verified copy requires audited-snapshot-copy-v1 provenance")
    expected_files = {k: v for k, v in expected_files.items() if k != "snapshot.files.json"}
    if not expected_files or _snapshot_files(source) != expected_files:
        raise ValueError("legacy snapshot differs from authoritative audited inventory")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError("snapshot exists; refusing to overwrite")
    temporary = Path(tempfile.mkdtemp(prefix=f".{safe_id(case_id)}.preparing-", dir=target.parent))
    try:
        shutil.copytree(
            source,
            temporary,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git", ".gradle", "target", "build", "classes", "snapshot.files.json"
            ),
        )
        if (
            _snapshot_files(temporary) != expected_files
            or _snapshot_files(source) != expected_files
        ):
            raise ValueError("snapshot changed during verified copy")
        recipe = temporary / "build.runtime.json"
        build = json.loads(recipe.read_text())
        # Absolute wrapper/dependency paths must follow the new snapshot, then
        # static extraction can remap them again into its private build copy.
        for attempt in build["attempts"]:
            attempt["command"] = [
                value.replace(str(source.resolve()), str(target.resolve()))
                for value in attempt["command"]
            ]
            attempt["environment"] = {
                key: value.replace(str(source.resolve()), str(target.resolve()))
                for key, value in attempt["environment"].items()
            }
        recipe.write_text(json.dumps(build, sort_keys=True))
        write_snapshot_manifest(temporary, case_id, provenance)
        validate_snapshot_manifest(temporary, case_id)
        os.rename(temporary, target)
        return validate_snapshot_manifest(target, case_id)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _archive_source(source: Path, target: Path, commit: str, patch: Path) -> None:
    """Read tracked pinned bytes, ignoring arbitrary modifications in a fetch workspace."""
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != commit:
        raise ValueError("source revision differs from pinned dataset")
    archive = target.parent / (target.name + ".tar")
    try:
        subprocess.run(
            ["git", "archive", "--format=tar", "--output=" + str(archive), commit],
            cwd=source,
            check=True,
            capture_output=True,
        )
        with tarfile.open(archive) as handle:
            for member in handle.getmembers():
                if (
                    member.name.startswith("/")
                    or ".." in Path(member.name).parts
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError(
                        "source archive contains unsafe path or symlink; audit required"
                    )
            handle.extractall(target)
        if patch.is_file():
            subprocess.run(
                ["git", "apply", str(patch.resolve())], cwd=target, check=True, capture_output=True
            )
        # Match the source inventory policy; generated build outputs are not snapshots.
        for path in sorted(target.rglob("*"), reverse=True):
            if path.is_dir() and path.name in {".git", ".gradle", "target", "build", "classes"}:
                shutil.rmtree(path)
            elif path.is_file() and path.suffix in {".patch", ".diff"}:
                path.unlink()
    finally:
        archive.unlink(missing_ok=True)


def prepare(
    root: Path, config: Path, *, sources: bool = False, selected_ids: list[str] | None = None
) -> dict:
    """Prepare pinned metadata and atomic source snapshots, resuming per case safely."""
    cfg = load_dataset_config(config)
    raw = (
        root
        / "data/raw"
        / ("cwe_bench_java_v1" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_java_extended")
    )
    acquire_dataset(cfg, raw)
    summary = materialize_release(root, raw, cfg, write_splits=cfg.dataset_id != "D_repro_v1")
    if not sources:
        return summary
    import yaml

    from maxvera.preflight import build_recipe_issues
    from src.common.envfile import effective_env
    from src.data.build_projects import _fetch_source, build_command_and_env

    rows = read_csv(
        root
        / "data/processed/manifests"
        / ("cwe_bench_v1.csv" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_extended.csv")
    )
    if selected_ids is not None:
        selected = {safe_id(case_id) for case_id in selected_ids}
        if not selected or len(selected) != len(selected_ids):
            raise ValueError("preparation selection must contain unique nonempty IDs")
        if selected - {r["project_id"] for r in rows}:
            raise ValueError("preparation selection missing from pinned dataset")
        rows = [row for row in rows if row["project_id"] in selected]
    toolchains = yaml.safe_load((root / "configs/toolchains/cwe_bench_java.yaml").read_text())
    machine = effective_env(root / ".env")
    view = root / "data/processed/analysis_input/projects"
    view.mkdir(parents=True, exist_ok=True)
    results = []
    for row in rows:
        case_id = safe_id(row["project_id"])
        target = view / case_id
        patch = raw / "patches" / f"{row['project_slug']}.patch"
        provenance = {
            "dataset_id": cfg.dataset_id,
            "dataset_revision": cfg.revision,
            "source_commit": row["buggy_commit_id"],
            "build_patch_sha256": sha256_file(patch) if patch.is_file() else None,
            "preparation_policy": "pinned-git-archive-v1",
        }
        temporary = None
        try:
            if target.exists() or target.is_symlink():
                validate_snapshot_manifest(target, case_id, provenance=provenance)
                recipe = json.loads((target / "build.runtime.json").read_text())
                if build_recipe_issues(target, recipe):
                    raise ValueError(
                        "existing snapshot has no valid available build recipe; preserved"
                    )
                results.append({"case_id": case_id, "status": "REUSED"})
                continue
            ok, reason, _ = _fetch_source(
                row,
                raw,
                root / "data/interim/project_sources",
                root / "data/interim/dataset_logs",
                7200,
            )
            if not ok:
                raise RuntimeError(reason)
            source = root / "data/interim/project_sources" / case_id
            temporary = Path(tempfile.mkdtemp(prefix=f".{case_id}.preparing-", dir=view))
            _archive_source(source, temporary, row["buggy_commit_id"], patch)
            attempts = []
            for option in toolchains["build_attempts"]:
                try:
                    args, env = build_command_and_env(root, temporary, option, toolchains, machine)
                    option_record = {
                        "command": args,
                        "environment": {k: v for k, v in env.items() if k in {"JAVA_HOME", "PATH"}},
                    }
                    if build_recipe_issues(temporary, {"attempts": [option_record]}):
                        continue
                    attempts.append(
                        {
                            "command": [arg.replace(str(temporary), str(target)) for arg in args],
                            "environment": {
                                k: v.replace(str(temporary), str(target))
                                for k, v in option_record["environment"].items()
                            },
                        }
                    )
                except ValueError:
                    continue
            if not attempts:
                raise ValueError(
                    "no available trusted build attempts; install configured toolchains"
                )
            (temporary / "build.runtime.json").write_text(
                json.dumps({"attempts": attempts}, sort_keys=True)
            )
            write_snapshot_manifest(temporary, case_id, provenance)
            validate_snapshot_manifest(temporary, case_id, provenance=provenance)
            if target.exists() or target.is_symlink():
                raise ValueError("snapshot appeared during preparation; refusing to overwrite")
            os.rename(temporary, target)
            results.append({"case_id": case_id, "status": "PREPARED"})
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            from maxvera.contracts import redact

            results.append(
                {
                    "case_id": case_id,
                    "status": "FAILED",
                    "error": redact(str(error)),
                    "existing_snapshot_preserved": target.exists(),
                }
            )
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary)
    prepared = sum(r["status"] == "PREPARED" for r in results)
    reused = sum(r["status"] == "REUSED" for r in results)
    return {
        **summary,
        "source_preparation": {
            "requested": len(rows),
            "prepared": prepared,
            "reused": reused,
            "failed": len(results) - prepared - reused,
            "ready": prepared + reused == len(rows),
            "cases": results,
        },
    }
