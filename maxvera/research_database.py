"""Frozen critical CodeQL relation inventory, independent of query bookkeeping."""

from __future__ import annotations

import json
import os
from pathlib import Path

from maxvera.contracts import digest, safe_id
from maxvera.orchestration import Context, StageFailure
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_json

MUTABLE_DIRECTORIES = {"cache", "pools", "log"}


def _no_symlink_parents(path: Path) -> None:
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise StageFailure("DATABASE_INTEGRITY_FAILED", "research database path contains symlink")


def database_inventory(database: Path) -> dict[str, str]:
    """Stream file hashes; compare exact critical files, including newly added ones."""
    database = database.absolute()
    _no_symlink_parents(database)
    files = {}

    def scan(path):
        _no_symlink_parents(path)
        if path.is_file():
            files[path.relative_to(database).as_posix()] = sha256_file(path)
        elif path.is_dir():
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise StageFailure(
                            "DATABASE_INTEGRITY_FAILED", "research database inventory symlink"
                        )
                    if entry.name in MUTABLE_DIRECTORIES and entry.is_dir():
                        continue
                    scan(Path(entry.path))
        else:
            raise StageFailure(
                "DATABASE_INTEGRITY_FAILED", "research database missing/non-regular critical entry"
            )

    try:
        for name in ("codeql-database.yml", "src.zip", "db-java"):
            scan(database / name)
        if not any(rel.startswith("db-java/") for rel in files):
            raise StageFailure("DATABASE_INTEGRITY_FAILED", "research database relations missing")
    except OSError as error:
        raise StageFailure(
            "DATABASE_INTEGRITY_FAILED", "research database critical inventory unreadable"
        ) from error
    return dict(sorted(files.items()))


def freeze_database(ctx: Context, snapshot_id: str) -> dict:
    """Persist a source-bound DB identity inside the hashed static stage checkpoint."""
    case_id = safe_id(ctx.case["case_id"])
    body = {
        "schema_version": "1.0",
        "case_id": case_id,
        "analyzed_snapshot_id": snapshot_id,
        "database_dir": "databases/" + case_id,
        "excluded_mutable_directories": sorted(MUTABLE_DIRECTORIES),
        "files": database_inventory(ctx.run_dir / "databases" / case_id),
    }
    identity = {**body, "database_identity_id": digest(body)}
    path = ctx.stage_dir / "db_identity.json"
    atomic_json(path, identity)
    return {
        "database_identity_file": "db_identity.json",
        "database_identity_sha256": sha256_file(path),
        "database_identity_id": identity["database_identity_id"],
    }


def validate_database(ctx: Context, checkpoint: dict | None = None) -> dict:
    """Fail closed before checkpoint reuse or querying a changed research database."""
    data = checkpoint.get("result", {}) if checkpoint else ctx.output("static_extract")
    case_id = safe_id(ctx.case["case_id"])
    manifest = ctx.run_dir / "stages" / case_id / "static_extract/db_identity.json"
    try:
        _no_symlink_parents(manifest)
        if (
            data.get("database_identity_file") != "db_identity.json"
            or not manifest.is_file()
            or sha256_file(manifest) != data.get("database_identity_sha256")
        ):
            raise ValueError("missing/changed database identity manifest")
        identity = json.loads(manifest.read_text())
        if not isinstance(identity, dict):
            raise ValueError("database identity must be an object")
        body = {k: v for k, v in identity.items() if k != "database_identity_id"}
        if (
            identity.get("database_identity_id") != digest(body)
            or identity.get("database_identity_id") != data.get("database_identity_id")
            or identity.get("case_id") != case_id
            or identity.get("analyzed_snapshot_id") != data.get("analyzed_snapshot_id")
            or identity.get("database_dir") != "databases/" + case_id
            or identity.get("schema_version") != "1.0"
            or identity.get("excluded_mutable_directories") != sorted(MUTABLE_DIRECTORIES)
            or identity.get("files") != database_inventory(ctx.run_dir / "databases" / case_id)
        ):
            raise ValueError("database critical inventory or source identity changed")
    except (OSError, ValueError, TypeError) as error:
        raise StageFailure(
            "DATABASE_INTEGRITY_FAILED", "research database identity/integrity mismatch"
        ) from error
    return identity
