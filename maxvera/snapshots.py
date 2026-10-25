"""Versioned source inventory policies shared by ingestion and build provenance."""

import json
import re
from pathlib import Path

from maxvera.graph import relative_file
from src.common.provenance import sha256_file

SEMANTIC_CACHE_DIRECTORIES = {
    ".git",
    ".gradle",
    "__pycache__",
    ".m2",
    ".maven-runtime",
    ".maven-cache",
}
PREPARATION_METADATA = {"build.runtime.json", "snapshot.files.json", "archive.materialization.json"}
BINARY_SUFFIXES = {".class", ".jar", ".war", ".ear", ".zip", ".jmod", ".bqrs"}


def tracked_input_policy(source: Path) -> bool:
    """Keep all tracked directories only for the explicit v2 archive input policy.

    Old frozen snapshots retain their original inventory and copy behavior. The
    snapshot manifest separately binds this ledger and the preparation policy.
    """
    ledger = source / "archive.materialization.json"
    if not ledger.exists():
        return False
    if ledger.is_symlink() or not ledger.is_file():
        raise ValueError("unsafe archive materialization ledger")
    value = json.loads(ledger.read_text())
    if not isinstance(value, dict) or value.get("inventory_policy") != "tracked-archive-v2":
        return False
    summaries = {
        "materialized_symlinks",
        "omitted_test_resource_symlinks",
        "omitted_advisory_documents",
        "omitted_policy_files",
    }
    if (
        set(value) != {"schema_version", "inventory_policy"} | summaries
        or value["schema_version"] != "2.0"
    ):
        raise ValueError("tracked archive materialization ledger fields invalid")
    for name in summaries:
        summary = value[name]
        if (
            not isinstance(summary, dict)
            or set(summary) != {"count", "receipt_digest"}
            or type(summary["count"]) is not int
            or summary["count"] < 0
            or not isinstance(summary["receipt_digest"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", summary["receipt_digest"])
        ):
            raise ValueError(
                "tracked archive materialization ledger requires count/digest summaries"
            )
    return True


def semantic_inventory(
    analyzed_files: dict[str, str], input_files: dict[str, str] | None = None
) -> dict[str, str]:
    """Separate source identity from the complete, independently frozen build inventory.

    Original repository inputs remain bound to their final analyzed bytes. Generated
    Java is included, while build timestamps, caches and preparation paths are not.
    The complete analyzed inventory still binds the database and evidence integrity.
    """
    baseline = analyzed_files if input_files is None else input_files
    files = {}
    for file, content_hash in sorted(analyzed_files.items()):
        path = Path(relative_file(file))
        if (
            SEMANTIC_CACHE_DIRECTORIES & set(path.parts)
            or path.as_posix() in PREPARATION_METADATA
            or path.suffix.lower() in BINARY_SUFFIXES
        ):
            continue
        if file in baseline or path.suffix == ".java":
            files[file] = content_hash
    return files


def source_inventory(source: Path, *, include_generated: bool = False) -> dict[str, str]:
    ignored = {".git", ".gradle", "__pycache__"}
    if not include_generated:
        ignored = (
            {".git"} if tracked_input_policy(source) else ignored | {"target", "build", "classes"}
        )
    files = {}
    for p in sorted(source.rglob("*")):
        rel = p.relative_to(source)
        if ignored & set(rel.parts):
            continue
        if p.is_symlink():
            raise ValueError("source snapshot symlink requires audit")
        if p.is_file():
            if include_generated and p.suffix in {".class", ".jar", ".war", ".zip", ".bqrs"}:
                continue
            files[relative_file(rel.as_posix())] = sha256_file(p)
    return files
