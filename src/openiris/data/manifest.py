"""Deterministic dataset snapshot manifests and integrity verification."""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from ._serialization import atomic_write_text, sha256_canonical
from .cwe_bench import normalize_cwe_id
from .errors import DatasetFormatError, DatasetIntegrityError
from .models import DatasetBundle

MANIFEST_SCHEMA_VERSION = "1.0"
_IGNORED_DIRECTORIES = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache"})
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def _git_output(root: Path, *arguments: str) -> str | None:
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    output = process.stdout.strip()
    return output or None


def resolve_git_commit(root: str | Path) -> str | None:
    value = _git_output(Path(root), "rev-parse", "HEAD")
    return value.lower() if value and _COMMIT_PATTERN.fullmatch(value) else None


def resolve_source_url(root: str | Path) -> str | None:
    return _git_output(Path(root), "config", "--get", "remote.origin.url")


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def collect_file_hashes(
    source_root: str | Path,
    *,
    exclude_paths: Iterable[str | Path] = (),
) -> dict[str, dict[str, Any]]:
    """Hash all snapshot files except VCS/tool caches, sorted by POSIX path."""

    root = Path(source_root).resolve()
    if not root.is_dir():
        raise DatasetFormatError(f"Snapshot source root is not a directory: {root}")
    excluded = {Path(path).resolve() for path in exclude_paths}
    files: list[Path] = []
    for candidate in root.rglob("*"):
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        if any(part in _IGNORED_DIRECTORIES for part in relative.parts):
            continue
        if candidate.resolve() in excluded:
            continue
        if candidate.is_file():
            files.append(candidate)

    result: dict[str, dict[str, Any]] = {}
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative_path = path.relative_to(root).as_posix()
        result[relative_path] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    return result


def aggregate_file_hash(file_hashes: Mapping[str, Mapping[str, Any]]) -> str:
    """Hash the canonical path/size/content-hash inventory."""

    normalized = {
        path: {
            "sha256": metadata["sha256"],
            "size_bytes": int(metadata["size_bytes"]),
        }
        for path, metadata in sorted(file_hashes.items())
    }
    return sha256_canonical(normalized)


def manifest_content_hash(manifest: Mapping[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("sha256_manifest", None)
    return sha256_canonical(payload)


def build_snapshot_manifest(
    bundle: DatasetBundle,
    *,
    snapshot_id: str | None = None,
    source_url: str | None = None,
    git_commit: str | None = None,
    downloaded_at: str | None = None,
    exclude_paths: Iterable[str | Path] = (),
) -> dict[str, Any]:
    """Build a deterministic manifest in memory.

    ``downloaded_at`` is deliberately never filled with the current clock.  Pass
    the acquisition timestamp from the fetch step when known; otherwise it is
    recorded as ``null`` so repeated freezes remain byte-for-byte deterministic.
    """

    commit = (git_commit or resolve_git_commit(bundle.root) or "").lower()
    if not _COMMIT_PATTERN.fullmatch(commit):
        raise DatasetFormatError(
            "A full 40-character git_commit is required to freeze a dataset snapshot"
        )
    resolved_source_url = source_url or resolve_source_url(bundle.root)
    if not resolved_source_url:
        raise DatasetFormatError("source_url is required when the dataset has no git remote")
    identifier = snapshot_id or f"cwe_bench_java_{bundle.track}_{commit[:12]}"
    if not identifier or any(part in identifier for part in ("/", "\\", "..")):
        raise DatasetFormatError(f"Unsafe snapshot_id: {identifier!r}")

    file_hashes = collect_file_hashes(bundle.root, exclude_paths=exclude_paths)
    statuses = [instance.build for instance in bundle.instances]
    successful = sum(build.succeeded for build in statuses)
    missing = sum(build.status == "missing" for build in statuses)
    aliases: defaultdict[str, list[str]] = defaultdict(list)
    for raw_label in sorted(bundle.effective_raw_cwe_labels):
        aliases[normalize_cwe_id(raw_label)].append(raw_label)
    collisions = {
        normalized: raw_labels
        for normalized, raw_labels in sorted(aliases.items())
        if len(raw_labels) > 1
    }
    payload: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "dataset_name": "cwe_bench_java",
        "snapshot_id": identifier,
        "track": bundle.track,
        "source_url": resolved_source_url,
        "git_commit": commit,
        "downloaded_at": downloaded_at,
        "num_instances": len(bundle.instances),
        "num_unique_repositories": len(bundle.repositories),
        "num_raw_cwe_labels": len(bundle.effective_raw_cwe_labels),
        "num_cwes": len(bundle.cwes),
        "cwe_normalization": {
            "rule": "strip zero-padding from numeric CWE identifier",
            "alias_collisions": collisions,
        },
        "num_upstream_declared_build_success": successful,
        "num_upstream_declared_build_failure": len(statuses) - successful - missing,
        "num_upstream_build_status_missing": missing,
        "num_fix_location_rows": sum(len(rows) for rows in bundle.fix_locations.values()),
        "num_raw_curated_source_sink_rows": bundle.raw_source_sink_annotation_rows,
        "num_curated_source_sink_instances_matched": len(bundle.source_sink_annotations),
        "num_orphan_curated_source_sink_rows": bundle.orphan_source_sink_annotation_rows,
        "file_hashes": file_hashes,
        "sha256_files": aggregate_file_hash(file_hashes),
        "hash_contract": "sha256(canonical-json(manifest-without-sha256_manifest))",
    }
    payload["sha256_manifest"] = manifest_content_hash(payload)
    return payload


def write_snapshot_manifest(path: str | Path, manifest: Mapping[str, Any]) -> Path:
    output = Path(path)
    expected = manifest_content_hash(manifest)
    if manifest.get("sha256_manifest") != expected:
        raise DatasetIntegrityError("Refusing to write a manifest with an invalid content hash")
    rendered = yaml.safe_dump(
        dict(manifest),
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=True,
        width=1000,
    )
    atomic_write_text(output, rendered)
    return output


def freeze_snapshot(
    bundle: DatasetBundle,
    output_path: str | Path,
    **manifest_options: Any,
) -> dict[str, Any]:
    """Build and atomically write one deterministic snapshot manifest."""

    output = Path(output_path)
    caller_excludes = tuple(manifest_options.pop("exclude_paths", ()))
    manifest = build_snapshot_manifest(
        bundle,
        exclude_paths=(*caller_excludes, output),
        **manifest_options,
    )
    write_snapshot_manifest(output, manifest)
    return manifest


def read_snapshot_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    if not manifest_path.is_file():
        raise DatasetFormatError(f"Snapshot manifest does not exist: {manifest_path}")
    loaded = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise DatasetFormatError("Snapshot manifest must be a YAML mapping")
    return loaded


def verify_snapshot_manifest(
    manifest: Mapping[str, Any] | str | Path,
    source_root: str | Path,
    *,
    exclude_paths: Iterable[str | Path] = (),
) -> None:
    """Raise :class:`DatasetIntegrityError` if content or files have drifted."""

    loaded = (
        read_snapshot_manifest(manifest) if isinstance(manifest, (str, Path)) else dict(manifest)
    )
    if loaded.get("sha256_manifest") != manifest_content_hash(loaded):
        raise DatasetIntegrityError("Dataset manifest content hash does not match")
    recorded_files = loaded.get("file_hashes")
    if not isinstance(recorded_files, Mapping):
        raise DatasetIntegrityError("Dataset manifest is missing file_hashes")
    exclusions = list(exclude_paths)
    if isinstance(manifest, (str, Path)):
        exclusions.append(manifest)
    current_files = collect_file_hashes(source_root, exclude_paths=exclusions)
    if dict(recorded_files) != current_files:
        recorded_names = set(recorded_files)
        current_names = set(current_files)
        added = sorted(current_names - recorded_names)
        removed = sorted(recorded_names - current_names)
        changed = sorted(
            name
            for name in recorded_names & current_names
            if recorded_files[name] != current_files[name]
        )
        raise DatasetIntegrityError(
            f"Snapshot file inventory drifted; added={added}, removed={removed}, changed={changed}"
        )
    if loaded.get("sha256_files") != aggregate_file_hash(current_files):
        raise DatasetIntegrityError("Aggregate snapshot file hash does not match")
