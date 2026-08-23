"""Deterministic repository-holdout split manifests."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from ._serialization import atomic_write_text, sha256_canonical
from .errors import DatasetFormatError, DatasetIntegrityError
from .runtime_view import RuntimeInstance, read_runtime_manifest

SPLIT_NAMES = ("train", "dev", "test")
SPLIT_SCHEMA_VERSION = "1.0"


def _normalized_ratios(ratios: Mapping[str, float]) -> dict[str, float]:
    if set(ratios) != set(SPLIT_NAMES):
        raise DatasetFormatError(f"Split ratios must contain exactly {SPLIT_NAMES}")
    values = {name: float(ratios[name]) for name in SPLIT_NAMES}
    if any(value < 0 for value in values.values()) or sum(values.values()) <= 0:
        raise DatasetFormatError("Split ratios must be non-negative and have a positive sum")
    total = sum(values.values())
    return {name: values[name] / total for name in SPLIT_NAMES}


def _largest_remainder_counts(total: int, ratios: Mapping[str, float]) -> dict[str, int]:
    exact = {name: ratios[name] * total for name in SPLIT_NAMES}
    counts = {name: int(exact[name]) for name in SPLIT_NAMES}
    remainder = total - sum(counts.values())
    priority = sorted(
        SPLIT_NAMES,
        key=lambda name: (-(exact[name] - counts[name]), SPLIT_NAMES.index(name)),
    )
    for name in priority[:remainder]:
        counts[name] += 1
    return counts


def _manifest_hash(manifest: Mapping[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("sha256_manifest", None)
    return sha256_canonical(payload)


def create_repository_split(
    instances: Iterable[RuntimeInstance],
    *,
    dataset_snapshot_id: str,
    dataset_manifest_sha256: str,
    seed: int | str = 0,
    ratios: Mapping[str, float] | None = None,
    split_id: str | None = None,
) -> dict[str, Any]:
    """Assign complete repositories to train/dev/test using stable SHA-256 order."""

    normalized = _normalized_ratios(ratios or {"train": 0.70, "dev": 0.15, "test": 0.15})
    materialized = tuple(instances)
    if not materialized:
        raise DatasetFormatError("Cannot create a split for an empty runtime manifest")
    ids = [instance.instance_id for instance in materialized]
    if len(ids) != len(set(ids)):
        raise DatasetFormatError("Cannot split duplicate runtime instance IDs")

    repository_instances: defaultdict[str, list[str]] = defaultdict(list)
    for instance in materialized:
        if instance.snapshot_id != dataset_snapshot_id:
            raise DatasetFormatError(
                f"Runtime instance {instance.instance_id} belongs to a different snapshot"
            )
        repository_instances[instance.repository.key].append(instance.instance_id)

    seed_text = str(seed)
    repositories = sorted(
        repository_instances,
        key=lambda repository: (
            hashlib.sha256(
                f"openiris-repository-split-v1\0{seed_text}\0{repository}".encode()
            ).hexdigest(),
            repository,
        ),
    )
    repository_counts = _largest_remainder_counts(len(repositories), normalized)

    repository_assignments: dict[str, list[str]] = {name: [] for name in SPLIT_NAMES}
    cursor = 0
    for name in SPLIT_NAMES:
        following = cursor + repository_counts[name]
        repository_assignments[name] = sorted(repositories[cursor:following])
        cursor = following

    assignments = {
        name: sorted(
            instance_id
            for repository in repository_assignments[name]
            for instance_id in repository_instances[repository]
        )
        for name in SPLIT_NAMES
    }
    identity_payload = {
        "snapshot": dataset_snapshot_id,
        "seed": seed_text,
        "ratios": normalized,
        "repositories": repository_assignments,
    }
    identifier = split_id or f"repository_holdout_{sha256_canonical(identity_payload)[:12]}"
    manifest: dict[str, Any] = {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "split_id": identifier,
        "strategy": "repository_holdout",
        "seed": seed_text,
        "dataset": {
            "snapshot_id": dataset_snapshot_id,
            "manifest_sha256": dataset_manifest_sha256,
        },
        "ratios": normalized,
        "counts": {
            name: {
                "instances": len(assignments[name]),
                "repositories": len(repository_assignments[name]),
            }
            for name in SPLIT_NAMES
        },
        "assignments": assignments,
        "repository_assignments": repository_assignments,
    }
    validate_repository_split(manifest, materialized)
    manifest["sha256_manifest"] = _manifest_hash(manifest)
    return manifest


def validate_repository_split(
    manifest: Mapping[str, Any], instances: Iterable[RuntimeInstance] | None = None
) -> None:
    """Validate disjointness, coverage, and the repository-holdout invariant."""

    assignments = manifest.get("assignments")
    repositories = manifest.get("repository_assignments")
    if not isinstance(assignments, Mapping) or set(assignments) != set(SPLIT_NAMES):
        raise DatasetFormatError("Invalid split assignments")
    if not isinstance(repositories, Mapping) or set(repositories) != set(SPLIT_NAMES):
        raise DatasetFormatError("Invalid repository assignments")

    id_sets = {name: set(assignments[name]) for name in SPLIT_NAMES}
    repository_sets = {name: set(repositories[name]) for name in SPLIT_NAMES}
    for index, left in enumerate(SPLIT_NAMES):
        for right in SPLIT_NAMES[index + 1 :]:
            if id_sets[left] & id_sets[right]:
                raise DatasetFormatError(f"Instance leakage between {left} and {right}")
            if repository_sets[left] & repository_sets[right]:
                raise DatasetFormatError(f"Repository leakage between {left} and {right}")

    if instances is None:
        return
    materialized = tuple(instances)
    expected_ids = {item.instance_id for item in materialized}
    assigned_ids = set().union(*id_sets.values())
    if expected_ids != assigned_ids:
        raise DatasetFormatError("Split assignments do not exactly cover the runtime manifest")
    repository_to_split = {
        repository: name for name, values in repository_sets.items() for repository in values
    }
    for instance in materialized:
        expected_split = repository_to_split.get(instance.repository.key)
        if expected_split is None or instance.instance_id not in id_sets[expected_split]:
            raise DatasetFormatError(
                f"Repository invariant failed for runtime instance {instance.instance_id}"
            )


def write_split_manifest(path: str | Path, manifest: Mapping[str, Any]) -> Path:
    expected = _manifest_hash(manifest)
    if manifest.get("sha256_manifest") != expected:
        raise DatasetIntegrityError("Refusing to write a split manifest with an invalid hash")
    rendered = yaml.safe_dump(
        dict(manifest),
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=True,
        width=1000,
    )
    output = Path(path)
    atomic_write_text(output, rendered)
    return output


def create_repository_split_from_manifest(
    runtime_manifest: str | Path,
    output_path: str | Path,
    *,
    dataset_snapshot_id: str,
    dataset_manifest_sha256: str,
    seed: int | str = 0,
    ratios: Mapping[str, float] | None = None,
    split_id: str | None = None,
) -> dict[str, Any]:
    instances = read_runtime_manifest(runtime_manifest)
    split = create_repository_split(
        instances,
        dataset_snapshot_id=dataset_snapshot_id,
        dataset_manifest_sha256=dataset_manifest_sha256,
        seed=seed,
        ratios=ratios,
        split_id=split_id,
    )
    write_split_manifest(output_path, split)
    return split


def read_split_manifest(path: str | Path) -> dict[str, Any]:
    loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise DatasetFormatError("Split manifest must be a YAML mapping")
    if loaded.get("sha256_manifest") != _manifest_hash(loaded):
        raise DatasetIntegrityError("Split manifest hash does not match")
    validate_repository_split(loaded)
    return loaded


create_splits = create_repository_split_from_manifest
