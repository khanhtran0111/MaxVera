"""Leakage-resistant runtime dataset manifests.

Only the immutable types and readers in this module should be used by a
zero-hint pipeline.  The trusted upstream CSV bundle is converted here through
an explicit allowlist; CVE/CWE/advisory/fix metadata is written to a physically
separate evaluator-only JSONL file.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._serialization import atomic_write_text, stable_json_line
from .errors import DatasetFormatError, DatasetIntegrityError, LeakageError
from .models import BuildInfo, DatasetBundle, ProjectRecord

RUNTIME_SCHEMA_VERSION = "1.0"
RUNTIME_KEYS = frozenset(
    {"schema_version", "instance_id", "snapshot_id", "track", "repository", "revision", "build"}
)
REPOSITORY_KEYS = frozenset({"host", "owner", "name", "url"})
BUILD_KEYS = frozenset(
    {"status", "jdk_version", "maven_version", "gradle_version", "use_gradle_wrapper"}
)

_FORBIDDEN_KEY_PARTS = frozenset(
    {
        "cve",
        "cwe",
        "advisory",
        "fix",
        "patch",
        "vulnerability",
        "groundtruth",
        "weakness",
    }
)
_FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"\bCVE[-_ ]?\d", re.IGNORECASE),
    re.compile(r"\bCWE[-_ ]?\d", re.IGNORECASE),
    re.compile(r"\bGHSA-[0-9a-z-]+", re.IGNORECASE),
)
_FORBIDDEN_REPOSITORY_COMPONENTS = frozenset(
    {
        "advisory",
        "advisories",
        "fix",
        "fixes",
        "ground_truth",
        "groundtruth",
        "patch",
        "patches",
    }
)
_FORBIDDEN_REPOSITORY_FILENAMES = frozenset(
    {
        "fix_info.csv",
        "fix_info_source_sink.csv",
        "project_info.csv",
        "source_sink_detect.csv",
    }
)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def assert_no_evaluation_leakage(value: Any, path: str = "$") -> None:
    """Recursively reject evaluation labels, identifiers, and metadata keys."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise LeakageError(f"Runtime key at {path} is not a string")
            normalized = _normalized_key(key)
            if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
                raise LeakageError(f"Forbidden runtime field at {path}.{key}")
            assert_no_evaluation_leakage(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            assert_no_evaluation_leakage(item, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in _FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                raise LeakageError(f"Forbidden evaluation identifier at {path}")


def opaque_instance_id(instance: ProjectRecord, snapshot_id: str) -> str:
    """Return a stable non-semantic ID without embedding the upstream slug/CVE."""

    material = "\0".join(
        (
            "openiris-runtime-instance-v1",
            snapshot_id,
            instance.repository_key,
            instance.revision,
            instance.upstream_id,
        )
    ).encode("utf-8")
    return "oi_" + hashlib.sha256(material).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class RuntimeRepository:
    host: str
    owner: str
    name: str
    url: str

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.name}".casefold()

    def to_dict(self) -> dict[str, str]:
        return {"host": self.host, "owner": self.owner, "name": self.name, "url": self.url}


@dataclass(frozen=True, slots=True)
class RuntimeInstance:
    instance_id: str
    snapshot_id: str
    track: str
    repository: RuntimeRepository
    revision: str
    build: BuildInfo

    def to_dict(self) -> dict[str, Any]:
        record = {
            "schema_version": RUNTIME_SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "snapshot_id": self.snapshot_id,
            "track": self.track,
            "repository": self.repository.to_dict(),
            "revision": self.revision,
            "build": self.build.to_runtime_dict(),
        }
        assert_no_evaluation_leakage(record)
        return record

    @classmethod
    def from_dict(cls, record: Mapping[str, Any]) -> RuntimeInstance:
        assert_no_evaluation_leakage(record)
        keys = frozenset(record)
        if keys != RUNTIME_KEYS:
            raise DatasetFormatError(
                f"Runtime record fields must be exactly {sorted(RUNTIME_KEYS)}, got {sorted(keys)}"
            )
        if record["schema_version"] != RUNTIME_SCHEMA_VERSION:
            raise DatasetFormatError(
                f"Unsupported runtime schema version: {record['schema_version']!r}"
            )
        repository = record["repository"]
        build = record["build"]
        if not isinstance(repository, Mapping) or frozenset(repository) != REPOSITORY_KEYS:
            raise DatasetFormatError("Invalid runtime repository object")
        if not isinstance(build, Mapping) or frozenset(build) != BUILD_KEYS:
            raise DatasetFormatError("Invalid runtime build object")
        text_fields = {
            "instance_id": record["instance_id"],
            "snapshot_id": record["snapshot_id"],
            "track": record["track"],
            "revision": record["revision"],
            **{f"repository.{key}": repository[key] for key in REPOSITORY_KEYS},
            **{f"build.{key}": build[key] for key in BUILD_KEYS},
        }
        invalid = [name for name, value in text_fields.items() if not isinstance(value, str)]
        if invalid:
            raise DatasetFormatError(f"Runtime fields must be strings: {sorted(invalid)}")
        if not re.fullmatch(r"oi_[0-9a-f]{32}", record["instance_id"]):
            raise DatasetFormatError("instance_id is not an opaque OpenIRIS identifier")
        return cls(
            instance_id=record["instance_id"],
            snapshot_id=record["snapshot_id"],
            track=record["track"],
            repository=RuntimeRepository(
                host=repository["host"],
                owner=repository["owner"],
                name=repository["name"],
                url=repository["url"],
            ),
            revision=record["revision"],
            build=BuildInfo(
                status=build["status"],
                jdk_version=build["jdk_version"],
                maven_version=build["maven_version"],
                gradle_version=build["gradle_version"],
                use_gradle_wrapper=build["use_gradle_wrapper"],
            ),
        )


@dataclass(frozen=True, slots=True)
class ViewPaths:
    runtime_manifest: Path
    ground_truth: Path


def _is_nested(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _forbidden_repository_path(relative: Path) -> bool:
    lowered_parts = tuple(part.casefold() for part in relative.parts)
    if any(part in _FORBIDDEN_REPOSITORY_COMPONENTS for part in lowered_parts):
        return True
    filename = relative.name.casefold()
    if filename in _FORBIDDEN_REPOSITORY_FILENAMES:
        return True
    return relative.suffix.casefold() in {".patch", ".diff"}


def _repository_files(source: Path) -> tuple[tuple[Path, Path], ...]:
    """Preflight a source tree and return safe ``(source, relative)`` files."""

    files: list[tuple[Path, Path]] = []
    for candidate in source.rglob("*"):
        relative = candidate.relative_to(source)
        if ".git" in relative.parts:
            continue
        if candidate.is_symlink():
            raise LeakageError(f"Runtime repository source contains a symlink: {relative}")
        if _forbidden_repository_path(relative):
            raise LeakageError(
                f"Runtime repository source contains evaluator-only metadata: {relative}"
            )
        if candidate.is_file():
            files.append((candidate, relative))
    return tuple(sorted(files, key=lambda item: item[1].as_posix()))


def _verify_source_revision(source: Path, expected_revision: str) -> None:
    if not expected_revision:
        raise DatasetIntegrityError("Runtime instance has no frozen source revision")
    try:
        actual = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise DatasetIntegrityError(
            f"Cannot verify git revision for runtime repository source: {source}"
        ) from exc
    if actual.casefold() != expected_revision.casefold():
        raise DatasetIntegrityError(
            f"Runtime source revision mismatch: expected {expected_revision}, found {actual}"
        )


def audit_runtime_repository(path: str | Path) -> dict[str, Any]:
    """Audit an already materialized repository for boundary violations."""

    repository = Path(path).resolve()
    if not repository.is_dir():
        raise DatasetFormatError(f"Runtime repository does not exist: {repository}")
    files = _repository_files(repository)
    if any(candidate.name == ".git" for candidate in repository.rglob(".git")):
        raise LeakageError("Runtime repository contains Git metadata")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "files_checked": len(files),
        "checks": {
            "no_git_metadata": True,
            "no_symlinks": True,
            "no_advisory_files": True,
            "no_patch_files": True,
            "no_fix_or_ground_truth_metadata": True,
        },
    }


def materialize_runtime_repository(
    instance: RuntimeInstance,
    source_repository: str | Path,
    runtime_root: str | Path,
    *,
    verify_revision: bool = True,
) -> Path:
    """Copy one fetched checkout into its opaque, sanitized runtime location.

    This operation is intentionally per-instance/on-demand. It never copies
    ``.git`` and aborts before writing if the caller supplies a benchmark root
    containing advisory, patch, fix, or ground-truth artifacts.
    """

    instance.to_dict()
    source = Path(source_repository).resolve()
    root = Path(runtime_root).resolve()
    if not source.is_dir():
        raise DatasetFormatError(f"Fetched repository source is not a directory: {source}")
    if _is_nested(source, root):
        raise LeakageError("Fetched source and runtime root must be separate, non-nested paths")
    destination = root / instance.snapshot_id / instance.instance_id / "repository"
    if destination.exists():
        raise DatasetFormatError(f"Runtime repository destination already exists: {destination}")
    if verify_revision:
        _verify_source_revision(source, instance.revision)

    # Complete preflight before creating the destination tree.
    files = _repository_files(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".repository.tmp-", dir=str(destination.parent)))
    try:
        for source_file, relative in files:
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, target)
            shutil.copymode(source_file, target)
        audit_runtime_repository(temporary)
        # ``os.replace`` maps to a replace-existing operation on Windows and
        # can reject a non-empty directory even when the destination is absent.
        # The destination was checked above and is unique per immutable
        # instance, so an ordinary atomic rename is the portable operation.
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def runtime_instance(instance: ProjectRecord, snapshot_id: str, track: str) -> RuntimeInstance:
    runtime = RuntimeInstance(
        instance_id=opaque_instance_id(instance, snapshot_id),
        snapshot_id=snapshot_id,
        track=track,
        repository=RuntimeRepository(
            host="github.com",
            owner=instance.repository_owner,
            name=instance.repository_name,
            url=instance.repository_url,
        ),
        revision=instance.revision,
        build=instance.build,
    )
    # Execute the guard at construction time, before anything touches disk.
    runtime.to_dict()
    return runtime


def build_runtime_instances(bundle: DatasetBundle, snapshot_id: str) -> tuple[RuntimeInstance, ...]:
    instances = tuple(
        sorted(
            (runtime_instance(item, snapshot_id, bundle.track) for item in bundle.instances),
            key=lambda item: item.instance_id,
        )
    )
    ids = [item.instance_id for item in instances]
    if len(ids) != len(set(ids)):
        raise DatasetFormatError("Opaque instance ID collision")
    return instances


def _separate_roots(runtime_root: Path, ground_truth_root: Path) -> tuple[Path, Path]:
    runtime = runtime_root.resolve()
    ground_truth = ground_truth_root.resolve()
    if _is_nested(runtime, ground_truth):
        raise LeakageError(
            "Runtime and ground-truth roots must be physically separate, non-nested directories"
        )
    return runtime, ground_truth


def _ground_truth_record(
    bundle: DatasetBundle, instance: ProjectRecord, instance_id: str
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "instance_id": instance_id,
        "upstream_id": instance.upstream_id,
        "project_slug": instance.project_slug,
        "cve_id": instance.cve_id,
        "cwe_id": instance.cwe_id,
        "cwe_name": instance.cwe_name,
        "advisory_id": instance.advisory_id,
        "repository_tag": instance.repository_tag,
        "buggy_commit_id": instance.revision,
        "fix_commit_ids": list(instance.fix_commit_ids),
        "fix_locations": [
            location.to_dict() for location in bundle.fix_locations.get(instance.project_slug, ())
        ],
        "manual_source_sink_annotations": [
            dict(row) for row in bundle.source_sink_annotations.get(instance.project_slug, ())
        ],
    }


def materialize_dataset_views(
    bundle: DatasetBundle,
    snapshot_id: str,
    runtime_root: str | Path,
    ground_truth_root: str | Path,
) -> ViewPaths:
    """Write sanitized runtime and evaluator-only records into separate roots."""

    if not snapshot_id or any(character in snapshot_id for character in ("/", "\\", "..")):
        raise DatasetFormatError(f"Unsafe snapshot_id: {snapshot_id!r}")
    runtime_base, truth_base = _separate_roots(Path(runtime_root), Path(ground_truth_root))
    runtime_path = runtime_base / snapshot_id / "manifest.jsonl"
    truth_path = truth_base / snapshot_id / "ground_truth.jsonl"

    runtime_instances = build_runtime_instances(bundle, snapshot_id)
    by_id = {item.instance_id: item for item in runtime_instances}
    runtime_content = "".join(stable_json_line(item.to_dict()) for item in runtime_instances)
    truth_content = "".join(
        stable_json_line(
            _ground_truth_record(
                bundle,
                item,
                opaque_instance_id(item, snapshot_id),
            )
        )
        for item in bundle.instances
    )

    # Validate the complete runtime payload again before either artifact is written.
    for line in runtime_content.splitlines():
        parsed = json.loads(line)
        loaded = RuntimeInstance.from_dict(parsed)
        if loaded.instance_id not in by_id:
            raise DatasetFormatError("Runtime manifest validation changed an instance ID")

    atomic_write_text(runtime_path, runtime_content)
    atomic_write_text(truth_path, truth_content)
    return ViewPaths(runtime_manifest=runtime_path, ground_truth=truth_path)


def read_runtime_manifest(path: str | Path) -> tuple[RuntimeInstance, ...]:
    manifest = Path(path)
    if not manifest.is_file():
        raise DatasetFormatError(f"Runtime manifest does not exist: {manifest}")
    instances: list[RuntimeInstance] = []
    with manifest.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetFormatError(
                    f"Invalid JSON in runtime manifest at line {line_number}"
                ) from exc
            if not isinstance(record, Mapping):
                raise DatasetFormatError(f"Runtime manifest line {line_number} is not an object")
            instances.append(RuntimeInstance.from_dict(record))
    ids = [item.instance_id for item in instances]
    if len(ids) != len(set(ids)):
        raise DatasetFormatError("Runtime manifest contains duplicate instance IDs")
    return tuple(instances)


def audit_runtime_manifest(path: str | Path) -> dict[str, Any]:
    """Return a machine-readable leakage audit, raising on the first violation."""

    instances = read_runtime_manifest(path)
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "records_checked": len(instances),
        "checks": {
            "opaque_instance_ids": True,
            "field_allowlist": True,
            "no_cve_identifiers": True,
            "no_cwe_labels": True,
            "no_advisory_metadata": True,
            "no_fix_or_patch_metadata": True,
        },
    }


# Backward-friendly concise aliases.
create_runtime_views = materialize_dataset_views
load_runtime_manifest = read_runtime_manifest
materialize_repository_source = materialize_runtime_repository
