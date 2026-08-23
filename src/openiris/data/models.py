"""Typed records used while preparing CWE-Bench-Java snapshots.

This module is preparation-side code.  Runtime consumers must use
``openiris.data.runtime_view`` instead of importing :class:`ProjectRecord`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class BuildInfo:
    status: str = "missing"
    jdk_version: str = ""
    maven_version: str = ""
    gradle_version: str = ""
    use_gradle_wrapper: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status.strip().casefold().startswith("success")

    def to_runtime_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "jdk_version": self.jdk_version,
            "maven_version": self.maven_version,
            "gradle_version": self.gradle_version,
            "use_gradle_wrapper": self.use_gradle_wrapper,
        }


@dataclass(frozen=True, slots=True)
class FixLocation:
    commit: str
    file: str
    class_name: str
    class_start: int | None
    class_end: int | None
    method: str
    method_start: int | None
    method_end: int | None
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "file": self.file,
            "class": self.class_name,
            "class_start": self.class_start,
            "class_end": self.class_end,
            "method": self.method,
            "method_start": self.method_start,
            "method_end": self.method_end,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class ProjectRecord:
    """One trusted preparation/evaluation record from ``project_info.csv``."""

    upstream_id: str
    project_slug: str
    cve_id: str
    cwe_id: str
    cwe_name: str
    repository_owner: str
    repository_name: str
    repository_tag: str
    repository_url: str
    advisory_id: str
    revision: str
    fix_commit_ids: tuple[str, ...]
    build: BuildInfo = field(default_factory=BuildInfo)

    @property
    def repository_key(self) -> str:
        """Canonical grouping key for GitHub repository holdout splits."""

        return f"{self.repository_owner}/{self.repository_name}".casefold()


@dataclass(frozen=True, slots=True)
class DatasetBundle:
    """Loaded trusted dataset and evaluation-only annotations."""

    root: Path
    track: str
    instances: tuple[ProjectRecord, ...]
    fix_locations: Mapping[str, tuple[FixLocation, ...]]
    source_sink_annotations: Mapping[str, tuple[Mapping[str, str], ...]]
    raw_cwe_labels: frozenset[str] = field(default_factory=frozenset)
    raw_source_sink_annotation_rows: int = 0
    orphan_source_sink_annotation_rows: int = 0

    @property
    def repositories(self) -> frozenset[str]:
        return frozenset(instance.repository_key for instance in self.instances)

    @property
    def cwes(self) -> frozenset[str]:
        return frozenset(instance.cwe_id for instance in self.instances)

    @property
    def effective_raw_cwe_labels(self) -> frozenset[str]:
        """Raw upstream labels, or normalized labels for synthetic bundles."""

        return self.raw_cwe_labels or self.cwes

    def instance_by_slug(self) -> dict[str, ProjectRecord]:
        return {instance.project_slug: instance for instance in self.instances}
