"""Evaluator-only CWE-Bench-Java ground-truth loader.

Keeping this loader under :mod:`openiris.evaluation` is a deliberate leakage
boundary.  Runtime views and analysis pipelines must never import this module.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

from openiris.evaluation.paths import normalize_uri


class GroundTruthError(ValueError):
    """Raised when evaluator-only ground truth is malformed."""


@dataclass(frozen=True, slots=True)
class FixedMethod:
    """A file/class/method tuple changed by a vulnerability fix."""

    file: str
    class_name: str
    method_name: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.file, self.class_name, self.method_name)

    @property
    def iris_key(self) -> str:
        """Return the colon-delimited key used by IRIS v1."""

        return f"{self.file}:{self.class_name}:{self.method_name}"


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Fixed methods visible only to evaluation code."""

    methods: tuple[FixedMethod, ...]

    @classmethod
    def from_records(
        cls,
        records: object,
        *,
        repository_root: str | PathLike[str] | None = None,
        project_slug: str | None = None,
        cve_id: str | None = None,
    ) -> GroundTruth:
        methods: list[FixedMethod] = []
        for row in _iter_records(records):
            if not _record_matches(row, project_slug=project_slug, cve_id=cve_id):
                continue
            _require_columns(row, {"file", "class", "method"})
            methods.append(
                FixedMethod(
                    file=normalize_uri(str(row["file"]), repository_root),
                    class_name=str(row["class"]),
                    method_name=str(row["method"]),
                )
            )
        return cls(tuple(methods))

    @property
    def production_methods(self) -> tuple[FixedMethod, ...]:
        """Methods considered by IRIS v1 (test-source fixes are excluded)."""

        return tuple(method for method in self.methods if "src/test" not in method.file)

    @property
    def fixed_files(self) -> frozenset[str]:
        return frozenset(method.file for method in self.production_methods)

    @property
    def fixed_method_keys(self) -> frozenset[tuple[str, str, str]]:
        return frozenset(method.key for method in self.production_methods)


def _require_columns(row: Mapping[str, object], required: set[str]) -> None:
    missing = sorted(required.difference(row))
    if missing:
        raise GroundTruthError(f"ground-truth row is missing columns: {', '.join(missing)}")


def _record_matches(
    row: Mapping[str, object],
    *,
    project_slug: str | None,
    cve_id: str | None,
) -> bool:
    if project_slug is not None:
        row_project = row.get("project_slug", row.get("db_name"))
        if row_project is None:
            raise GroundTruthError(
                "project filtering requires a 'project_slug' or 'db_name' column"
            )
        if str(row_project) != project_slug:
            return False
    if cve_id is not None:
        if "cve_id" not in row:
            raise GroundTruthError("CVE filtering requires a 'cve_id' column")
        if str(row["cve_id"]) != cve_id:
            return False
    return True


def _iter_records(records: object) -> Iterator[Mapping[str, object]]:
    if isinstance(records, (str, PathLike)):
        path = Path(records)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from csv.DictReader(handle)
        return

    if isinstance(records, Mapping):
        yield records
        return

    # Compatibility with the pandas DataFrame passed to IRIS v1.  Pandas is
    # intentionally not a dependency of the evaluator.
    iterrows = getattr(records, "iterrows", None)
    if callable(iterrows):
        for _, row in iterrows():
            if hasattr(row, "to_dict"):
                converted: Any = row.to_dict()
                if isinstance(converted, Mapping):
                    yield converted
                    continue
            if isinstance(row, Mapping):
                yield row
                continue
            raise GroundTruthError("iterrows() yielded a non-mapping row")
        return

    if isinstance(records, Iterable):
        for row in records:
            if not isinstance(row, Mapping):
                raise GroundTruthError("ground truth must contain mapping rows")
            yield row
        return

    raise GroundTruthError("ground truth must be a CSV path or iterable of mapping rows")


def load_ground_truth(
    path: str | PathLike[str],
    *,
    project_slug: str | None = None,
    cve_id: str | None = None,
    repository_root: str | PathLike[str] | None = None,
) -> GroundTruth:
    """Load and optionally select one project/CVE from ``fix_info.csv``."""

    return GroundTruth.from_records(
        path,
        repository_root=repository_root,
        project_slug=project_slug,
        cve_id=cve_id,
    )


load_ground_truth_csv = load_ground_truth
