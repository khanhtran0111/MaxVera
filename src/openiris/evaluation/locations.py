"""Class and function location maps used for IRIS method-level overlap."""

from __future__ import annotations

import csv
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

from openiris.evaluation.paths import normalize_uri


class LocationMapError(ValueError):
    """Raised when a CodeQL declaration-location CSV is malformed."""


@dataclass(frozen=True, slots=True)
class DeclarationLocation:
    name: str
    file: str
    start_line: int
    end_line: int

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


@dataclass(frozen=True, slots=True)
class LocationIndex:
    """File-indexed declarations preserving the input row order."""

    by_file: Mapping[str, tuple[DeclarationLocation, ...]]

    @classmethod
    def from_records(
        cls,
        records: object,
        *,
        repository_root: str | PathLike[str] | None = None,
    ) -> LocationIndex:
        grouped: defaultdict[str, list[DeclarationLocation]] = defaultdict(list)
        for row in _iter_records(records):
            missing = {"name", "file", "start_line", "end_line"}.difference(row)
            if missing:
                columns = ", ".join(sorted(missing))
                raise LocationMapError(f"location row is missing columns: {columns}")
            try:
                start_line = int(str(row["start_line"]))
                end_line = int(str(row["end_line"]))
            except (TypeError, ValueError) as error:
                raise LocationMapError("start_line and end_line must be integers") from error
            file = normalize_uri(str(row["file"]), repository_root)
            grouped[file].append(
                DeclarationLocation(
                    name=str(row["name"]),
                    file=file,
                    start_line=start_line,
                    end_line=end_line,
                )
            )
        return cls({file: tuple(locations) for file, locations in grouped.items()})

    @classmethod
    def from_csv(
        cls,
        path: str | PathLike[str],
        *,
        repository_root: str | PathLike[str] | None = None,
    ) -> LocationIndex:
        return cls.from_records(path, repository_root=repository_root)

    def closest_enclosing(self, file: str, line: int) -> DeclarationLocation | None:
        """Match IRIS's descending-start-line enclosing declaration lookup."""

        best: DeclarationLocation | None = None
        for declaration in self.by_file.get(file, ()):
            if declaration.contains(line) and (
                best is None or declaration.start_line > best.start_line
            ):
                best = declaration
        return best


def _iter_records(records: object) -> Iterator[Mapping[str, object]]:
    if isinstance(records, LocationIndex):
        for locations in records.by_file.values():
            for location in locations:
                yield {
                    "name": location.name,
                    "file": location.file,
                    "start_line": location.start_line,
                    "end_line": location.end_line,
                }
        return

    if isinstance(records, (str, PathLike)):
        with Path(records).open("r", encoding="utf-8-sig", newline="") as handle:
            yield from csv.DictReader(handle)
        return

    if isinstance(records, Mapping):
        yield records
        return

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
            raise LocationMapError("iterrows() yielded a non-mapping row")
        return

    if isinstance(records, Iterable):
        for row in records:
            if not isinstance(row, Mapping):
                raise LocationMapError("location map must contain mapping rows")
            yield row
        return

    raise LocationMapError("location map must be a CSV path or iterable of mapping rows")
