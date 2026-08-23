"""Strict, dependency-light readers for CWE-Bench-Java legacy and IRIS v2."""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from .errors import DatasetFormatError
from .models import BuildInfo, DatasetBundle, FixLocation, ProjectRecord

SUPPORTED_TRACKS = frozenset({"legacy", "v2"})

PROJECT_COLUMNS = frozenset(
    {
        "id",
        "project_slug",
        "cve_id",
        "cwe_id",
        "cwe_name",
        "github_username",
        "github_repository_name",
        "github_tag",
        "github_url",
        "advisory_id",
        "buggy_commit_id",
        "fix_commit_ids",
    }
)
BUILD_COLUMNS = frozenset(
    {
        "project_slug",
        "status",
        "jdk_version",
        "mvn_version",
        "gradle_version",
        "use_gradlew",
    }
)
FIX_COLUMNS = frozenset(
    {
        "project_slug",
        "commit",
        "file",
        "class",
        "class_start",
        "class_end",
        "method",
        "method_start",
        "method_end",
        "signature",
    }
)

_CWE_PATTERN = re.compile(r"^CWE(?:[-_ ]?)(\d+)$", re.IGNORECASE)
_CVE_IN_SLUG = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def normalize_cwe_id(value: str) -> str:
    """Normalize both legacy ``CWE-022`` and v2 ``CWE-22`` to ``CWE-22``."""

    match = _CWE_PATTERN.fullmatch(value.strip())
    if not match:
        raise DatasetFormatError(f"Invalid CWE identifier: {value!r}")
    return f"CWE-{int(match.group(1))}"


def _read_csv(path: Path, required_columns: Iterable[str]) -> list[dict[str, str]]:
    """Read a CSV while tolerating IRIS v2's empty trailing header column."""

    if not path.is_file():
        raise DatasetFormatError(f"Required dataset file does not exist: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            raw_headers = next(reader)
        except StopIteration as exc:
            raise DatasetFormatError(f"CSV is empty: {path}") from exc

        headers = [header.strip() for header in raw_headers]
        nonempty_headers = [header for header in headers if header]
        duplicates = sorted(
            {header for header in nonempty_headers if nonempty_headers.count(header) > 1}
        )
        if duplicates:
            raise DatasetFormatError(f"Duplicate columns in {path}: {duplicates}")
        missing = sorted(set(required_columns) - set(nonempty_headers))
        if missing:
            raise DatasetFormatError(f"Missing columns in {path}: {missing}")

        records: list[dict[str, str]] = []
        for line_number, row in enumerate(reader, start=2):
            if not row or not any(cell.strip() for cell in row):
                continue
            if len(row) > len(headers) and any(cell.strip() for cell in row[len(headers) :]):
                raise DatasetFormatError(f"Unexpected extra values in {path} at line {line_number}")
            padded = row + [""] * max(0, len(headers) - len(row))
            record = {
                header: padded[index].strip() for index, header in enumerate(headers) if header
            }
            records.append(record)
        return records


def read_csv_records(
    path: str | Path, required_columns: Iterable[str] = ()
) -> tuple[Mapping[str, str], ...]:
    """Public strict CSV reader used by compatibility adapters and tests."""

    return tuple(_read_csv(Path(path), required_columns))


def _optional_int(value: str, *, path: Path, field: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise DatasetFormatError(
            f"Expected integer in {path} column {field}, got {value!r}"
        ) from exc


def _resolve_data_directory(root: Path) -> tuple[Path, Path]:
    root = root.resolve()
    if (root / "project_info.csv").is_file():
        return root.parent, root
    if (root / "data" / "project_info.csv").is_file():
        return root, root / "data"
    raise DatasetFormatError(f"Could not find project_info.csv below dataset root: {root}")


def _auxiliary_slug(
    row: Mapping[str, str],
    known_slugs: set[str],
    cve_to_slug: Mapping[str, str],
) -> str | None:
    """Resolve known v2 ``repo__CVE`` versus ``repo_CVE`` schema drift.

    The v2 build and curated-annotation CSVs use a different slug convention
    for some 2025 additions.  CVE is used only inside this trusted preparation
    boundary to perform the join; it never enters a runtime record.
    """

    raw_slug = row.get("project_slug", "")
    if raw_slug in known_slugs:
        return raw_slug
    cve_id = row.get("cve_id", "").upper()
    if not cve_id:
        match = _CVE_IN_SLUG.search(raw_slug)
        cve_id = match.group(0).upper() if match else ""
    return cve_to_slug.get(cve_id)


def load_cwe_bench(dataset_root: str | Path, track: str) -> DatasetBundle:
    """Load either supported upstream CSV layout into typed records.

    Sensitive fields intentionally remain in this preparation-side bundle.  Use
    :func:`openiris.data.runtime_view.materialize_dataset_views` to construct the
    only representation that a zero-hint runtime may consume.
    """

    normalized_track = track.strip().casefold()
    if normalized_track not in SUPPORTED_TRACKS:
        raise DatasetFormatError(
            f"Unsupported dataset track {track!r}; expected one of {sorted(SUPPORTED_TRACKS)}"
        )

    root, data_dir = _resolve_data_directory(Path(dataset_root))
    project_rows = _read_csv(data_dir / "project_info.csv", PROJECT_COLUMNS)
    seen_slugs: set[str] = set()
    for row in project_rows:
        slug = row["project_slug"]
        if not slug:
            raise DatasetFormatError("project_info.csv contains an empty project_slug")
        if slug in seen_slugs:
            raise DatasetFormatError(f"Duplicate project record for {slug!r}")
        seen_slugs.add(slug)

    cve_to_slug: dict[str, str] = {}
    for row in project_rows:
        cve_id = row["cve_id"].upper()
        if cve_id in cve_to_slug:
            raise DatasetFormatError(f"Duplicate CVE record for {cve_id!r}")
        cve_to_slug[cve_id] = row["project_slug"]

    build_rows = _read_csv(data_dir / "build_info.csv", BUILD_COLUMNS)
    builds: dict[str, BuildInfo] = {}
    for row in build_rows:
        resolved_slug = _auxiliary_slug(row, seen_slugs, cve_to_slug)
        if resolved_slug is None:
            # Upstream may carry build rows for a neighboring track.
            continue
        if resolved_slug in builds:
            raise DatasetFormatError(f"Duplicate build record resolving to {resolved_slug!r}")
        builds[resolved_slug] = BuildInfo(
            status=row["status"] or "missing",
            jdk_version=row["jdk_version"],
            maven_version=row["mvn_version"],
            gradle_version=row["gradle_version"],
            use_gradle_wrapper=row["use_gradlew"],
        )

    instances: list[ProjectRecord] = []
    for row in project_rows:
        slug = row["project_slug"]
        fix_commits = tuple(
            commit.strip() for commit in row["fix_commit_ids"].split(";") if commit.strip()
        )
        instances.append(
            ProjectRecord(
                upstream_id=row["id"],
                project_slug=slug,
                cve_id=row["cve_id"],
                cwe_id=normalize_cwe_id(row["cwe_id"]),
                cwe_name=row["cwe_name"],
                repository_owner=row["github_username"],
                repository_name=row["github_repository_name"],
                repository_tag=row["github_tag"],
                repository_url=row["github_url"],
                advisory_id=row["advisory_id"],
                revision=row["buggy_commit_id"],
                fix_commit_ids=fix_commits,
                build=builds.get(slug, BuildInfo()),
            )
        )

    # Stable ordering makes all downstream hashes independent of upstream row order.
    instances.sort(key=lambda item: (item.repository_key, item.project_slug, item.upstream_id))

    fix_locations: defaultdict[str, list[FixLocation]] = defaultdict(list)
    fix_path = data_dir / "fix_info.csv"
    if fix_path.is_file():
        for row in _read_csv(fix_path, FIX_COLUMNS):
            resolved_slug = _auxiliary_slug(row, seen_slugs, cve_to_slug)
            if resolved_slug is None:
                continue  # Some upstream files contain annotations outside a track.
            fix_locations[resolved_slug].append(
                FixLocation(
                    commit=row["commit"],
                    file=row["file"].replace("\\", "/"),
                    class_name=row["class"],
                    class_start=_optional_int(
                        row["class_start"], path=fix_path, field="class_start"
                    ),
                    class_end=_optional_int(row["class_end"], path=fix_path, field="class_end"),
                    method=row["method"],
                    method_start=_optional_int(
                        row["method_start"], path=fix_path, field="method_start"
                    ),
                    method_end=_optional_int(row["method_end"], path=fix_path, field="method_end"),
                    signature=row["signature"],
                )
            )

    annotations: defaultdict[str, list[Mapping[str, str]]] = defaultdict(list)
    raw_annotation_rows = 0
    orphan_annotation_rows = 0
    annotation_path = data_dir / "fix_info_source_sink.csv"
    if annotation_path.is_file():
        for row in _read_csv(annotation_path, {"project_slug"}):
            raw_annotation_rows += 1
            resolved_slug = _auxiliary_slug(row, seen_slugs, cve_to_slug)
            if resolved_slug is not None:
                annotations[resolved_slug].append(dict(row))
            else:
                orphan_annotation_rows += 1

    return DatasetBundle(
        root=root,
        track=normalized_track,
        instances=tuple(instances),
        fix_locations={
            slug: tuple(
                sorted(
                    locations,
                    key=lambda item: (
                        item.file,
                        item.method_start if item.method_start is not None else -1,
                        item.signature,
                    ),
                )
            )
            for slug, locations in fix_locations.items()
        },
        source_sink_annotations={slug: tuple(rows) for slug, rows in sorted(annotations.items())},
        raw_cwe_labels=frozenset(row["cwe_id"].strip().upper() for row in project_rows),
        raw_source_sink_annotation_rows=raw_annotation_rows,
        orphan_source_sink_annotation_rows=orphan_annotation_rows,
    )


# Friendly aliases for callers that use reader-oriented names.
read_cwe_bench = load_cwe_bench
load_dataset = load_cwe_bench
