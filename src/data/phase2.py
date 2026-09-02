"""Acquire and materialize CWE-Bench data without exposing evaluator labels."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeAlias, cast

import yaml

from src.common.provenance import sha256_file, utc_now, write_checksums

CsvRow: TypeAlias = dict[str, str]

CANONICAL_COLUMNS: Final = (
    "dataset_id",
    "upstream_revision",
    "row_id",
    "project_id",
    "project_slug",
    "cve_id",
    "ground_truth_cwe",
    "cwe_name",
    "github_username",
    "github_repository_name",
    "github_tag",
    "github_url",
    "advisory_id",
    "buggy_commit_id",
    "fix_commit_ids",
    "upstream_build_status",
    "jdk_version",
    "maven_version",
    "gradle_version",
    "use_gradlew",
    "fix_location_count",
    "advisory_sha256",
)

ANALYSIS_COLUMNS: Final = (
    "project_id",
    "source_dir",
    "source_required",
    "jdk_version",
    "maven_version",
    "gradle_version",
    "use_gradlew",
)

FORBIDDEN_ANALYSIS_FIELDS: Final = frozenset(
    {
        "cve_id",
        "ground_truth_cwe",
        "cwe_id",
        "cwe_name",
        "advisory_id",
        "advisory_text",
        "patch_commit",
        "fix_commit",
        "fix_commit_ids",
        "fixed_method",
        "fixed_line",
        "vulnerable_description",
        "project_slug",
        "github_username",
        "github_repository_name",
        "github_url",
        "buggy_commit_id",
    }
)


@dataclass(frozen=True)
class DatasetConfig:
    dataset_id: str
    upstream_url: str
    revision: str
    expected_cves: int | None
    split_seed: int
    development_ratio: float


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a mapping in {path}")
    return cast(dict[str, Any], value)


def load_dataset_config(path: Path) -> DatasetConfig:
    """Load only the fields Phase 2 is allowed to resolve."""
    raw = _load_yaml(path)
    ratios = raw.get("split_ratios", {})
    if ratios is None:
        ratios = {}
    if not isinstance(ratios, Mapping):
        raise ValueError("split_ratios must be a mapping")
    development_ratio = float(ratios.get("development", 0.8))
    test_ratio = float(ratios.get("test_locked", 1.0 - development_ratio))
    if not 0.0 < development_ratio < 1.0 or abs(development_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("development/test_locked split ratios must be positive and sum to 1")
    expected = raw.get("expected_cves")
    return DatasetConfig(
        dataset_id=str(raw["dataset_id"]),
        upstream_url=str(raw["upstream_url"]),
        revision=str(raw["revision"]),
        expected_cves=int(expected) if expected is not None else None,
        split_seed=int(raw.get("split_seed", 1234)),
        development_ratio=development_ratio,
    )


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 3600) -> str:
    process = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip() or "no diagnostic"
        raise RuntimeError(f"command failed ({process.returncode}): {command[0]}: {detail}")
    return process.stdout.strip()


def validate_checkout(path: Path, config: DatasetConfig) -> None:
    """Reject a checkout that is not exactly the frozen upstream revision."""
    if not (path / ".git").is_dir():
        raise ValueError(f"not a Git checkout: {path}")
    head = _run(["git", "rev-parse", "HEAD"], cwd=path)
    if head != config.revision:
        raise ValueError(f"checkout revision mismatch: expected {config.revision}, found {head}")
    origin = _run(["git", "remote", "get-url", "origin"], cwd=path)
    normalized = origin.removesuffix(".git").rstrip("/")
    expected = config.upstream_url.removesuffix(".git").rstrip("/")
    if normalized != expected:
        raise ValueError(f"checkout origin mismatch: expected {expected}, found {normalized}")
    dirty = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=path)
    if dirty:
        raise ValueError(f"raw checkout is not immutable/clean: {path}")
    required = ("data/project_info.csv", "data/build_info.csv", "data/fix_info.csv")
    missing = [relative for relative in required if not (path / relative).is_file()]
    if missing:
        raise ValueError(f"checkout is missing required metadata: {', '.join(missing)}")


def acquire_dataset(config: DatasetConfig, destination: Path) -> None:
    """Clone to a temporary sibling and atomically install a detached checkout."""
    if destination.exists():
        validate_checkout(destination, config)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    checkout = temporary / "checkout"
    try:
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                config.upstream_url,
                str(checkout),
            ]
        )
        _run(["git", "checkout", "--detach", config.revision], cwd=checkout)
        validate_checkout(checkout, config)
        os.replace(checkout, destination)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _read_csv(path: Path) -> list[CsvRow]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _atomic_write_csv(
    path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, str]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_cwe(value: str) -> str:
    prefix, number = value.upper().split("-", maxsplit=1)
    if prefix != "CWE" or not number.isdigit():
        raise ValueError(f"invalid CWE identifier: {value}")
    return f"CWE-{int(number)}"


def opaque_project_id(dataset_id: str, revision: str, project_slug: str) -> str:
    """Return a stable identifier that contains no owner, CVE, CWE, or version hint."""
    payload = f"maxvera-phase2\0{dataset_id}\0{revision}\0{project_slug}".encode()
    return f"proj_{hashlib.sha256(payload).hexdigest()[:20]}"


def _index_unique(rows: Sequence[CsvRow], key: str, source: str) -> dict[str, CsvRow]:
    result: dict[str, CsvRow] = {}
    for row in rows:
        value = row.get(key, "")
        if not value or value in result:
            raise ValueError(f"missing or duplicate {key} in {source}: {value!r}")
        result[value] = row
    return result


def build_canonical_rows(raw_root: Path, config: DatasetConfig) -> list[CsvRow]:
    """Join frozen upstream project/build/fix/advisory metadata once per CVE-project."""
    projects = _read_csv(raw_root / "data" / "project_info.csv")
    builds = _index_unique(
        _read_csv(raw_root / "data" / "build_info.csv"), "project_slug", "build_info"
    )
    fix_counts = Counter(
        row["project_slug"] for row in _read_csv(raw_root / "data" / "fix_info.csv")
    )
    if config.expected_cves is not None and len(projects) != config.expected_cves:
        raise ValueError(f"expected {config.expected_cves} CVEs, found {len(projects)}")
    _index_unique(projects, "project_slug", "project_info")
    canonical: list[CsvRow] = []
    for project in projects:
        slug = project["project_slug"]
        build = builds.get(slug)
        if build is None:
            raise ValueError(f"missing upstream build metadata for {slug}")
        advisory = raw_root / "advisory" / f"{slug}.json"
        if not advisory.is_file():
            raise ValueError(f"missing advisory for {slug}")
        canonical.append(
            {
                "dataset_id": config.dataset_id,
                "upstream_revision": config.revision,
                "row_id": project["id"],
                "project_id": opaque_project_id(config.dataset_id, config.revision, slug),
                "project_slug": slug,
                "cve_id": project["cve_id"],
                "ground_truth_cwe": normalize_cwe(project["cwe_id"]),
                "cwe_name": project["cwe_name"],
                "github_username": project["github_username"],
                "github_repository_name": project["github_repository_name"],
                "github_tag": project["github_tag"],
                "github_url": project["github_url"],
                "advisory_id": project["advisory_id"],
                "buggy_commit_id": project["buggy_commit_id"],
                "fix_commit_ids": project["fix_commit_ids"],
                "upstream_build_status": build["status"].upper(),
                "jdk_version": build["jdk_version"],
                "maven_version": build["mvn_version"],
                "gradle_version": build["gradle_version"],
                "use_gradlew": build["use_gradlew"],
                "fix_location_count": str(fix_counts[slug]),
                "advisory_sha256": sha256_file(advisory),
            }
        )
    return canonical


def _group_key(row: Mapping[str, str]) -> str:
    return f"{row['github_username']}/{row['github_repository_name']}".casefold()


def assign_group_splits(
    rows: Sequence[CsvRow], *, seed: int, development_ratio: float
) -> dict[str, str]:
    """Deterministically split owner/repository groups using a version-stable SHA256 order."""
    groups: dict[str, list[CsvRow]] = {}
    for row in rows:
        groups.setdefault(_group_key(row), []).append(row)
    ordered = sorted(
        groups,
        key=lambda group: hashlib.sha256(f"{seed}\0{group}".encode()).hexdigest(),
    )
    target_rows = round(len(rows) * development_ratio)
    development: set[str] = set()
    current = 0
    for group in ordered:
        group_size = len(groups[group])
        include_distance = abs((current + group_size) - target_rows)
        exclude_distance = abs(current - target_rows)
        if include_distance < exclude_distance or (
            include_distance == exclude_distance and current < target_rows
        ):
            development.add(group)
            current += group_size
    if not development or len(development) == len(groups):
        raise ValueError("group split produced an empty partition")
    return {
        row["project_id"]: "development" if _group_key(row) in development else "test_locked"
        for row in rows
    }


def assert_analysis_rows_safe(rows: Sequence[Mapping[str, str]]) -> None:
    """Fail closed if a protected column or label-like value enters the analyzer view."""
    for row in rows:
        forbidden = FORBIDDEN_ANALYSIS_FIELDS.intersection(row)
        if forbidden:
            raise ValueError(
                f"analysis view contains forbidden fields: {', '.join(sorted(forbidden))}"
            )
        serialized = json.dumps(row, sort_keys=True)
        if "CVE-" in serialized.upper() or "CWE-" in serialized.upper():
            raise ValueError("analysis view contains a CVE/CWE label-like value")


def _write_fix_locations(raw_root: Path, rows_by_slug: Mapping[str, CsvRow], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for fix in _read_csv(raw_root / "data" / "fix_info.csv"):
        canonical = rows_by_slug.get(fix["project_slug"])
        # Upstream fix_info intentionally contains historical rows outside the
        # frozen 120-project project_info table. They are not release members.
        if canonical is None:
            continue
        protected = dict(fix)
        protected["project_id"] = canonical["project_id"]
        lines.append(json.dumps(protected, sort_keys=True, ensure_ascii=False))
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def materialize_release(
    repo_root: Path,
    raw_root: Path,
    config: DatasetConfig,
    *,
    write_splits: bool,
) -> dict[str, Any]:
    """Create canonical metadata, isolated views, deterministic splits, and checksums."""
    validate_checkout(raw_root, config)
    rows = build_canonical_rows(raw_root, config)
    processed = repo_root / "data" / "processed"
    canonical_path = (
        processed
        / "manifests"
        / ("cwe_bench_v1.csv" if config.dataset_id == "D_repro_v1" else "cwe_bench_extended.csv")
    )
    _atomic_write_csv(canonical_path, CANONICAL_COLUMNS, rows)

    analysis_rows = [
        {
            "project_id": row["project_id"],
            "source_dir": f"projects/{row['project_id']}",
            "source_required": "true",
            "jdk_version": row["jdk_version"],
            "maven_version": row["maven_version"],
            "gradle_version": row["gradle_version"],
            "use_gradlew": row["use_gradlew"],
        }
        for row in rows
    ]
    assert_analysis_rows_safe(analysis_rows)
    analysis_manifest = processed / "analysis_input" / f"{config.dataset_id}_projects.csv"
    _atomic_write_csv(analysis_manifest, ANALYSIS_COLUMNS, analysis_rows)

    evaluator_labels = processed / "evaluator_only" / f"{config.dataset_id}_labels.csv"
    _atomic_write_csv(evaluator_labels, CANONICAL_COLUMNS, rows)
    fix_locations = processed / "evaluator_only" / f"{config.dataset_id}_fix_locations.jsonl"
    _write_fix_locations(raw_root, {row["project_slug"]: row for row in rows}, fix_locations)

    generated: list[Path] = [canonical_path, analysis_manifest, evaluator_labels, fix_locations]
    split_counts: Counter[str] = Counter()
    if write_splits:
        assignments = assign_group_splits(
            rows, seed=config.split_seed, development_ratio=config.development_ratio
        )
        for split in ("development", "test_locked"):
            split_rows = [
                {"project_id": row["project_id"], "split": split}
                for row in rows
                if assignments[row["project_id"]] == split
            ]
            split_counts[split] = len(split_rows)
            split_path = processed / "splits" / f"{split}.csv"
            _atomic_write_csv(split_path, ("project_id", "split"), split_rows)
            generated.append(split_path)
        groups_path = processed / "evaluator_only" / f"{config.dataset_id}_split_groups.csv"
        group_rows = [
            {
                "project_id": row["project_id"],
                "repository_group": _group_key(row),
                "split": assignments[row["project_id"]],
            }
            for row in rows
        ]
        _atomic_write_csv(groups_path, ("project_id", "repository_group", "split"), group_rows)
        generated.append(groups_path)

    metadata_sources = [
        raw_root / "data" / "project_info.csv",
        raw_root / "data" / "build_info.csv",
        raw_root / "data" / "fix_info.csv",
    ]
    for relative, pattern in (
        ("advisory", "*.json"),
        ("patches", "*.patch"),
        ("package-names", "*.txt"),
        ("scripts", "*_version.json"),
    ):
        directory = raw_root / relative
        if directory.is_dir():
            metadata_sources.extend(sorted(directory.glob(pattern)))
    source_index = processed / "manifests" / f"{config.dataset_id}_source_checksums.sha256"
    write_checksums(metadata_sources, source_index, raw_root)
    generated.append(source_index)
    release_index = processed / "manifests" / f"{config.dataset_id}_checksums.sha256"
    write_checksums(generated, release_index, repo_root)
    return {
        "dataset_id": config.dataset_id,
        "revision": config.revision,
        "rows": len(rows),
        "repositories": len({_group_key(row) for row in rows}),
        "cwes": sorted({row["ground_truth_cwe"] for row in rows}),
        "splits": dict(split_counts),
        "release_checksum": sha256_file(release_index),
        "materialized_at": utc_now(),
    }


def initialize_build_status(repo_root: Path, rows: Sequence[CsvRow], config: DatasetConfig) -> Path:
    """Record every project honestly before local builds start; PENDING does not pass the gate."""
    path = repo_root / "data" / "interim" / "build_info" / "build_status.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    expected_ids = [row["project_id"] for row in rows]
    if path.is_file():
        existing = [
            cast(dict[str, Any], json.loads(line))
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        existing_ids = [str(record.get("project_id", "")) for record in existing]
        if existing_ids != expected_ids:
            raise ValueError("existing build status does not match canonical project order")
        return path
    lines = [
        json.dumps(
            {
                "schema_version": 1,
                "dataset_id": config.dataset_id,
                "upstream_revision": config.revision,
                "project_id": row["project_id"],
                "status": "PENDING",
                "reason": "local build and CodeQL database creation have not run",
            },
            sort_keys=True,
        )
        for row in rows
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def verify_checksum_index(index: Path, root: Path) -> list[str]:
    """Verify a GNU-style checksum index without allowing paths outside its root."""
    failures: list[str] = []
    resolved_root = root.resolve()
    if not index.is_file():
        return [f"checksum index is missing: {index.name}"]
    for number, line in enumerate(index.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            digest, relative = line.split("  ", maxsplit=1)
        except ValueError:
            failures.append(f"malformed checksum record {index.name}:{number}")
            continue
        target = (resolved_root / relative).resolve()
        if target != resolved_root and resolved_root not in target.parents:
            failures.append(f"unsafe checksum path {index.name}:{number}")
        elif not target.is_file():
            failures.append(f"checksummed file is missing: {relative}")
        elif sha256_file(target) != digest:
            failures.append(f"checksum mismatch: {relative}")
    return failures


def validate_phase2(repo_root: Path, expected: int = 120) -> list[str]:
    """Return gate failures; an empty list means the complete Phase 2 gate passes."""
    failures: list[str] = []
    manifest = repo_root / "data/processed/manifests/cwe_bench_v1.csv"
    if not manifest.is_file():
        return ["canonical v1 manifest is missing"]
    rows = _read_csv(manifest)
    if len(rows) != expected:
        failures.append(f"canonical manifest has {len(rows)}/{expected} rows")
    if len({row["project_id"] for row in rows}) != len(rows):
        failures.append("canonical project_id values are not unique")
    status_path = repo_root / "data/interim/build_info/build_status.jsonl"
    statuses: list[dict[str, Any]] = []
    if status_path.is_file():
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                statuses.append(cast(dict[str, Any], json.loads(line)))
    if len(statuses) != expected:
        failures.append(f"build status has {len(statuses)}/{expected} records")
    allowed = {
        "SUCCESS",
        "BUILD_FAILED",
        "CODEQL_DB_FAILED",
        "ANALYSIS_FAILED",
        "EXCLUDED_WITH_REASON",
    }
    invalid = Counter(
        str(item.get("status")) for item in statuses if item.get("status") not in allowed
    )
    if invalid:
        failures.append(f"non-final project statuses remain: {dict(invalid)}")
    exclusions_without_reason = [
        item.get("project_id", "UNKNOWN")
        for item in statuses
        if item.get("status") == "EXCLUDED_WITH_REASON" and not item.get("reason")
    ]
    if exclusions_without_reason:
        failures.append("one or more exclusions lack a reason")
    successful = [item for item in statuses if item.get("status") == "SUCCESS"]
    missing_databases = [
        item.get("project_id", "UNKNOWN")
        for item in successful
        if not (repo_root / "data/interim/codeql_databases" / str(item.get("project_id"))).is_dir()
    ]
    if missing_databases:
        failures.append(f"{len(missing_databases)} successful projects lack a CodeQL database")
    for split in ("development.csv", "test_locked.csv"):
        if not (repo_root / "data/processed/splits" / split).is_file():
            failures.append(f"split is missing: {split}")
    extended_path = repo_root / "data/processed/manifests/cwe_bench_extended.csv"
    if extended_path.is_file():
        extended = _read_csv(extended_path)
        extended_config = load_dataset_config(
            repo_root / "configs/datasets/cwe_bench_extended.yaml"
        )
        expected_assignments = assign_group_splits(
            extended,
            seed=extended_config.split_seed,
            development_ratio=extended_config.development_ratio,
        )
        observed: dict[str, str] = {}
        for split in ("development", "test_locked"):
            split_path = repo_root / "data/processed/splits" / f"{split}.csv"
            if split_path.is_file():
                for row in _read_csv(split_path):
                    project_id = row.get("project_id", "")
                    if project_id in observed:
                        failures.append(f"project appears in multiple splits: {project_id}")
                    observed[project_id] = row.get("split", "")
        if observed != expected_assignments:
            failures.append("split files do not reproduce the frozen group-wise assignment")
    else:
        failures.append("extended manifest is missing")
    analysis_files = list((repo_root / "data/processed/analysis_input").glob("*.csv"))
    if len(analysis_files) != 2:
        failures.append(f"expected two analysis manifests, found {len(analysis_files)}")
    for analysis_file in analysis_files:
        assert_analysis_rows_safe(_read_csv(analysis_file))
    evaluator_files = list((repo_root / "data/processed/evaluator_only").glob("*"))
    if len(evaluator_files) < 6:
        failures.append("physical evaluator-only view is incomplete")
    manifest_root = repo_root / "data/processed/manifests"
    for dataset_id, raw_suffix in (("D_repro_v1", "v1"), ("D_extended", "extended")):
        failures.extend(
            verify_checksum_index(manifest_root / f"{dataset_id}_checksums.sha256", repo_root)
        )
        failures.extend(
            verify_checksum_index(
                manifest_root / f"{dataset_id}_source_checksums.sha256",
                repo_root / "data/raw" / f"cwe_bench_java_{raw_suffix}",
            )
        )
    return failures


def _default_raw_path(repo_root: Path, dataset_id: str) -> Path:
    suffix = "v1" if dataset_id == "D_repro_v1" else "extended"
    return repo_root / "data" / "raw" / f"cwe_bench_java_{suffix}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("acquire", "materialize", "validate"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, default=Path("configs/datasets/cwe_bench_v1.yaml"))
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--with-splits", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    if args.command == "validate":
        failures = validate_phase2(repo_root)
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            return 1
        print("Phase 2 gate passed.")
        return 0
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    config = load_dataset_config(config_path)
    raw_root = args.raw_root or _default_raw_path(repo_root, config.dataset_id)
    raw_root = raw_root.resolve()
    if args.command == "acquire":
        acquire_dataset(config, raw_root)
        print(f"Verified {config.dataset_id} at {config.revision}: {raw_root}")
        return 0
    summary = materialize_release(repo_root, raw_root, config, write_splits=bool(args.with_splits))
    rows = build_canonical_rows(raw_root, config)
    if config.dataset_id == "D_repro_v1":
        initialize_build_status(repo_root, rows, config)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
