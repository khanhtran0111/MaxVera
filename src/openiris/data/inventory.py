"""Deterministic dataset inventory reports required by the Phase 0 gate."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ._serialization import atomic_write_text
from .errors import DatasetFormatError
from .models import DatasetBundle, ProjectRecord
from .runtime_view import audit_runtime_manifest, opaque_instance_id

REQUIRED_REPORT_FILES = frozenset(
    {
        "summary.md",
        "cwe_distribution.csv",
        "repository_distribution.csv",
        "build_status.csv",
        "duplicate_repository_versions.csv",
        "leakage_audit.json",
    }
)


def _csv_text(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue()


def _snapshot_value(manifest: Mapping[str, Any], key: str) -> Any:
    if key not in manifest:
        raise DatasetFormatError(f"Snapshot manifest is missing {key!r}")
    return manifest[key]


def _summary_markdown(
    bundle: DatasetBundle,
    manifest: Mapping[str, Any],
    *,
    repeated_repositories: int,
    missing_fix_commits: int,
    missing_fix_locations: int,
    missing_source_sink: int,
    leakage_status: str,
) -> str:
    cwe_counts = Counter(item.cwe_id for item in bundle.instances)
    success = sum(item.build.succeeded for item in bundle.instances)
    failure = sum(
        not item.build.succeeded and item.build.status != "missing" for item in bundle.instances
    )
    missing_build = len(bundle.instances) - success - failure
    cwe_lines = "\n".join(
        f"| {cwe} | {count} |"
        for cwe, count in sorted(cwe_counts.items(), key=lambda item: int(item[0].split("-")[1]))
    )
    raw_labels = bundle.effective_raw_cwe_labels
    aliases: defaultdict[str, list[str]] = defaultdict(list)
    for raw_label in sorted(raw_labels):
        # Records already carry normalized identifiers; this highlights aliases
        # from the upstream spelling without changing distribution semantics.
        aliases[f"CWE-{int(raw_label.split('-')[-1])}"].append(raw_label)
    collisions = {key: values for key, values in aliases.items() if len(values) > 1}
    if collisions:
        collision_lines = "\n".join(
            f"- `{normalized}` merges upstream labels: "
            + ", ".join(f"`{raw}`" for raw in raw_values)
            for normalized, raw_values in sorted(collisions.items())
        )
    else:
        collision_lines = "- No raw-label alias collisions in this snapshot."
    return (
        f"# Dataset inventory: {_snapshot_value(manifest, 'snapshot_id')}\n\n"
        "## Summary\n\n"
        "| Metric | Value |\n"
        "|---|---:|\n"
        f"| Benchmark instances | {len(bundle.instances)} |\n"
        f"| Unique GitHub repositories | {len(bundle.repositories)} |\n"
        f"| Raw upstream CWE labels | {len(raw_labels)} |\n"
        f"| Semantic CWEs after normalization | {len(bundle.cwes)} |\n"
        f"| Upstream-declared successful builds | {success} |\n"
        f"| Upstream-declared failed builds | {failure} |\n"
        f"| Missing upstream build-status records | {missing_build} |\n"
        f"| Repositories with multiple instances/versions | {repeated_repositories} |\n"
        f"| Instances missing fix commits | {missing_fix_commits} |\n"
        f"| Instances missing fix locations | {missing_fix_locations} |\n"
        f"| Instances without curated source/sink metadata | {missing_source_sink} |\n"
        f"| Raw curated source/sink rows | {bundle.raw_source_sink_annotation_rows} |\n"
        f"| Orphan curated source/sink rows | {bundle.orphan_source_sink_annotation_rows} |\n"
        f"| Runtime leakage audit | {leakage_status} |\n"
        f"| Snapshot hash | `{_snapshot_value(manifest, 'sha256_manifest')}` |\n\n"
        "Build counts above reproduce metadata declared by the benchmark; they are not local "
        "Phase 0 smoke-run results.\n\n"
        "## CWE label normalization anomalies\n\n"
        f"{collision_lines}\n\n"
        "## CWE distribution\n\n"
        "| CWE | Instances |\n"
        "|---|---:|\n"
        f"{cwe_lines}\n"
    )


def generate_inventory_reports(
    bundle: DatasetBundle,
    snapshot_manifest: Mapping[str, Any],
    output_directory: str | Path,
    *,
    runtime_manifest: str | Path | None = None,
) -> dict[str, Path]:
    """Generate the six auditable reports defined by the dataset protocol."""

    output = Path(output_directory)
    snapshot_id = str(_snapshot_value(snapshot_manifest, "snapshot_id"))

    cwe_counts = Counter(item.cwe_id for item in bundle.instances)
    cwe_rows = [
        (cwe, count, f"{count / len(bundle.instances):.8f}")
        for cwe, count in sorted(cwe_counts.items(), key=lambda item: int(item[0].split("-")[1]))
    ]

    repositories: defaultdict[str, list[ProjectRecord]] = defaultdict(list)
    for instance in bundle.instances:
        repositories[instance.repository_key].append(instance)
    repository_rows = []
    duplicate_rows = []
    for repository, instances in repositories.items():
        versions = sorted({item.repository_tag for item in instances if item.repository_tag})
        repository_rows.append((repository, len(instances), len(versions)))
        if len(instances) > 1 or len(versions) > 1:
            duplicate_rows.append(
                (
                    repository,
                    len(instances),
                    len(versions),
                    ";".join(versions),
                    ";".join(sorted(item.project_slug for item in instances)),
                )
            )
    repository_rows.sort(key=lambda row: (-row[1], row[0]))
    duplicate_rows.sort(key=lambda row: (-row[1], row[0]))

    build_rows = [
        (
            opaque_instance_id(instance, snapshot_id),
            instance.project_slug,
            instance.repository_key,
            instance.build.status,
            instance.build.jdk_version,
            instance.build.maven_version,
            instance.build.gradle_version,
            instance.build.use_gradle_wrapper,
        )
        for instance in sorted(bundle.instances, key=lambda item: item.project_slug)
    ]

    if runtime_manifest is None:
        leakage_audit: dict[str, Any] = {
            "schema_version": "1.0",
            "status": "NOT_RUN",
            "records_checked": 0,
            "reason": "runtime_manifest was not supplied",
        }
    else:
        leakage_audit = audit_runtime_manifest(runtime_manifest)

    missing_fix_commits = sum(not item.fix_commit_ids for item in bundle.instances)
    missing_fix_locations = sum(
        item.project_slug not in bundle.fix_locations for item in bundle.instances
    )
    missing_source_sink = sum(
        item.project_slug not in bundle.source_sink_annotations for item in bundle.instances
    )

    contents = {
        "cwe_distribution.csv": _csv_text(("cwe_id", "instance_count", "fraction"), cwe_rows),
        "repository_distribution.csv": _csv_text(
            ("repository", "instance_count", "version_count"), repository_rows
        ),
        "build_status.csv": _csv_text(
            (
                "instance_id",
                "project_slug",
                "repository",
                "declared_status",
                "jdk_version",
                "maven_version",
                "gradle_version",
                "use_gradle_wrapper",
            ),
            build_rows,
        ),
        "duplicate_repository_versions.csv": _csv_text(
            ("repository", "instance_count", "version_count", "versions", "project_slugs"),
            duplicate_rows,
        ),
        "leakage_audit.json": json.dumps(
            leakage_audit, ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n",
        "summary.md": _summary_markdown(
            bundle,
            snapshot_manifest,
            repeated_repositories=len(duplicate_rows),
            missing_fix_commits=missing_fix_commits,
            missing_fix_locations=missing_fix_locations,
            missing_source_sink=missing_source_sink,
            leakage_status=str(leakage_audit["status"]),
        ),
    }
    paths: dict[str, Path] = {}
    for name, content in sorted(contents.items()):
        path = output / name
        atomic_write_text(path, content)
        paths[name] = path
    return paths


generate_inventory = generate_inventory_reports
