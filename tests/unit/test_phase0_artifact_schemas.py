from __future__ import annotations

import hashlib
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from openiris.data import BuildInfo, RuntimeInstance, RuntimeRepository
from openiris.data.manifest import manifest_content_hash
from openiris.data.splits import SPLIT_NAMES, read_split_manifest
from openiris.experiments import BaselineRecord, BaselineStatus

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "schemas"
FORMAT_CHECKER = FormatChecker()


def _document(path: Path) -> dict[str, Any]:
    if path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
    else:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"{path} must contain one object"
    return value


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _document(SCHEMA_ROOT / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        assert isinstance(value, dict), f"{path}:{line_number} must contain one object"
        records.append(value)
    return records


def test_all_json_schemas_are_valid_and_have_unique_ids() -> None:
    schemas = [_document(path) for path in sorted(SCHEMA_ROOT.glob("*.schema.json"))]

    assert schemas
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    ids = [schema["$id"] for schema in schemas]
    assert len(ids) == len(set(ids))


def test_frozen_dataset_manifests_validate_and_are_self_consistent() -> None:
    validator = _validator("dataset_manifest.schema.json")
    paths = sorted((PROJECT_ROOT / "data" / "manifests" / "datasets").glob("*.yaml"))

    assert {path.stem for path in paths} == {
        "cwe_bench_java_legacy_698fb724",
        "cwe_bench_java_v2_3a12f457",
    }
    for path in paths:
        manifest = _document(path)
        validator.validate(manifest)
        assert manifest["sha256_manifest"] == manifest_content_hash(manifest)
        assert (
            manifest["num_upstream_declared_build_success"]
            + manifest["num_upstream_declared_build_failure"]
            + manifest["num_upstream_build_status_missing"]
            == manifest["num_instances"]
        )
        assert manifest["num_cwes"] <= manifest["num_raw_cwe_labels"]
        collisions = manifest["cwe_normalization"]["alias_collisions"]
        collapsed_aliases = sum(len(raw_labels) - 1 for raw_labels in collisions.values())
        assert manifest["num_raw_cwe_labels"] - manifest["num_cwes"] == collapsed_aliases
        assert manifest["num_curated_source_sink_instances_matched"] <= manifest["num_instances"]
        assert (
            manifest["num_orphan_curated_source_sink_rows"]
            <= manifest["num_raw_curated_source_sink_rows"]
        )


def test_split_manifests_validate_and_cover_their_dataset_snapshots() -> None:
    validator = _validator("split_manifest.schema.json")
    dataset_paths = (PROJECT_ROOT / "data" / "manifests" / "datasets").glob("*.yaml")
    datasets = {
        manifest["snapshot_id"]: manifest
        for manifest in (_document(path) for path in dataset_paths)
    }
    split_paths = sorted((PROJECT_ROOT / "data" / "manifests" / "splits").glob("*.yaml"))

    assert len(split_paths) == len(datasets) == 2
    for path in split_paths:
        split = read_split_manifest(path)
        validator.validate(split)
        dataset = datasets[split["dataset"]["snapshot_id"]]
        assert split["dataset"]["manifest_sha256"] == dataset["sha256_manifest"]
        assert sum(split["ratios"].values()) == pytest.approx(1.0)

        assigned_ids: set[str] = set()
        assigned_repositories: set[str] = set()
        for name in SPLIT_NAMES:
            instance_ids = split["assignments"][name]
            repositories = split["repository_assignments"][name]
            assert split["counts"][name] == {
                "instances": len(instance_ids),
                "repositories": len(repositories),
            }
            assert assigned_ids.isdisjoint(instance_ids)
            assert assigned_repositories.isdisjoint(repositories)
            assigned_ids.update(instance_ids)
            assigned_repositories.update(repositories)
        assert len(assigned_ids) == dataset["num_instances"]
        assert len(assigned_repositories) == dataset["num_unique_repositories"]


def test_runtime_record_schema_matches_the_zero_hint_allowlist() -> None:
    validator = _validator("runtime_manifest_record.schema.json")
    record = RuntimeInstance(
        instance_id=f"oi_{'a' * 32}",
        snapshot_id="fixture",
        track="legacy",
        repository=RuntimeRepository(
            host="github.com",
            owner="acme",
            name="widget",
            url="https://github.com/acme/widget",
        ),
        revision="b" * 40,
        build=BuildInfo(status="success", jdk_version="17"),
    ).to_dict()

    validator.validate(record)
    leaked = deepcopy(record)
    leaked["cve_id"] = "CVE-2026-1"
    with pytest.raises(ValidationError):
        validator.validate(leaked)


def test_materialized_runtime_and_ground_truth_jsonl_validate_when_present() -> None:
    runtime_validator = _validator("runtime_manifest_record.schema.json")
    truth_validator = _validator("ground_truth_record.schema.json")
    runtime_paths = sorted((PROJECT_ROOT / "data" / "runtime_views").rglob("manifest.jsonl"))
    truth_paths = sorted((PROJECT_ROOT / "data" / "ground_truth").rglob("ground_truth.jsonl"))

    if not runtime_paths or not truth_paths:
        pytest.skip("materialized dataset views are intentionally not source-controlled")
    assert len(runtime_paths) == len(truth_paths) == 2
    runtime_ids_by_snapshot: dict[str, set[str]] = {}
    truth_ids_by_snapshot: dict[str, set[str]] = {}
    for path in runtime_paths:
        records = _jsonl(path)
        assert records
        for record in records:
            runtime_validator.validate(record)
        instance_ids = [record["instance_id"] for record in records]
        assert len(instance_ids) == len(set(instance_ids))
        runtime_ids_by_snapshot[path.parent.name] = set(instance_ids)
    for path in truth_paths:
        records = _jsonl(path)
        assert records
        for record in records:
            truth_validator.validate(record)
        instance_ids = [record["instance_id"] for record in records]
        assert len(instance_ids) == len(set(instance_ids))
        truth_ids_by_snapshot[path.parent.name] = set(instance_ids)

    assert runtime_ids_by_snapshot == truth_ids_by_snapshot
    split_paths = (PROJECT_ROOT / "data" / "manifests" / "splits").glob("*.yaml")
    split_ids = {
        split["dataset"]["snapshot_id"]: set().union(
            *(set(split["assignments"][name]) for name in SPLIT_NAMES)
        )
        for split in (read_split_manifest(path) for path in split_paths)
    }
    assert runtime_ids_by_snapshot == split_ids


def test_published_reference_manifest_and_jsonl_are_cross_consistent() -> None:
    root = PROJECT_ROOT / "results" / "phases" / "phase_00" / "baselines" / "published_reference"
    manifest_validator = _validator("published_reference_manifest.schema.json")
    record_validator = _validator("published_reference_record.schema.json")
    manifest = _document(root / "manifest.json")
    manifest_validator.validate(manifest)
    referenced_outputs: set[Path] = set()

    for summary in manifest["references"]:
        output = PROJECT_ROOT / summary["output"]
        referenced_outputs.add(output.resolve())
        records = _jsonl(output)
        for record in records:
            record_validator.validate(record)
            assert record["case_id"] == f"{record['project_slug']}::{record['cwe_id']}"
            assert record["source_name"] == summary["source_name"]
            assert record["source_commit"] == summary["source_commit"]

        case_ids = [record["case_id"] for record in records]
        assert len(case_ids) == len(set(case_ids))
        assert len(records) == summary["num_records"]
        assert sum(record["detected"] for record in records) == summary["num_detected"]
        assert Counter(record["cwe_id"] for record in records) == summary["cwe_distribution"]

        source = PROJECT_ROOT / summary["source"]
        if source.is_file():
            assert hashlib.sha256(source.read_bytes()).hexdigest() == summary["source_sha256"]

    discovered_outputs = {path.resolve() for path in root.glob("*.jsonl")}
    assert referenced_outputs == discovered_outputs


def test_baseline_schema_accepts_normalized_unpadded_cwe_ids() -> None:
    validator = _validator("baseline_record.schema.json")
    record = BaselineRecord(
        run_id="schema_fixture",
        baseline="codeql",
        track="legacy",
        project="acme__widget_CVE-2026-1_1.0",
        cve="CVE-2026-1",
        cwe="CWE-22",
        query="cwe-022wCodeQL",
        status=BaselineStatus.COMPLETE,
        runtime_seconds=1.0,
        number_of_paths=0,
        vulnerability_detected=False,
        exit_code=0,
    ).to_dict()

    validator.validate(record)
    record["unexpected"] = True
    with pytest.raises(ValidationError):
        validator.validate(record)


def test_source_controlled_local_baseline_records_validate_and_have_unique_runs() -> None:
    validator = _validator("baseline_record.schema.json")
    root = PROJECT_ROOT / "results" / "phases" / "phase_00" / "baselines"
    paths = [
        *sorted((root / "codeql").glob("*.jsonl")),
        *sorted((root / "iris").glob("*.jsonl")),
    ]

    assert {path.parent.name for path in paths} == {"codeql", "iris"}
    run_ids: list[str] = []
    for path in paths:
        records = _jsonl(path)
        assert records, f"{path} must contain at least one local result"
        for record in records:
            validator.validate(record)
            assert record["baseline"] == path.parent.name
            run_ids.append(record["run_id"])

    assert len(run_ids) == len(set(run_ids))
