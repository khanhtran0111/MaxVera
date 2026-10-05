from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.common.provenance import sha256_file
from src.experiments.development_audit import (
    BASELINES,
    audit,
    check_manifest,
    check_projects,
    snapshot_run,
    summarize_specifications,
)
from src.reproduction.common import atomic_json, atomic_jsonl, write_checksums


def test_audit_rejects_test_scope_and_mixed_project_records() -> None:
    manifest: dict[str, Any] = {"phase": 6, "selected_project_ids": ["dev"]}
    check_manifest(manifest, {"dev"}, 6)
    with pytest.raises(ValueError, match="non-development"):
        check_manifest({**manifest, "analysis_scope": "test_locked"}, {"dev"}, 6)
    with pytest.raises(ValueError, match="complete development"):
        check_manifest({**manifest, "selected_project_ids": ["test"]}, {"dev"}, 6)
    with pytest.raises(ValueError, match="outside the development"):
        check_projects([{"project_id": "test"}], {"dev"})


def test_historical_checksum_snapshot_detects_changes_and_unindexed_files(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}\n")
    write_checksums(tmp_path)
    before = snapshot_run(tmp_path)
    assert snapshot_run(tmp_path) == before
    artifact.write_text('{"changed": true}\n')
    with pytest.raises(ValueError, match="checksum or coverage"):
        snapshot_run(tmp_path)
    artifact.write_text("{}\n")
    (tmp_path / "unindexed.json").write_text("{}\n")
    with pytest.raises(ValueError, match="checksum or coverage"):
        snapshot_run(tmp_path)


def test_missing_source_remains_visible_when_synthesis_borrows_program_endpoints() -> None:
    hypotheses = {"hyp": {"project_id": "dev", "source_candidates": []}}
    nodes = {"node": {"project_id": "dev", "layer": "program"}}
    specification = {
        "hypothesis_id": "hyp",
        "project_id": "dev",
        "sources": [{"node_id": "node"}],
        "sinks": [{"node_id": "node"}],
    }
    result = summarize_specifications([specification], hypotheses, nodes)
    assert result["from_hypotheses_without_source"] == 1
    assert result["shared_source_sink_node"] == 1
    with pytest.raises(ValueError, match="another project"):
        summarize_specifications(
            [specification], hypotheses, {"node": {"project_id": "other", "layer": "program"}}
        )


def _fixtures(root: Path) -> Path:
    split = root / "data/processed/splits/development.csv"
    split.parent.mkdir(parents=True)
    split.write_text("project_id\ndev\n")
    inputs: dict[str, Any] = {"development_split_sha256": sha256_file(split)}

    def run(name: str, prefix: str, phase: int) -> Path:
        path = root / prefix / name
        atomic_json(
            path / "manifest.json",
            {
                "phase": phase,
                "run_id": name,
                "selected_project_ids": ["dev"],
            },
        )
        inputs[name] = {
            "run_root": path.relative_to(root).as_posix(),
            "run_id": name,
            "manifest_sha256": sha256_file(path / "manifest.json"),
        }
        return path

    phase6 = run("phase6", "results/hypotheses/static", 6)
    atomic_jsonl(
        phase6 / "hypotheses.jsonl",
        [
            {
                "hypothesis_id": "hyp",
                "project_id": "dev",
                "candidate_cwe": ["CWE-22"],
                "source_candidates": [],
                "sink_candidates": [{"symbol": "sink"}],
            }
        ],
    )
    atomic_jsonl(
        phase6 / "metrics_project.jsonl",
        [
            {
                "project_id": "dev",
                "hypothesis_recall_at_10": True,
                "candidate_pool_recall_at_40": True,
            }
        ],
    )
    phase7 = run("phase7", "results/graphs/program", 7)
    atomic_jsonl(phase7 / "project_status.jsonl", [{"project_id": "dev", "status": "SUCCESS"}])
    atomic_jsonl(phase7 / "graphs/dev/nodes.jsonl", [{"project_id": "dev", "kind": "EXPR"}])
    phase9 = run("phase9", "results/graphs/useg", 9)
    atomic_jsonl(
        phase9 / "useg/nodes.jsonl",
        [
            {
                "node_id": "hyp_node",
                "project_id": "dev",
                "kind": "HYPOTHESIS",
                "layer": "evidence",
                "properties": {"upstream_hypothesis_id": "hyp"},
            },
            {
                "node_id": "sink",
                "project_id": "dev",
                "kind": "ASSERTION",
                "layer": "evidence",
                "properties": {"assertion_type": "source_location", "role": "sink"},
            },
            {
                "node_id": "node",
                "project_id": "dev",
                "kind": "PROGRAM_NODE",
                "layer": "program",
                "properties": {},
            },
        ],
    )
    atomic_jsonl(
        phase9 / "useg/edges.jsonl",
        [
            {
                "project_id": "dev",
                "kind": "MATCHES",
                "source_id": "sink",
                "target_id": "node",
            }
        ],
    )
    for baseline, folder in BASELINES.items():
        path = run(baseline, f"results/specifications/phase10/{folder}", 10)
        atomic_jsonl(
            path / "specifications.jsonl",
            [
                {
                    "specification_id": baseline,
                    "hypothesis_id": "hyp",
                    "project_id": "dev",
                    "sources": [{"node_id": "node"}],
                    "sinks": [{"node_id": "node"}],
                }
            ],
        )
    evaluation = run("phase10_evaluation", "results/evaluations/phase10", 10)
    atomic_json(
        evaluation / "manifest.json",
        {
            "phase": 10,
            "run_id": "phase10_evaluation",
            "data_access": "development labels/fix locations only; test_locked forbidden",
            "evaluator_inputs": {"development_split_sha256": sha256_file(split)},
            "dependencies": {name: inputs[name] for name in BASELINES},
        },
    )
    inputs["phase10_evaluation"]["manifest_sha256"] = sha256_file(evaluation / "manifest.json")
    atomic_jsonl(
        evaluation / "spec_metrics.jsonl",
        [
            {
                "project_id": "dev",
                "baseline_id": baseline,
                "candidate_cwe_correct": True,
                "paper_proxy_match": False,
            }
            for baseline in BASELINES
        ],
    )
    for name, dependency in inputs.items():
        if name != "development_split_sha256":
            write_checksums(root / dependency["run_root"])
    config = root / "audit.yaml"
    config.write_text(yaml.safe_dump({"audit_inputs": inputs}))
    return config


def test_audit_is_immutable_and_reads_only_development_artifacts(tmp_path: Path) -> None:
    config = _fixtures(tmp_path)
    # Neither a test split nor evaluator-only labels exist in this fixture.
    original = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = audit(tmp_path, config, "audit_001")
    summary = json.loads((result / "summary.json").read_text())
    assert summary["phase6"]["without_source"] == 1
    assert summary["phase9"]["hypotheses_without_phase6_source"] == 1
    assert summary["phase10"]["B9"]["from_hypotheses_without_source"] == 1
    assert summary["test_artifacts_opened"] is False
    assert summary["historical_inputs_unchanged"] is True
    assert all(path.read_bytes() == content for path, content in original.items())
    snapshot_run(result)
    with pytest.raises(FileExistsError, match="already exists"):
        audit(tmp_path, config, "audit_001")


def test_audit_rejects_test_record_even_in_checksum_valid_development_run(tmp_path: Path) -> None:
    config = _fixtures(tmp_path)
    phase6 = tmp_path / "results/hypotheses/static/phase6"
    atomic_jsonl(phase6 / "hypotheses.jsonl", [{"project_id": "test"}])
    write_checksums(phase6)
    with pytest.raises(ValueError, match="outside the development"):
        audit(tmp_path, config, "audit_001")
    assert not (tmp_path / "results/audits/audit_001").exists()
