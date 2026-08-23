#!/usr/bin/env python3
"""Summarize auditable Phase 0 artifacts without treating references as reruns."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from openiris.toolchain.doctor import audit  # noqa: E402
from openiris.utils.hashing import sha256_file, sha256_paths  # noqa: E402
from openiris.utils.io import write_json  # noqa: E402


def _load_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle) if path.suffix == ".json" else yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected one object in {path}")
    return value


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"expected an object at {path}:{line_number}")
            records.append(value)
    return records


def _json_objects(directory: Path) -> list[dict[str, Any]]:
    return [_load_mapping(path) for path in sorted(directory.glob("*.json"))]


def _local_baseline_records(root: Path, baseline: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    directory = root / "results" / "phases" / "phase_00" / "baselines" / baseline
    for path in sorted(directory.glob("*.jsonl")) if directory.is_dir() else ():
        records.extend(_jsonl(path))
    return records


def _record_identity(record: dict[str, Any]) -> str | None:
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        for key in ("instance_id", "runtime_instance_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
    project = record.get("project")
    return project if isinstance(project, str) and project else None


def _cwe_number(value: Any) -> int | None:
    if not isinstance(value, str) or not value.upper().startswith("CWE-"):
        return None
    try:
        return int(value[4:])
    except ValueError:
        return None


def _matches_published_codeql(record: dict[str, Any], references: list[dict[str, Any]]) -> bool:
    metadata = record.get("metadata")
    evaluation = metadata.get("evaluation") if isinstance(metadata, dict) else None
    if not isinstance(evaluation, dict):
        return False
    candidates = [
        item
        for item in references
        if item.get("cve_id") == record.get("cve")
        and _cwe_number(item.get("cwe_id")) == _cwe_number(record.get("cwe"))
    ]
    return any(
        item.get("num_alerts") == evaluation.get("num_results")
        and item.get("num_paths") == record.get("number_of_paths")
        and item.get("num_tp_alerts") == evaluation.get("num_tp_results_method")
        and item.get("num_tp_paths") == evaluation.get("num_tp_paths_method")
        and item.get("detected") == record.get("vulnerability_detected")
        for item in candidates
    )


def _evaluation_pairs(records: list[dict[str, Any]]) -> set[tuple[str, int]]:
    pairs: set[tuple[str, int]] = set()
    for record in records:
        cve = record.get("cve_id")
        cwe = _cwe_number(record.get("cwe_id"))
        if isinstance(cve, str) and cwe is not None:
            pairs.add((cve, cwe))
    return pairs


def _local_artifacts_present(record: dict[str, Any]) -> bool:
    command_record = record.get("command_record")
    artifacts = record.get("output_artifacts")
    return (
        isinstance(command_record, str)
        and Path(command_record).is_file()
        and isinstance(artifacts, list)
        and bool(artifacts)
        and all(isinstance(path, str) and Path(path).is_file() for path in artifacts)
    )


def _token_receipt_valid(receipt: dict[str, Any], iris_records: list[dict[str, Any]]) -> bool:
    run_id = receipt.get("run_id")
    matching = [record for record in iris_records if record.get("run_id") == run_id]
    if len(matching) != 1:
        return False
    artifacts = matching[0].get("output_artifacts")
    source = receipt.get("source_artifacts")
    if not isinstance(artifacts, list) or not isinstance(source, dict):
        return False
    paths = [Path(path) for path in artifacts if isinstance(path, str)]
    model_snapshots = [path for path in paths if path.name == "model_snapshot.json"]
    final_results = [path for path in paths if path.name == "results.json"]
    if len(model_snapshots) != 1 or len(final_results) != 1:
        return False
    model_snapshot = model_snapshots[0]
    final_result = final_results[0]
    if not model_snapshot.is_file() or not final_result.is_file():
        return False
    output_root = final_result.parents[1]
    raw_paths = [
        path.relative_to(output_root)
        for path in output_root.rglob("*.txt")
        if path.name.startswith(("raw_user_prompt_", "raw_llm_response_"))
    ]
    counts_valid = (
        isinstance(receipt.get("prompt_tokens"), int)
        and receipt["prompt_tokens"] > 0
        and isinstance(receipt.get("completion_tokens"), int)
        and receipt["completion_tokens"] > 0
        and receipt.get("total_tokens") == receipt["prompt_tokens"] + receipt["completion_tokens"]
    )
    return (
        counts_valid
        and len(raw_paths) == source.get("num_raw_text_files")
        and sha256_paths(output_root, raw_paths) == source.get("sha256_paths_and_contents")
        and sha256_file(model_snapshot) == source.get("model_snapshot_sha256")
        and sha256_file(final_result) == source.get("final_results_sha256")
    )


def collect(root: Path) -> dict[str, Any]:
    dataset_paths = sorted((root / "data" / "manifests" / "datasets").glob("*.yaml"))
    datasets = [_load_mapping(path) for path in dataset_paths]
    published_path = (
        root
        / "results"
        / "phases"
        / "phase_00"
        / "baselines"
        / "published_reference"
        / "manifest.json"
    )
    published = _load_mapping(published_path) if published_path.is_file() else {"references": []}
    codeql_records = _local_baseline_records(root, "codeql")
    iris_records = _local_baseline_records(root, "iris")
    token_receipt_path = (
        root / "results" / "phases" / "phase_00" / "audits" / "iris_qwen15b_token_usage.json"
    )
    token_receipt = _load_mapping(token_receipt_path) if token_receipt_path.is_file() else {}
    published_codeql = _jsonl(
        root
        / "results"
        / "phases"
        / "phase_00"
        / "baselines"
        / "published_reference"
        / "codeql.jsonl"
    )
    toolchain = audit(root / "configs" / "toolchain" / "phase0.yaml", root)
    primary_model = _load_mapping(root / "configs" / "models" / "qwen25_coder_3b_q4_k_m.yaml")
    model_smokes = _json_objects(root / "results" / "phases" / "phase_00" / "model_smoke")
    valid_model_smokes = [
        item
        for item in model_smokes
        if item.get("status") == "COMPLETE"
        and isinstance(item.get("model"), dict)
        and item["model"].get("model_id") == primary_model.get("model_id")
        and item["model"].get("revision") == primary_model.get("revision")
        and item["model"].get("sha256") == primary_model.get("sha256")
        and isinstance(item.get("runtime"), dict)
        and item["runtime"].get("cuda_log_detected") is True
    ]

    runtime_ready = all(
        (root / "data" / "runtime_views" / str(item["snapshot_id"]) / "manifest.jsonl").is_file()
        and (
            root / "data" / "ground_truth" / str(item["snapshot_id"]) / "ground_truth.jsonl"
        ).is_file()
        for item in datasets
    )
    codeql_complete = [
        record
        for record in codeql_records
        if record.get("status") == "COMPLETE" and _local_artifacts_present(record)
    ]
    iris_complete = [
        record
        for record in iris_records
        if record.get("status") == "COMPLETE" and _local_artifacts_present(record)
    ]
    legacy = next((item for item in datasets if item.get("track") == "legacy"), None)
    legacy_instances = int(legacy["num_instances"]) if legacy is not None else 0
    legacy_snapshot = str(legacy["snapshot_id"]) if legacy is not None else ""
    legacy_truth = _jsonl(root / "data" / "ground_truth" / legacy_snapshot / "ground_truth.jsonl")
    frozen_pairs = _evaluation_pairs(legacy_truth)
    reference_pairs = _evaluation_pairs(published_codeql)
    missing_reference_pairs = sorted(frozen_pairs - reference_pairs)
    extra_reference_pairs = sorted(reference_pairs - frozen_pairs)
    reference_projects = {
        str(record["project_slug"])
        for record in published_codeql
        if isinstance(record.get("project_slug"), str)
    }
    reference_alignment = {
        "frozen_pairs": len(frozen_pairs),
        "published_rows": len(published_codeql),
        "published_distinct_projects": len(reference_projects),
        "missing_pairs": [f"{cve}::CWE-{cwe:03d}" for cve, cwe in missing_reference_pairs],
        "extra_pairs": [f"{cve}::CWE-{cwe:03d}" for cve, cwe in extra_reference_pairs],
    }
    published_summaries: list[dict[str, Any]] = []
    for summary in published.get("references", []):
        if not isinstance(summary, dict):
            continue
        records = _jsonl(root / str(summary["output"]))
        aligned = [
            record
            for record in records
            if len(pair := _evaluation_pairs([record])) == 1 and pair <= frozen_pairs
        ]
        published_summaries.append(
            {
                **summary,
                "frozen_pair_records": len(aligned),
                "frozen_pair_detected": sum(record.get("detected") is True for record in aligned),
            }
        )
    locally_exercised = len(
        {
            identity
            for record in [*codeql_complete, *iris_complete]
            if (identity := _record_identity(record)) is not None
        }
    )

    checks = {
        "frozen_legacy_and_v2_snapshots": len(datasets) == 2
        and {item.get("track") for item in datasets} == {"legacy", "v2"},
        "runtime_ground_truth_boundary_materialized": runtime_ready,
        "toolchain_ready_for_smoke": bool(toolchain.get("ready_smoke")),
        "evaluator_implementation_and_regressions_present": (
            root / "src" / "openiris" / "evaluation" / "evaluator.py"
        ).is_file()
        and (root / "tests" / "unit" / "test_evaluator.py").is_file(),
        "published_reference_alignment_understood": (
            len(frozen_pairs) == 120
            and len(published_codeql) == 121
            and len(reference_projects) == 120
            and not missing_reference_pairs
            and extra_reference_pairs == [("CVE-2021-21345", 94)]
        ),
        "local_codeql_smoke_complete": bool(codeql_complete),
        "local_codeql_smoke_matches_published_case": any(
            _matches_published_codeql(record, published_codeql) for record in codeql_complete
        ),
        "local_iris_configuration_complete": bool(iris_complete),
        "local_iris_token_usage_accounted": bool(iris_complete)
        and _token_receipt_valid(token_receipt, iris_complete),
        "primary_local_qwen_gguf_smoke_complete": bool(valid_model_smokes),
        "paper_scale_local_build_coverage": legacy_instances > 0
        and locally_exercised / legacy_instances >= 0.8,
        "paper_scale_codeql_baseline_complete": len(codeql_complete) >= legacy_instances > 0,
    }
    smoke_gate = all(
        checks[key]
        for key in (
            "frozen_legacy_and_v2_snapshots",
            "runtime_ground_truth_boundary_materialized",
            "toolchain_ready_for_smoke",
            "evaluator_implementation_and_regressions_present",
            "published_reference_alignment_understood",
            "local_codeql_smoke_complete",
            "local_codeql_smoke_matches_published_case",
            "local_iris_configuration_complete",
            "primary_local_qwen_gguf_smoke_complete",
        )
    )
    paper_gate = (
        smoke_gate
        and checks["paper_scale_local_build_coverage"]
        and checks["paper_scale_codeql_baseline_complete"]
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "PASS" if paper_gate else "SMOKE_PASS" if smoke_gate else "IN_PROGRESS",
        "scope": {
            "local_codeql_records": len(codeql_records),
            "local_codeql_complete": len(codeql_complete),
            "local_iris_records": len(iris_records),
            "local_iris_complete": len(iris_complete),
            "legacy_instances": legacy_instances,
            "locally_exercised_projects": locally_exercised,
        },
        "checks": checks,
        "datasets": datasets,
        "published_references": published_summaries,
        "published_reference_alignment": reference_alignment,
        "iris_token_usage": token_receipt,
        "primary_model": primary_model,
        "primary_model_smokes": model_smokes,
        "local_results": {"codeql": codeql_records, "iris": iris_records},
        "toolchain": toolchain,
        "interpretation": {
            "published_reference_is_local_rerun": False,
            "upstream_build_status_is_local_verification": False,
            "smoke_gate": smoke_gate,
            "paper_scale_gate": paper_gate,
        },
    }


def _mark(value: bool) -> str:
    return "PASS" if value else "PENDING"


def render_markdown(report: dict[str, Any]) -> str:
    datasets = report["datasets"]
    token_usage = report.get("iris_token_usage", {})
    model_smokes = report.get("primary_model_smokes", [])
    lines = [
        "# Phase 0 execution report",
        "",
        f"Generated: `{report['generated_at']}`  ",
        f"Status: **{report['status']}**",
        "",
        "`SMOKE_PASS` means the reproducible single-project CodeQL and IRIS paths work. "
        "It does not mean that the 120-case paper baseline has been rerun.",
        "",
        "## Frozen datasets",
        "",
        "| Track | Commit | Instances | Repositories | Raw CWE labels | Semantic CWEs |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for item in datasets:
        lines.append(
            "| {track} | `{commit}` | {instances} | {repositories} | {raw} | {semantic} |".format(
                track=item["track"],
                commit=str(item["git_commit"])[:12],
                instances=item["num_instances"],
                repositories=item["num_unique_repositories"],
                raw=item["num_raw_cwe_labels"],
                semantic=item["num_cwes"],
            )
        )

    lines.extend(
        [
            "",
            "Build-success counts in the inventory reproduce upstream metadata; they are not "
            "local build results.",
            "",
            "## Gate checks",
            "",
            "| Check | Status |",
            "|---|---|",
        ]
    )
    for name, passed in report["checks"].items():
        lines.append(f"| `{name}` | {_mark(bool(passed))} |")

    scope = report["scope"]
    local_results = [
        *report["local_results"]["codeql"],
        *report["local_results"]["iris"],
    ]
    lines.extend(
        [
            "",
            "## Local execution scope",
            "",
            (
                f"- CodeQL: {scope['local_codeql_complete']}/"
                f"{scope['local_codeql_records']} complete records."
            ),
            (
                f"- IRIS: {scope['local_iris_complete']}/"
                f"{scope['local_iris_records']} complete records."
            ),
            (
                f"- IRIS token usage: {token_usage['prompt_tokens']:,} prompt + "
                f"{token_usage['completion_tokens']:,} completion = "
                f"{token_usage['total_tokens']:,} tokens (post-hoc pinned-tokenizer receipt)."
                if token_usage
                else "- IRIS token usage: no audited receipt."
            ),
            (
                f"- Locally exercised projects: {scope['locally_exercised_projects']}/"
                f"{scope['legacy_instances']} legacy cases."
            ),
            "- Primary Qwen 3B GGUF CUDA smokes: "
            f"{sum(item.get('status') == 'COMPLETE' for item in model_smokes)}/"
            f"{len(model_smokes)} complete.",
            "",
            "| Baseline | Run | Status | Project | Paths | Recall@method | Runtime (s) |",
            "|---|---|---|---|---:|---|---:|",
        ]
    )
    for item in local_results:
        metadata = item.get("metadata")
        upstream_project = (
            metadata.get("upstream_project_slug") if isinstance(metadata, dict) else None
        )
        project = upstream_project or item.get("project") or "-"
        paths = item.get("number_of_paths")
        detected = item.get("vulnerability_detected")
        runtime = item.get("runtime_seconds")
        lines.append(
            f"| {item.get('baseline', '-')} | `{item.get('run_id', '-')}` | "
            f"{item.get('status', '-')} | `{project}` | "
            f"{paths if paths is not None else '-'} | "
            f"{detected if detected is not None else '-'} | "
            f"{float(runtime):.1f} |"
        )

    lines.extend(
        [
            "",
            "## Declared limitations",
            "",
            "- The local scope is a reproducibility smoke, not the 120-case paper rerun; "
            "paper-scale checks stay pending until local evidence reaches their thresholds.",
            "- Upstream build-success metadata is inventory evidence only and is never "
            "reported as local build coverage.",
            "- Pinned IRIS v1 requires an oracle CWE query, a semantic project slug, and "
            "evaluator fix metadata. This is the declared `iris-v1-oracle-interface` "
            "compatibility exception, not a zero-hint run.",
            "- The legacy IRIS Qwen 1.5B smoke follows upstream FP16 loading and effective "
            "temperature "
            "0.01 with sampling disabled; the configured 4-bit field is retained as an "
            "unforwarded request, not claimed as the executed precision.",
            "- The upstream local-model path emits no counters. Zeroes in the immutable "
            "run usage stream are explicit sentinels; `results/phases/phase_00/audits/"
            "iris_qwen15b_token_usage.json` contains the audited post-hoc count.",
            "",
            "## Published comparison references",
            "",
            "The files under `results/phases/phase_00/baselines/published_reference/` are "
            "imported from the "
            "pinned IRIS commit. They are never counted as local reruns.",
            "",
            "| Source | Published rows | Published detected | Frozen-pair rows | "
            "Frozen-pair detected | Source commit |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    for item in report["published_references"]:
        lines.append(
            f"| {item['source_name']} | {item['num_records']} | {item['num_detected']} | "
            f"{item['frozen_pair_records']} | {item['frozen_pair_detected']} | "
            f"`{str(item['source_commit'])[:12]}` |"
        )

    alignment = report["published_reference_alignment"]
    lines.append("")
    if report["checks"]["published_reference_alignment_understood"]:
        lines.extend(
            [
                (
                    f"The pinned tables contain {alignment['published_rows']} project-CWE "
                    f"evaluation rows over {alignment['published_distinct_projects']} "
                    f"distinct projects. They cover all {alignment['frozen_pairs']} frozen "
                    "`(CVE, CWE)` pairs."
                ),
                (
                    "The sole additional published evaluation is "
                    f"`{alignment['extra_pairs'][0]}`: the same x-stream 1.4.15 project is "
                    "evaluated as CWE-094 in addition to its frozen CWE-078 label. Published "
                    "files remain verbatim; paper-scale denominators use the frozen 120 pairs."
                ),
            ]
        )
    else:
        lines.append(
            "Published-reference alignment could not be validated until the frozen "
            "ground-truth view is materialized."
        )

    lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```powershell",
            "uv sync --extra dev --locked",
            "uv run python scripts/data/bootstrap_upstream.py",
            "uv run python scripts/data/prepare_phase0.py",
            "uv run python scripts/toolchain/fetch_codeql.py",
            "uv run python scripts/toolchain/fetch_qwen_gguf.py",
            "docker build --platform linux/amd64 -t maxvera-phase0:jdk17 docker/phase0",
            (
                "docker build --platform linux/amd64 -f "
                "docker/phase0/Dockerfile.codeql -t maxvera-phase0:codeql tools/downloads"
            ),
            (
                "docker build --platform linux/amd64 -f "
                "docker/phase0/Dockerfile.iris -t maxvera-phase0:iris-local docker/phase0"
            ),
            "uv run openiris-doctor --config configs/toolchain/phase0.yaml --strict",
            "uv run pytest",
            "uv run python scripts/phase0.py",
            "```",
            "",
            "Use the append-only CodeQL and IRIS commands in `README.md` to create new "
            "local baseline records; every rerun needs fresh run IDs.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=PROJECT_ROOT)
    parser.add_argument(
        "--json-output", type=Path, default=Path("results/phases/phase_00/status.json")
    )
    parser.add_argument(
        "--markdown-output", type=Path, default=Path("results/phases/phase_00/report.md")
    )
    parser.add_argument("--strict-paper-gate", action="store_true")
    args = parser.parse_args()

    root = args.workspace.resolve()
    report = collect(root)
    json_output = _workspace_output(root, args.json_output)
    markdown_output = _workspace_output(root, args.markdown_output)
    write_json(json_output, report)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    print(json.dumps({"status": report["status"], "report": str(markdown_output)}, indent=2))
    return int(args.strict_paper_gate and report["status"] != "PASS")


def _workspace_output(root: Path, value: Path) -> Path:
    return value.resolve() if value.is_absolute() else (root / value).resolve()


if __name__ == "__main__":
    raise SystemExit(main())
