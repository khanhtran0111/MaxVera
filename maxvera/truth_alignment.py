"""Trusted evaluator-only binding of annotations to exact vulnerable source bytes.

Upstream fix coordinates are not presumed to describe the vulnerable commit. Every
annotation must either declare that exact commit, or have an explicit reviewed
mapping. A single unresolved annotation makes its entire case unscorable.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from maxvera.contracts import digest, redact
from maxvera.graph import relative_file
from maxvera.snapshots import semantic_inventory
from src.common.provenance import sha256_file

ALIGNMENT_POLICY_VERSION = "vulnerable-source-alignment-v1"
EVALUATION_NAMESPACE = "zero_hint_aligned_v1"
# Only statuses currently emitted by extraction/orchestration can prove that an
# inventory is absent because analysis failed. Future/active states stay unknown.
FAILED_EXTRACTION_STATUSES = frozenset(
    {
        "FETCH_FAILED",
        "BUILD_FAILED",
        "CODEQL_DB_FAILED",
        "ANALYSIS_FAILED",
        "TIMEOUT",
        "BLOCKED_BY_DEPENDENCY",
        "DATABASE_INTEGRITY_FAILED",
        "RESOURCE_EXHAUSTED",
    }
)


def _trusted_only():
    if os.environ.get("MAXVERA_DATA_ROLE") == "analysis":
        raise ValueError("truth alignment is unavailable inside the analyzer")


def _safe_file(directory: Path, name: str) -> Path:
    if not isinstance(name, str) or relative_file(name) != name:
        raise ValueError("noncanonical or unsafe relative source path")
    path = directory / name
    if any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(directory)):
        raise ValueError("source path contains a symlink")
    if not path.resolve().is_relative_to(directory.resolve()) or not path.is_file():
        raise ValueError("source file missing from exact vulnerable snapshot")
    return path


def _inventory(value):
    if not isinstance(value, dict) or not value:
        raise ValueError("source inventory missing")
    for name, content in value.items():
        if (
            not isinstance(name, str)
            or relative_file(name) != name
            or not isinstance(content, str)
            or re.fullmatch(r"[0-9a-f]{64}", content) is None
        ):
            raise ValueError("source inventory file/hash invalid")
    return value


def source_context(root: Path, case: dict, label: dict, *, run: Path | None = None) -> dict:
    """Load verified preparation identity from current input or a frozen run's copy."""
    _trusted_only()
    cid = case["case_id"]
    if run is None:
        from maxvera.dataset import validate_snapshot_manifest
        from maxvera.snapshots import source_inventory

        view = root / "data/processed/analysis_input"
        source = view / relative_file(case["source_dir"])
        if not source.resolve().is_relative_to(view.resolve()):
            raise ValueError("source path escapes trusted analysis input")
        if any(p.is_symlink() for p in (source, *source.parents) if p.is_relative_to(view)):
            raise ValueError("source path contains a symlink")
        record = validate_snapshot_manifest(source, cid)
        baseline = source_inventory(source)
        analyzed = baseline
    else:
        from maxvera.dataset import _validate_provenance

        base = run / "stages" / cid
        frozen = json.loads((base / "ingest/snapshot.json").read_text())
        baseline = _inventory(frozen["files"])
        if frozen.get("case_id") != cid or frozen.get("snapshot_id") != digest(baseline):
            raise ValueError("frozen input snapshot identity mismatch")
        source = base / "static_extract/workspace"
        analyzed_manifest = base / "static_extract/analyzed_snapshot.json"
        if analyzed_manifest.exists() or analyzed_manifest.is_symlink():
            if not source.is_dir():
                raise ValueError("analyzed inventory exists without its frozen workspace")
            if source.is_symlink():
                raise ValueError("frozen workspace contains a symlink")
            extracted = json.loads(analyzed_manifest.read_text())
            analyzed = _inventory(extracted["analyzed_files"])
            if extracted.get("input_snapshot_id") != digest(baseline) or extracted.get(
                "analyzed_snapshot_id"
            ) != digest(analyzed):
                raise ValueError("frozen analyzed source identity mismatch")
        else:
            checkpoint = json.loads((base / "static_extract/stage.json").read_text())
            status = checkpoint.get("status")
            if not isinstance(status, str) or status not in FAILED_EXTRACTION_STATUSES:
                raise ValueError("analyzed inventory missing without terminal extraction failure")
            # An analysis failure can still have trustworthy prepared input. Never
            # substitute a later source tree without proving the frozen inventory.
            from maxvera.dataset import validate_snapshot_manifest
            from maxvera.snapshots import source_inventory

            source = Path(frozen["source"])
            view = root / "data/processed/analysis_input"
            if not source.resolve().is_relative_to(view.resolve()):
                raise ValueError("frozen input source escapes trusted analysis input")
            if any(p.is_symlink() for p in (source, *source.parents) if p.is_relative_to(view)):
                raise ValueError("frozen input source contains a symlink")
            validate_snapshot_manifest(source, cid)
            if source_inventory(source) != baseline:
                raise ValueError("source changed since frozen ingest")
            analyzed = baseline
        manifest = _safe_file(source, "snapshot.files.json")
        if sha256_file(manifest) != baseline.get("snapshot.files.json"):
            raise ValueError("frozen preparation manifest hash mismatch")
        record = json.loads(manifest.read_text())
        if (
            record.get("schema_version") != "1.0"
            or record.get("case_id") != cid
            or record.get("files")
            != {k: v for k, v in baseline.items() if k != "snapshot.files.json"}
        ):
            raise ValueError("frozen preparation manifest inventory/identity mismatch")
        _validate_provenance(record["provenance"])
        if record["semantic_snapshot_id"] != digest(semantic_inventory(record["files"])):
            raise ValueError("frozen preparation semantic identity mismatch")
        if record["files"].get("build.runtime.json") != record["provenance"]["build_recipe_sha256"]:
            raise ValueError("frozen preparation build recipe identity mismatch")
    commit = record["provenance"]["source_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", label.get("buggy_commit_id", "")):
        raise ValueError("trusted label lacks exact vulnerable commit identity")
    if commit != label["buggy_commit_id"]:
        raise ValueError("prepared source differs from trusted vulnerable commit")
    return {
        "directory": source,
        "files": baseline,
        "analyzed_files": analyzed,
        "source_commit": commit,
        "source_inventory_sha256": digest(baseline),
        "preparation_manifest_sha256": sha256_file(_safe_file(source, "snapshot.files.json")),
    }


def load_mapping(path: Path | None, truth_sha256: str) -> tuple[dict, dict]:
    """Validate external review evidence and return immutable evaluator identity."""
    _trusted_only()
    if path is None:
        return {}, {"policy_version": ALIGNMENT_POLICY_VERSION, "mapping_sha256": None}
    path = Path(path)
    if path.is_symlink():
        raise ValueError("unsafe truth alignment mapping path")
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != "1.0"
        or data.get("policy_version") != ALIGNMENT_POLICY_VERSION
        or data.get("truth_sha256") != truth_sha256
        or not isinstance(data.get("cases"), list)
    ):
        raise ValueError("truth alignment mapping identity/schema mismatch")
    index = {}
    evidence_hashes = {}
    for case in data["cases"]:
        if not isinstance(case, dict):
            raise ValueError("truth alignment case must be an object")
        cid = case.get("case_id")
        if not isinstance(cid, str) or cid in index or not isinstance(case.get("mappings"), list):
            raise ValueError("duplicate/invalid truth alignment case")
        mappings = {}
        for item in case["mappings"]:
            if not isinstance(item, dict):
                raise ValueError("truth alignment mapping must be an object")
            key = item.get("truth_row_sha256")
            if (
                not isinstance(key, str)
                or not re.fullmatch(r"[0-9a-f]{64}", key)
                or key in mappings
            ):
                raise ValueError("duplicate/invalid truth alignment annotation identity")
            if (
                not isinstance(item.get("status"), str)
                or item["status"] not in {"MAPPED", "UNRESOLVED", "FIX_ONLY", "AMBIGUOUS"}
                or not isinstance(item.get("reviewed_by"), str)
                or not item["reviewed_by"].strip()
                or not isinstance(item.get("reason"), str)
                or not item["reason"].strip()
                or not isinstance(item.get("evidence"), dict)
            ):
                raise ValueError("truth alignment mapping requires explicit review provenance")
            evidence = item["evidence"]
            target = _safe_file(path.parent, evidence.get("file"))
            actual = sha256_file(target)
            if actual != evidence.get("sha256"):
                raise ValueError("truth alignment review evidence hash mismatch")
            evidence_hashes[evidence["file"]] = actual
            if item["status"] == "MAPPED":
                destination = item.get("target")
                if not isinstance(destination, dict):
                    raise ValueError("mapped annotation requires one exact target")
                content_hash = destination.get("sha256")
                if (
                    not isinstance(content_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", content_hash) is None
                ):
                    raise ValueError("mapped annotation target requires an exact SHA256 hash")
            mappings[key] = item
        index[cid] = {**case, "mapping_index": mappings}
    return index, {
        "policy_version": ALIGNMENT_POLICY_VERSION,
        "mapping_sha256": sha256_file(path),
        "review_evidence": evidence_hashes,
    }


def _validate_location(context: dict, file: str, start: int, end: int, expected_hash=None):
    path = _safe_file(context["directory"], file)
    original = context["files"].get(file)
    if original is None or context["analyzed_files"].get(file) != original:
        raise ValueError("truth file absent from input or changed during analysis")
    if sha256_file(path) != original or (expected_hash is not None and expected_hash != original):
        raise ValueError("truth source hash mismatch")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("truth span invalid")
    if end > len(path.read_bytes().splitlines()):
        raise ValueError("truth span exceeds vulnerable source line count")


def align_case(case_id: str, rows: list[dict], context: dict, mapping: dict | None = None):
    """Return all aligned rows, or no usable rows if any original row is unresolved."""
    from maxvera.evaluation import _range

    issues, aligned = [], []
    if mapping and (
        mapping.get("source_commit") != context["source_commit"]
        or mapping.get("source_inventory_sha256") != context["source_inventory_sha256"]
    ):
        return [], [
            {"code": "SOURCE_IDENTITY_MISMATCH", "message": "mapping/source identity mismatch"}
        ]
    if mapping and set(mapping.get("mapping_index", {})) - {digest(row) for row in rows}:
        return [], [
            {
                "code": "ANNOTATION_IDENTITY_MISMATCH",
                "message": "mapping references an annotation outside this exact truth case",
            }
        ]
    for row in rows:
        key = digest(row)
        reviewed = mapping.get("mapping_index", {}).get(key) if mapping else None
        try:
            if reviewed:
                if reviewed["status"] != "MAPPED":
                    issues.append(
                        {
                            "code": reviewed["status"],
                            "truth_row_sha256": key,
                            "message": reviewed["reason"],
                        }
                    )
                    continue
                target = reviewed["target"]
                file, start, end = target["file"], target["start_line"], target["end_line"]
                _validate_location(context, file, start, end, target["sha256"])
            else:
                file, start, end = _range(row)
                _validate_location(context, file, start, end)
                if row.get("commit") != context["source_commit"]:
                    raise ValueError(
                        "annotation commit is not the exact vulnerable commit; "
                        "reviewed mapping required"
                    )
            aligned.append(
                {
                    "project_id": case_id,
                    "file": file,
                    "method_start": start,
                    "method_end": end,
                    "commit": context["source_commit"],
                }
            )
        except (ValueError, TypeError, OSError, KeyError) as error:
            issues.append(
                {"code": "TRUTH_UNALIGNED", "truth_row_sha256": key, "message": redact(str(error))}
            )
    return ([], issues) if issues else (aligned, [])


def alignment_report(root, cases, labels, truths, *, run=None, mapping=None):
    _trusted_only()
    result, usable = [], {}
    for case in cases:
        cid = case["case_id"]
        row = {
            "case_id": cid,
            "aligned": False,
            "annotation_rows": len(truths.get(cid, [])),
            "annotation_commits": sorted({str(r.get("commit", "")) for r in truths.get(cid, [])}),
            "aligned_rows": 0,
            "issues": [],
        }
        try:
            context = source_context(root, case, labels.get(cid, {}), run=run)
            row.update(
                {
                    k: context[k]
                    for k in (
                        "source_commit",
                        "source_inventory_sha256",
                        "preparation_manifest_sha256",
                    )
                }
            )
            usable[cid], row["issues"] = align_case(
                cid, truths.get(cid, []), context, (mapping or {}).get(cid)
            )
            row["aligned_rows"] = len(usable[cid])
            row["aligned"] = bool(usable[cid]) and not row["issues"]
        except (ValueError, TypeError, OSError, KeyError) as error:
            row["issues"] = [{"code": "TRUSTED_SOURCE_UNAVAILABLE", "message": redact(str(error))}]
            usable[cid] = []
        result.append(row)
    return {
        "policy_version": ALIGNMENT_POLICY_VERSION,
        "selected_cases": len(result),
        "aligned_cases": sum(r["aligned"] for r in result),
        "unaligned_case_ids": sorted(r["case_id"] for r in result if not r["aligned"]),
        "ready": bool(result) and all(r["aligned"] for r in result),
        "cases": result,
    }, usable
