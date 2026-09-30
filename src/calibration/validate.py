"""Validate Phase 12 calibration and selective-routing artifacts."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.calibration.model import calibration_metrics, route
from src.common.provenance import sha256_file
from src.reproduction.common import read_jsonl

REQUIRED = {
    "STATUS",
    "calibration_summary.json",
    "candidate_metrics.json",
    "checksums.sha256",
    "command.txt",
    "config.resolved.yaml",
    "environment.json",
    "features.jsonl",
    "manifest.json",
    "model.json",
    "oof_predictions.jsonl",
    "risk_coverage.jsonl",
    "routing_decisions.jsonl",
    "thresholds.json",
}


def _json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], loaded)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"expected mapping for {label}")
    return cast(Mapping[str, Any], value)


def _validate_checksums(run_root: Path) -> None:
    indexed: set[str] = set()
    for line in (run_root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        target = run_root / relative
        if not target.is_file() or sha256_file(target) != digest:
            raise ValueError(f"Phase 12 checksum mismatch: {relative}")
        indexed.add(relative)
    actual = {
        path.relative_to(run_root).as_posix()
        for path in run_root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    if indexed != actual:
        raise ValueError("Phase 12 checksum coverage mismatch")


def validate(run_root: Path, *, repo_root: Path | None = None) -> str:
    missing = sorted(name for name in REQUIRED if not (run_root / name).is_file())
    if missing:
        raise ValueError(f"missing Phase 12 outputs: {', '.join(missing)}")
    if (run_root / "STATUS").read_text(encoding="utf-8").strip() != "PASS":
        raise ValueError("Phase 12 status is not PASS")
    _validate_checksums(run_root)

    manifest = _json(run_root / "manifest.json")
    if (
        manifest.get("phase") != 12
        or manifest.get("run_id") != run_root.name
        or manifest.get("data_role") != "evaluator"
        or manifest.get("locked_test_used") is not False
    ):
        raise ValueError("not a development-only Phase 12 evaluator artifact")
    if repo_root is not None:
        config = _mapping(manifest["config"], "manifest config")
        config_path = repo_root / str(config["path"])
        if not config_path.is_file() or sha256_file(config_path) != config["sha256"]:
            raise ValueError("Phase 12 config lock mismatch")

    resolved = yaml.safe_load((run_root / "config.resolved.yaml").read_text(encoding="utf-8"))
    if not isinstance(resolved, Mapping):
        raise ValueError("invalid resolved Phase 12 config")
    features = read_jsonl(run_root / "features.jsonl")
    predictions = read_jsonl(run_root / "oof_predictions.jsonl")
    decisions = read_jsonl(run_root / "routing_decisions.jsonl")
    curve = read_jsonl(run_root / "risk_coverage.jsonl")
    summary = _json(run_root / "calibration_summary.json")
    candidate_report = _json(run_root / "candidate_metrics.json")
    thresholds = _json(run_root / "thresholds.json")
    model = _json(run_root / "model.json")
    if not features or not (len(features) == len(predictions) == len(decisions) == len(curve)):
        raise ValueError("Phase 12 row coverage mismatch")
    if any(row.get("phase11_status") != "VERIFIED_DIFFERENTIAL" for row in features):
        raise ValueError("Phase 12 included a non-differential or unverified row")
    keys = [(str(row["project_id"]), str(row["specification_id"])) for row in features]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate Phase 12 finding")
    prediction_keys = [
        (str(row["project_id"]), str(row["specification_id"])) for row in predictions
    ]
    decision_keys = [
        (str(row["project_id"]), str(row["specification_id"])) for row in decisions
    ]
    if keys != prediction_keys or keys != decision_keys:
        raise ValueError("Phase 12 feature/prediction/decision identity mismatch")

    selected = str(candidate_report["selected_model"])
    if selected != thresholds["selected_model"] or selected != model["model_name"]:
        raise ValueError("Phase 12 selected model mismatch")
    candidates = _mapping(candidate_report["candidates"], "candidate metrics")
    if set(candidates) != {"platt", "isotonic", "logistic"}:
        raise ValueError("Phase 12 calibrator comparison is incomplete")
    selection = min(
        candidates,
        key=lambda name: (
            float(_mapping(candidates[name], name)["brier"]),
            float(_mapping(candidates[name], name)["ece_equal_width"]),
            float(_mapping(candidates[name], name)["aurc"]),
            name,
        ),
    )
    if selected != selection:
        raise ValueError("Phase 12 selected model does not follow frozen selection order")
    labels = [int(row["target"]) for row in predictions]
    probabilities = [
        float(_mapping(row["probabilities"], "probabilities")[selected])
        for row in predictions
    ]
    bins = int(_mapping(resolved["calibration"], "calibration")["ece_bins"])
    recomputed = calibration_metrics(probabilities, labels, bins)
    selected_metrics = _mapping(candidates[selected], "selected metrics")
    for name, value in recomputed.items():
        if not math.isclose(value, float(selected_metrics[name]), rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError(f"Phase 12 metric mismatch: {name}")

    tau_accept = float(thresholds["tau_accept"])
    tau_verify = float(thresholds["tau_verify"])
    tau_abstain = float(thresholds["tau_abstain"])
    if not 0.0 <= tau_abstain <= tau_verify <= tau_accept <= 1.0:
        raise ValueError("Phase 12 threshold ordering is invalid")
    if thresholds.get("locked_test_used") is not False:
        raise ValueError("Phase 12 thresholds used locked-test data")
    expected_decisions = [route(probability, thresholds) for probability in probabilities]
    actual_decisions = [str(row["decision"]) for row in decisions]
    if actual_decisions != expected_decisions:
        raise ValueError("Phase 12 routing decision mismatch")
    expected_tiers = [
        "HIGH_CONFIDENCE"
        if decision == "ABSTAIN" and probability <= tau_abstain
        else "CONSERVATIVE"
        if decision == "ABSTAIN"
        else None
        for probability, decision in zip(probabilities, expected_decisions, strict=True)
    ]
    if [row.get("abstain_tier") for row in decisions] != expected_tiers:
        raise ValueError("Phase 12 abstention tier mismatch")
    if any(
        row.get("evaluated_as_negative") is not False
        for row in decisions
        if row.get("decision") == "ABSTAIN"
    ):
        raise ValueError("Phase 12 ABSTAIN was evaluated as a negative")
    if summary.get("unverified_treated_as_negative") is not False:
        raise ValueError("Phase 12 summary violates the unverified-label policy")
    if summary.get("locked_test_used") is not False:
        raise ValueError("Phase 12 summary reports locked-test use")
    if int(summary["eligible_findings"]) != len(features):
        raise ValueError("Phase 12 summary finding count mismatch")
    if dict(sorted(Counter(actual_decisions).items())) != summary["decision_counts"]:
        raise ValueError("Phase 12 decision count mismatch")
    if int(summary["positive_labels"]) != sum(labels):
        raise ValueError("Phase 12 positive label count mismatch")
    return (
        f"PASS: Phase 12 {selected} calibration "
        f"({len(features)} differential findings, {sum(labels)} positives)"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(validate(args.run_root.resolve(), repo_root=args.repo_root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
