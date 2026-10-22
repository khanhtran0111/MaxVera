"""Evaluator-only metrics computed from frozen raw output, never analyzer imports."""

from __future__ import annotations

from collections import Counter

MATCH_POLICY_VERSION = "program-point-strong-span-v2.1"


def candidate_pool_hash(records: list[dict]) -> str:
    from maxvera.contracts import digest

    # Exclude run IDs, scores, ranks, LLM decisions and final verifier outcomes.
    keys = (
        "case_id",
        "snapshot_id",
        "candidate_id",
        "origin_generators",
        "locations",
        "source_node_id",
        "sink_node_id",
        "graph_path_edge_ids",
        "graph_path_node_ids",
        "discovery_status",
        "default_alert_overlap",
        "provenance",
    )
    content = [{key: c.get(key) for key in keys} for c in records]
    return digest(sorted(content, key=lambda c: (str(c["case_id"]), str(c["candidate_id"]))))


def condition_manifest(run, manifest, config, identity, labels_hash, truth_hash, protocol):
    import json

    source_records = {}
    for case_id in manifest["case_ids"]:
        for stage, name in [
            ("prepare", "snapshot.json"),
            ("ingest", "snapshot.json"),
            ("static_extract", "analyzed_snapshot.json"),
        ]:
            path = run / "stages" / case_id / stage / name
            if path.is_file():
                record = json.loads(path.read_text())
                source_records.setdefault(case_id, {})[stage] = {
                    k: record[k]
                    for k in ("source_hash", "snapshot_id", "analyzed_snapshot_id")
                    if k in record
                }
    return {
        "protocol": protocol,
        "mode": manifest["mode"],
        "case_ids": sorted(manifest["case_ids"]),
        "input_hash": manifest["input_hash"],
        "source_identities": source_records,
        "analyzer_implementation_hash": manifest["implementation_hash"],
        "tools": config.get("tool_fingerprints", {}),
        "evaluator_identity": identity,
        "labels_hash": labels_hash,
        "truth_hash": truth_hash,
        "conditions": {
            k: config.get(k) for k in ("budgets", "llm", "evidence", "dataset", "codeql")
        },
    }


def paper_aggregate(rows: list[dict], *, expected: int) -> dict:
    if len(rows) != expected or len({r["case_id"] for r in rows}) != expected:
        raise ValueError("missing/duplicate case coverage in evaluator")
    completed = [r for r in rows if r["status"] == "SUCCESS"]
    with_alerts = [r for r in completed if r["alerts"] > 0]
    detected = sum(bool(r["detected"]) for r in rows)
    f1 = []
    for row in rows:
        p = row["tp_alerts"] / row["alerts"] if row["alerts"] else 0
        recall = int(row["detected"])
        f1.append(2 * p * recall / (p + recall) if p + recall else 0)
    return {
        "detected": detected,
        "denominator_intention_to_analyze": expected,
        "detection_rate": detected / expected if expected else 0,
        "successfully_analyzed": len(completed),
        "detected_per_successful_analysis": detected / len(completed) if completed else 0,
        "avg_fdr": sum(1 - r["tp_alerts"] / r["alerts"] for r in with_alerts) / len(with_alerts)
        if with_alerts
        else None,
        "avg_fdr_denominator": len(with_alerts),
        "avg_f1": sum(f1) / expected if expected else 0,
        "avg_f1_denominator": expected,
        "statuses": dict(Counter(r["status"] for r in rows)),
    }


def _range(row):
    file = row.get("file")
    for start, end in [("method_start", "method_end"), ("class_start", "class_end")]:
        try:
            lo, hi = int(row.get(start, 0)), int(row.get(end, 0))
        except (ValueError, TypeError):
            continue
        if lo > 0 and hi >= lo:
            return file, lo, hi
    return file, None, None


def _location_match(locations, truth, *, require_span=False):
    for loc in locations:
        for row in truth:
            file, start, end = _range(row)
            if require_span and start is None:
                continue
            if file == loc["file"] and (
                start is None
                or (
                    int(loc["start_line"]) <= end
                    and int(loc.get("end_line", loc["start_line"])) >= start
                )
            ):
                return True
    return False


def _paper_case(root, run, case_id, stage, truth):
    import json
    import subprocess
    import sys

    from maxvera.evaluator_identity import verified_upstream

    folder = run / "stages" / case_id / stage
    record = folder / "stage.json"
    base = {
        "case_id": case_id,
        "status": "ANALYSIS_FAILED",
        "detected": False,
        "alerts": 0,
        "tp_alerts": 0,
    }
    if not record.exists() or json.loads(record.read_text())["status"] != "SUCCESS":
        return base
    data = json.loads(record.read_text())["result"]
    sarif = folder / data["sarif"]
    classes = folder / "class_locs_path.csv"
    methods = folder / "func_locs_path.csv"
    if not classes.is_file() or not methods.is_file():
        raise ValueError(
            "paper evaluator requires class/method inventory for each successful branch"
        )
    request = {
        "iris_root": str(root / "third_party/iris"),
        "sarif": str(sarif),
        "classes": str(classes),
        "methods": str(methods),
        "truth": truth,
        "upstream_identity": verified_upstream(root / "third_party/iris"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "maxvera.evaluator_worker"],
        cwd=root,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode:
        raise ValueError("upstream paper evaluator failed; inspect class/method/fix metadata")
    lines = [line for line in result.stdout.splitlines() if line.startswith("MAXVERA_METRIC=")]
    if not lines:
        raise ValueError("upstream evaluator produced no metric")
    metric = json.loads(lines[-1].split("=", 1)[1])
    return {
        **base,
        "status": "SUCCESS",
        "detected": bool(metric["recall_method"]),
        "alerts": metric["num_results"],
        "tp_alerts": metric["num_tp_results_method"],
        "upstream_metric": metric,
    }


def evaluate(root, run, protocol, *, labels, truth):
    import csv
    import json
    from collections import defaultdict
    from pathlib import Path

    import yaml

    from maxvera.contracts import digest
    from maxvera.orchestration import verify_checksums
    from src.common.provenance import sha256_file
    from src.reproduction.common import (
        atomic_json,
        atomic_jsonl,
        read_csv,
        read_jsonl,
        write_checksums,
    )

    run, root = Path(run).resolve(), Path(root).resolve()
    verify_checksums(run)  # Validate before any GT is read.
    state = (run / "STATUS").read_text().strip()
    if state not in {"COMPLETED", "COMPLETED_WITH_CASE_FAILURES"}:
        raise ValueError("evaluation requires a frozen terminal run")
    manifest = json.loads((run / "manifest.json").read_text())
    config = yaml.safe_load((run / "config.resolved.yaml").read_text())
    cases = read_jsonl(run / "cases.jsonl")
    ids = manifest["case_ids"]
    if len(cases) != len(ids) or {c["case_id"] for c in cases} != set(ids):
        raise ValueError("missing/duplicate final case accounting")
    label_rows = read_csv(Path(labels))
    label_index = {r["project_id"]: r for r in label_rows}
    truths = defaultdict(list)
    for row in read_jsonl(Path(truth)):
        truths[row["project_id"]].append(row)
    if set(ids) - label_index.keys() or set(ids) - truths.keys():
        raise ValueError("evaluator ground truth coverage incomplete")
    from maxvera.evaluator_identity import evaluator_identity

    identity = evaluator_identity(root, protocol, MATCH_POLICY_VERSION)
    labels_hash, truth_hash = sha256_file(Path(labels)), sha256_file(Path(truth))
    condition = condition_manifest(
        run, manifest, config, identity, labels_hash, truth_hash, protocol
    )
    output = root / "results/evaluations" / manifest["run_id"] / protocol
    if output.exists():
        verify_checksums(output)
        previous = json.loads((output / "evaluator_manifest.json").read_text())
        if (
            previous.get("evaluator_identity") != identity
            or previous["run_hash"] != sha256_file(run / "checksums.sha256")
            or previous["labels_hash"] != sha256_file(Path(labels))
            or previous["truth_hash"] != sha256_file(Path(truth))
        ):
            raise ValueError("immutable evaluator identity/input mismatch")
        return output
    import shutil
    import tempfile

    final_output = output
    final_output.parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="." + protocol + ".", dir=final_output.parent))
    try:
        rows = []
        if protocol == "iris_paper":
            if manifest["pipeline"] != "reproduction":
                raise ValueError("oracle paper protocol requires reproduction run")
            panels = {}
            for branch, stage in [("iris", "finalize"), ("codeql_reference", "codeql_reference")]:
                branch_rows = [_paper_case(root, run, c, stage, truths[c]) for c in ids]
                for row in branch_rows:
                    row.update(
                        {
                            "branch": branch,
                            "true_cwe": label_index[row["case_id"]]["ground_truth_cwe"],
                        }
                    )
                rows.extend(branch_rows)
                panels[branch] = paper_aggregate(branch_rows, expected=len(ids))
                panels[branch]["per_cwe"] = {
                    cwe: paper_aggregate(
                        [r for r in branch_rows if r["true_cwe"] == cwe],
                        expected=sum(r["true_cwe"] == cwe for r in branch_rows),
                    )
                    for cwe in sorted({r["true_cwe"] for r in branch_rows})
                }
            aggregate = {
                "panel": "oracle_reference",
                "cases": len(ids),
                "case_ids": ids,
                "branches": panels,
                "canonical_rows": len(ids),
                "artifact_121_view": "NOT_COMPUTED_NO_DUPLICATE_QUERY_RUN",
                "scope": "SMOKE_NOT_BENCHMARK"
                if manifest["mode"] == "smoke"
                else "dataset_canonical",
                "fidelity": "model-substituted; inspect reproduction_deviations.json",
            }
            atomic_json(output / "paper_compatible_metrics.json", aggregate)
        elif protocol == "zero_hint":
            if manifest["pipeline"] != "research":
                raise ValueError("zero_hint protocol requires research run")
            candidate_rows = read_jsonl(run / "candidates_pre_llm.jsonl")
            findings = read_jsonl(run / "findings.jsonl")
            candidates, finals = defaultdict(list), defaultdict(list)
            for c in candidate_rows:
                if c["case_id"] not in ids:
                    raise ValueError("candidate outside declared case selection")
                candidates[c["case_id"]].append(c)
            for c in findings:
                finals[c["case_id"]].append(c)
            for case in cases:
                cid = case["case_id"]
                cs = sorted(candidates[cid], key=lambda c: c["rank_pre_llm"])

                def strong(c, truth_rows=truths[cid]):
                    return (
                        c["discovery_status"] == "STATIC_CONFIRMED"
                        or (
                            c["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
                            and bool(c["graph_path_edge_ids"])
                        )
                    ) and _location_match(c["locations"], truth_rows, require_span=True)

                correct = [c for c in cs if strong(c)]
                rows.append(
                    {
                        "case_id": cid,
                        "status": case["status"],
                        "discovery_recall_at_k": {
                            str(k): any(c["rank_pre_llm"] <= k for c in correct)
                            for k in (5, 10, 20)
                        },
                        "ranked_recall_at_k": None,
                        "first_correct_rank": min(
                            (c["rank_pre_llm"] for c in correct), default=None
                        ),
                        "weak_location_matches": sum(
                            _location_match(c["locations"], truths[cid]) and not strong(c)
                            for c in cs
                        ),
                        "verified_detected": any(
                            c.get("verification_status") == "FLOW_FOUND"
                            and _location_match(c["locations"], truths[cid], require_span=True)
                            for c in finals[cid]
                        ),
                        "candidate_count": len(cs),
                        "generator_contribution": dict(
                            Counter(g for c in correct for g in c["origin_generators"])
                        ),
                        "outside_default_alerts": sum(
                            c.get("default_alert_overlap") is False for c in cs
                        ),
                    }
                )
            aggregate = {
                "panel": "zero_hint",
                "cases": len(ids),
                "case_ids": ids,
                "candidate_pool_hash": candidate_pool_hash(
                    read_jsonl(run / "candidates_raw.jsonl")
                    if (run / "candidates_raw.jsonl").is_file()
                    else candidate_rows
                ),
                "discovery_recall_at_k": {
                    str(k): sum(r["discovery_recall_at_k"][str(k)] for r in rows) / len(ids)
                    for k in (5, 10, 20)
                },
                "ranked_recall_at_k": None,
                "verified_detection_rate": sum(r["verified_detected"] for r in rows) / len(ids),
                "unmatched_label_status": "UNKNOWN_UNREVIEWED",
                "precision_fdr": "NOT_ESTIMATED_WITHOUT_ADJUDICATED_NEGATIVES",
                "statuses": dict(Counter(c["status"] for c in cases)),
                "track": config.get("dataset", {}).get("track", "UNKNOWN"),
                "scope": "SMOKE_NOT_BENCHMARK"
                if manifest["mode"] == "smoke"
                else "development_exploratory",
                "candidate_count": sum(r["candidate_count"] for r in rows),
                "outside_default_alerts": sum(r["outside_default_alerts"] for r in rows),
            }
        else:
            raise ValueError("unsupported evaluation protocol")
        aggregate["condition_manifest"] = condition
        aggregate["condition_hash"] = digest(condition)
        atomic_jsonl(output / "metrics_per_case.jsonl", rows)
        atomic_json(output / "metrics_aggregate.json", aggregate)
        atomic_json(
            output / "evaluator_manifest.json",
            {
                "schema_version": "2.0",
                "protocol": protocol,
                "evaluator_identity": identity,
                "condition_hash": digest(condition),
                "run_hash": sha256_file(run / "checksums.sha256"),
                "labels_hash": sha256_file(Path(labels)),
                "truth_hash": sha256_file(Path(truth)),
                "raw_outputs_modified": False,
            },
        )
        table = output / "tables"
        table.mkdir()
        with (table / "cases.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["case_id", "status"])
            writer.writeheader()
            writer.writerows({k: r[k] for k in ("case_id", "status")} for r in rows)
        write_checksums(output)
        import os

        os.rename(output, final_output)
        return final_output
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def compare(evaluations, output, *, paired_llm=False):
    import csv
    import json
    from pathlib import Path

    from maxvera.orchestration import verify_checksums
    from src.reproduction.common import atomic_json, write_checksums

    for path in evaluations:
        verify_checksums(Path(path))
    metrics = [json.loads((Path(p) / "metrics_aggregate.json").read_text()) for p in evaluations]
    from maxvera.contracts import digest

    if any(
        not m.get("condition_manifest")
        or m.get("condition_hash") != digest(m["condition_manifest"])
        for m in metrics
    ):
        raise ValueError("comparison requires explicit consistent condition/input identity")
    if len(metrics) < 2:
        raise ValueError("comparison requires at least two runs")
    panels = {m["panel"] for m in metrics}
    if len(panels) != 1:
        raise ValueError("oracle references and zero-hint methods require separate panels")
    if any(set(m["case_ids"]) != set(metrics[0]["case_ids"]) for m in metrics[1:]):
        raise ValueError("comparison case IDs are not paired")
    if any(m.get("condition_hash") != metrics[0].get("condition_hash") for m in metrics[1:]):
        raise ValueError("comparison budgets/dataset/query/model conditions differ")
    if paired_llm and any(
        m.get("candidate_pool_hash") != metrics[0].get("candidate_pool_hash") for m in metrics[1:]
    ):
        raise ValueError("paired LLM comparison requires identical frozen candidate pool")
    output = Path(output)
    if output.exists():
        raise ValueError("comparison output already exists")
    output.mkdir(parents=True)
    atomic_json(
        output / "comparison.json",
        {
            "panel": metrics[0]["panel"],
            "paired_llm": paired_llm,
            "causal_claim": False,
            "runs": metrics,
        },
    )
    with (output / "comparison.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["evaluation", "cases", "candidate_recall_at_5", "verified_detection_rate"])
        for p, m in zip(evaluations, metrics, strict=False):
            writer.writerow(
                [
                    str(p),
                    m["cases"],
                    m.get("discovery_recall_at_k", {}).get("5"),
                    m.get("verified_detection_rate"),
                ]
            )
    write_checksums(output)
    return output
