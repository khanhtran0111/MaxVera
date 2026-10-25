"""Evaluator-only metrics computed from frozen raw output, never analyzer imports."""

from __future__ import annotations

from collections import Counter

MATCH_POLICY_VERSION = "program-point-strong-span-v3-vulnerable-alignment"
ORACLE_PROTOCOLS = frozenset({"iris_paper", "legacy_artifact", "paper_formula_path"})


def metric_semantics(protocol: str) -> dict:
    """Both protocols use pinned IRIS matching; only the counted unit differs."""
    if protocol not in ORACLE_PROTOCOLS:
        raise ValueError("unsupported oracle evaluation protocol")
    path_based = protocol == "paper_formula_path"
    return {
        "canonical_protocol": "paper_formula_path" if path_based else "legacy_artifact",
        "metric_unit": "path" if path_based else "alert_container",
        "precision_denominator": "num_paths" if path_based else "num_results",
        "precision_numerator": "num_tp_paths_method" if path_based else "num_tp_results_method",
        "path_matching": "PINNED_IRIS_INCLUDING_UPSTREAM_IGNORE_CODE_FLOW",
        "fdr_eligibility": "SUCCESS_WITH_POSITIVE_DENOMINATOR",
        "recall_denominator": "ALL_SELECTED_CASES_INCLUDING_ANALYSIS_FAILURES",
        "missing_ground_truth_policy": "ERROR_WITH_CASE_IDS",
    }


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
    for candidate in content:
        if isinstance(candidate["provenance"], dict):
            # Full build identity remains in each frozen candidate and run checksum.
            # Paired pool identity compares semantic evidence, excluding volatile
            # bookkeeping bytes already separated by the extractor.
            candidate["provenance"] = {
                key: value
                for key, value in candidate["provenance"].items()
                if key != "analyzed_snapshot_id"
            }
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
                keys = ("source_hash", "snapshot_id", "analyzed_snapshot_id")
                if protocol == "zero_hint" and record.get("semantic_snapshot_id"):
                    keys = ("semantic_snapshot_id",)
                source_records.setdefault(case_id, {})[stage] = {
                    k: record[k] for k in keys if k in record
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

    # Old callers supply only alert counts; named protocols also carry their
    # explicit metric units so the raw alert/path inventories retain their names.
    def denominator(row):
        return row.get("metric_denominator", row["alerts"])

    def numerator(row):
        return row.get("metric_numerator", row["tp_alerts"])

    with_alerts = [r for r in completed if denominator(r) > 0]
    detected = sum(bool(r["detected"]) for r in rows)
    f1 = []
    for row in rows:
        p = numerator(row) / denominator(row) if denominator(row) else 0
        recall = int(row["detected"])
        f1.append(2 * p * recall / (p + recall) if p + recall else 0)
    return {
        "detected": detected,
        "denominator_intention_to_analyze": expected,
        "detection_rate": detected / expected if expected else 0,
        "successfully_analyzed": len(completed),
        "detected_per_successful_analysis": detected / len(completed) if completed else 0,
        "avg_fdr": sum(1 - numerator(r) / denominator(r) for r in with_alerts) / len(with_alerts)
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


def _paper_case(root, run, case_id, stage, truth, *, protocol="legacy_artifact"):
    import json
    import subprocess
    import sys

    from maxvera.evaluator_identity import verified_upstream

    semantics = metric_semantics(protocol)
    folder = run / "stages" / case_id / stage
    record = folder / "stage.json"
    base = {
        "case_id": case_id,
        "status": "ANALYSIS_FAILED",
        "detected": False,
        "alerts": 0,
        "tp_alerts": 0,
        "paths": 0,
        "tp_paths": 0,
        "metric_denominator": 0,
        "metric_numerator": 0,
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
        "paths": metric["num_paths"],
        "tp_paths": metric["num_tp_paths_method"],
        "metric_denominator": metric[semantics["precision_denominator"]],
        "metric_numerator": metric[semantics["precision_numerator"]],
        "upstream_metric": metric,
    }


def evaluate(
    root, run, protocol, *, labels, truth, missing_truth_policy="error", truth_alignment=None
):
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

    if protocol == "zero_hint":
        from maxvera.truth_alignment import _trusted_only

        _trusted_only()
    elif truth_alignment is not None:
        raise ValueError("truth alignment mappings are research-only")
    if missing_truth_policy not in {"error", "report"}:
        raise ValueError("unknown missing truth policy")
    if protocol != "zero_hint" and missing_truth_policy != "error":
        raise ValueError("report missing truth policy is research-only")
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
    missing_labels = sorted(set(ids) - label_index.keys())
    missing_truth = sorted(set(ids) - truths.keys())
    if (missing_labels or missing_truth) and missing_truth_policy == "error":
        raise ValueError(
            "evaluator ground truth coverage incomplete: "
            f"missing_label_case_ids={missing_labels}; missing_truth_case_ids={missing_truth}"
        )
    incomplete_labels = sorted(
        c for c in ids if c in label_index and not label_index[c].get("ground_truth_cwe")
    )
    incomplete_methods = (
        sorted(
            c
            for c in ids
            if any(not all(r.get(k) for k in ("file", "class", "method")) for r in truths[c])
        )
        if protocol in ORACLE_PROTOCOLS
        else []
    )
    if (incomplete_labels or incomplete_methods) and missing_truth_policy == "error":
        raise ValueError(
            "evaluator ground truth fields incomplete: "
            f"incomplete_label_case_ids={incomplete_labels}; "
            f"incomplete_method_case_ids={incomplete_methods}"
        )
    from maxvera.evaluator_identity import evaluator_identity

    identity = evaluator_identity(root, protocol, MATCH_POLICY_VERSION)
    labels_hash, truth_hash = sha256_file(Path(labels)), sha256_file(Path(truth))
    condition = condition_manifest(
        run, manifest, config, identity, labels_hash, truth_hash, protocol
    )
    condition["missing_truth_policy"] = missing_truth_policy
    missing_spans = sorted(
        cid
        for cid in ids
        if truths[cid]
        and not any(
            isinstance(row.get("file"), str) and row["file"] and _range(row)[1] is not None
            for row in truths[cid]
        )
    )
    # Original coordinate gaps remain diagnostic. A reviewed mapping may supply
    # a valid vulnerable-source span, so only aligned coverage controls scoring.
    unscorable = set(missing_labels + missing_truth + incomplete_labels)
    alignment = None
    alignment_identity = None
    original_truths = truths
    unaligned = []
    if protocol == "zero_hint":
        from maxvera.truth_alignment import alignment_report, load_mapping

        mapping, alignment_identity = load_mapping(truth_alignment, truth_hash)
        alignment, aligned_truths = alignment_report(
            root, [{"case_id": cid} for cid in ids], label_index, truths, run=run, mapping=mapping
        )
        unaligned = alignment["unaligned_case_ids"]
        if unaligned and missing_truth_policy == "error":
            raise ValueError(
                f"evaluator truth alignment incomplete: unaligned_truth_case_ids={unaligned}; "
                f"missing_span_case_ids={sorted(set(missing_spans) & set(unaligned))}"
            )
        unscorable.update(unaligned)
        truths = defaultdict(list, aligned_truths)
        condition["truth_alignment"] = alignment_identity
        condition["aligned_source_identities"] = {
            row["case_id"]: {
                k: row[k]
                for k in ("source_commit", "source_inventory_sha256", "preparation_manifest_sha256")
                if k in row
            }
            for row in alignment["cases"]
        }
    truth_coverage = {
        "selected_cases": len(ids),
        "evaluable_cases": len(ids) - len(unscorable),
        "missing_label_case_ids": missing_labels,
        "incomplete_label_case_ids": incomplete_labels,
        "missing_truth_case_ids": missing_truth,
        "missing_span_case_ids": missing_spans,
        "complete": not unscorable,
        "policy": missing_truth_policy,
        **({"alignment": alignment, "unaligned_truth_case_ids": unaligned} if alignment else {}),
    }
    from maxvera.truth_alignment import EVALUATION_NAMESPACE

    namespace = EVALUATION_NAMESPACE if protocol == "zero_hint" else protocol
    output = root / "results/evaluations" / manifest["run_id"] / namespace
    if protocol == "zero_hint":
        output = output / digest(condition)
    if output.exists():
        verify_checksums(output)
        previous = json.loads((output / "evaluator_manifest.json").read_text())
        if (
            previous.get("evaluator_identity") != identity
            or previous["run_hash"] != sha256_file(run / "checksums.sha256")
            or previous["labels_hash"] != sha256_file(Path(labels))
            or previous["truth_hash"] != sha256_file(Path(truth))
            or previous.get("missing_truth_policy", "error") != missing_truth_policy
            or previous.get("truth_alignment") != alignment_identity
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
        if protocol in ORACLE_PROTOCOLS:
            if manifest["pipeline"] != "reproduction":
                raise ValueError("oracle paper protocol requires reproduction run")
            panels = {}
            for branch, stage in [("iris", "finalize"), ("codeql_reference", "codeql_reference")]:
                branch_rows = [
                    _paper_case(root, run, c, stage, truths[c], protocol=protocol) for c in ids
                ]
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
                "metric_semantics": metric_semantics(protocol),
            }
            atomic_json(output / "paper_compatible_metrics.json", aggregate)
        elif protocol == "zero_hint":
            if manifest["pipeline"] != "research":
                raise ValueError("zero_hint protocol requires research run")
            candidate_rows = read_jsonl(run / "candidates_pre_llm.jsonl")
            raw_path = run / "candidates_raw.jsonl"
            raw_rows = read_jsonl(raw_path) if raw_path.is_file() else None
            raw_counts = Counter(c["case_id"] for c in raw_rows) if raw_rows is not None else None
            # Discovery freezes only the configured Top-K pool. Larger K values
            # cannot be recovered from that truncated ranking after analysis.
            cutoffs = sorted(set(config.get("evidence", {}).get("top_k", [5, 10, 20])))
            retained_cutoff = max(cutoffs)
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
                evaluable = cid not in unscorable
                ground_truth_status = (
                    "GT_MISSING"
                    if cid in missing_truth
                    else "GT_MISSING_LABEL"
                    if cid in missing_labels or cid in incomplete_labels
                    else "GT_MISSING_SPAN"
                    if cid in missing_spans and not evaluable
                    else "GT_UNALIGNED"
                    if not evaluable
                    else "AVAILABLE"
                )

                def strong(c, truth_rows=truths[cid]):
                    return (
                        c["discovery_status"] == "STATIC_CONFIRMED"
                        or (
                            c["discovery_status"] == "COMPLETE_CANDIDATE_PATH"
                            and (
                                bool(c["graph_path_edge_ids"])
                                or (
                                    isinstance(c.get("source_node_id"), str)
                                    and bool(c["source_node_id"])
                                    and c["source_node_id"] == c.get("sink_node_id")
                                    and c.get("graph_path_node_ids") == [c["source_node_id"]]
                                )
                            )
                        )
                    ) and _location_match(c["locations"], truth_rows, require_span=True)

                correct = [c for c in cs if strong(c)] if evaluable else []
                ranking_complete = False
                if config.get("selected_variant", {}).get("llm_enabled"):
                    stage = run / "stages" / cid / "llm_reason/stage.json"
                    assessment = json.loads(stage.read_text()) if stage.is_file() else {}
                    failed = assessment.get("result", {}).get("failed_assessments")
                    final = finals[cid]
                    ranking_complete = (
                        case["status"]
                        in {"SUCCESS", "COMPLETED_WITH_FINDINGS", "COMPLETED_NO_FINDINGS"}
                        and assessment.get("status") == "SUCCESS"
                        and type(failed) is int
                        and failed == 0
                        and len(final) == len(cs)
                        and {c["candidate_id"] for c in final} == {c["candidate_id"] for c in cs}
                        and all(type(c.get("rank_final")) is int for c in final)
                        and sorted(c["rank_final"] for c in final) == list(range(1, len(final) + 1))
                        and all(c.get("llm_assessment", {}).get("status") == "VALID" for c in final)
                    )
                ranked = (
                    {
                        str(k): any(c["rank_final"] <= k and strong(c) for c in finals[cid])
                        for k in cutoffs
                    }
                    if ranking_complete and evaluable
                    else None
                )
                rows.append(
                    {
                        "case_id": cid,
                        "status": case["status"],
                        "ground_truth_status": ground_truth_status,
                        "ground_truth_evaluable": evaluable,
                        "discovery_recall_at_k": {
                            str(k): any(c["rank_pre_llm"] <= k for c in correct) for k in cutoffs
                        }
                        if evaluable
                        else None,
                        "ranked_recall_at_k": ranked,
                        "ranking_complete": ranking_complete,
                        "first_correct_rank": min(
                            (c["rank_pre_llm"] for c in correct), default=None
                        ),
                        "weak_location_matches": sum(
                            _location_match(c["locations"], original_truths[cid]) and not strong(c)
                            for c in cs
                        ),
                        "verified_detected": any(
                            c.get("verification_status") == "FLOW_FOUND"
                            and _location_match(c["locations"], truths[cid], require_span=True)
                            for c in finals[cid]
                        )
                        if evaluable
                        else None,
                        "candidate_count": len(cs),
                        "retained_candidate_count": len(cs),
                        "raw_candidate_count": raw_counts[cid] if raw_counts is not None else None,
                        "retained_candidate_cutoff": retained_cutoff,
                        "candidate_pool_truncated": raw_counts[cid] > len(cs)
                        if raw_counts is not None
                        else None,
                        "generator_contribution": dict(
                            Counter(g for c in correct for g in c["origin_generators"])
                        ),
                        "outside_default_alerts": sum(
                            c.get("default_alert_overlap") is False for c in cs
                        ),
                    }
                )
            evaluable_rows = [r for r in rows if r["ground_truth_evaluable"]]

            def discovery_recall(selected):
                return (
                    {
                        str(k): sum(r["discovery_recall_at_k"][str(k)] for r in selected)
                        / len(selected)
                        for k in cutoffs
                    }
                    if selected
                    else None
                )

            def ranked_recall(selected):
                return (
                    {
                        str(k): sum(r["ranked_recall_at_k"][str(k)] for r in selected)
                        / len(selected)
                        for k in cutoffs
                    }
                    if selected and all(r["ranked_recall_at_k"] is not None for r in selected)
                    else None
                )

            aggregate = {
                "panel": "zero_hint",
                "cases": len(ids),
                "case_ids": ids,
                "candidate_pool_hash": candidate_pool_hash(
                    raw_rows if raw_rows is not None else candidate_rows
                ),
                "truth_coverage": truth_coverage,
                "discovery_recall_at_k": discovery_recall(rows) if not unscorable else None,
                "ranked_recall_at_k": ranked_recall(rows) if not unscorable else None,
                "ranking_complete_cases": sum(r["ranking_complete"] for r in rows),
                "verified_detection_rate": sum(r["verified_detected"] for r in rows) / len(ids)
                if not unscorable
                else None,
                "evaluable_subset": {
                    "denominator": len(evaluable_rows),
                    "case_ids": [r["case_id"] for r in evaluable_rows],
                    "discovery_recall_at_k": discovery_recall(evaluable_rows),
                    "ranked_recall_at_k": ranked_recall(evaluable_rows),
                    "verified_detection_rate": sum(r["verified_detected"] for r in evaluable_rows)
                    / len(evaluable_rows)
                    if evaluable_rows
                    else None,
                },
                "unmatched_label_status": "UNKNOWN_UNREVIEWED",
                "precision_fdr": "NOT_ESTIMATED_WITHOUT_ADJUDICATED_NEGATIVES",
                "statuses": dict(Counter(c["status"] for c in cases)),
                "track": config.get("dataset", {}).get("track", "UNKNOWN"),
                "scope": "SMOKE_NOT_BENCHMARK"
                if manifest["mode"] == "smoke"
                else "development_exploratory",
                "candidate_count": sum(r["candidate_count"] for r in rows),
                "retained_candidate_count": sum(r["retained_candidate_count"] for r in rows),
                "raw_candidate_count": len(raw_rows) if raw_rows is not None else None,
                "retained_candidate_cutoff": retained_cutoff,
                "candidate_pool_truncated": any(r["candidate_pool_truncated"] for r in rows)
                if raw_rows is not None
                else None,
                "outside_default_alerts": sum(r["outside_default_alerts"] for r in rows),
            }
        else:
            raise ValueError("unsupported evaluation protocol")
        aggregate["condition_manifest"] = condition
        aggregate["condition_hash"] = digest(condition)
        if protocol == "zero_hint":
            aggregate["build_provenance"] = {}
            for case_id in ids:
                provenance_path = run / "stages" / case_id / "static_extract/analyzed_snapshot.json"
                if provenance_path.is_file():
                    source = json.loads(provenance_path.read_text())
                    aggregate["build_provenance"][case_id] = {
                        key: source[key]
                        for key in (
                            "input_snapshot_id",
                            "analyzed_snapshot_id",
                            "semantic_snapshot_id",
                        )
                        if key in source
                    }
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
                "missing_truth_policy": missing_truth_policy,
                "truth_alignment": alignment_identity,
                "missing_ground_truth_policy": "ERROR_WITH_CASE_IDS"
                if missing_truth_policy == "error"
                else "REPORT_UNKNOWN_KEEP_SELECTED_COHORT",
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
                    (m.get("discovery_recall_at_k") or {}).get("5"),
                    m.get("verified_detection_rate"),
                ]
            )
    write_checksums(output)
    return output
