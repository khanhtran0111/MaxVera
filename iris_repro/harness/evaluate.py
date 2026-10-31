"""Project-level and aggregate metrics for a run (see metrics_lib.py for definitions).

Inputs : runs/<run_id>/cases/<eval_id>/{b0,b2}.json (IRIS evaluator output embedded by run_case.py)
Outputs: runs/<run_id>/metrics/
  project_metrics.csv                one row per (evaluation row, configuration)
  raw_vs_filtered.csv                B2 before vs after LLM contextual filtering, per row
  per_cwe_results.csv                per-CWE detection counts for each policy/configuration
  metrics_artifact_compatible.json   all evaluation rows (121 for a full run, incl. CVE-2021-21345 under CWE-094)
  metrics_dataset_canonical.json     the 120 canonical cases, each under its dataset CWE
  operational_metrics.json           build/db/spec/query/e2e success rates, runtimes, failure and miss causes
  token_cost_report.json, token_cost_by_project.csv
Configurations: b0 (CodeQL), b2_raw (IRIS before contextual filtering = results_pp.sarif),
b2_filtered (IRIS after contextual filtering = posthoc-filter results.sarif; the paper's IRIS numbers).
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (REPO_ROOT, IRIS_DIR, DATASET_STATE_DIR, load_json, dump_json, write_csv_dicts, run_dir, now_iso,  # noqa: E402
                    sha256_file)
from metrics_lib import row_metrics, aggregate, artifact_csv_rows  # noqa: E402
from orchestrate import cohort_rows  # noqa: E402

CONFIGS = ("b0", "b2_raw", "b2_filtered")
PAPER_TABLE1 = {"CodeQL": {"detected": 27, "avg_fdr": 0.9003, "avg_f1": 0.076},
                "IRIS + GPT-4": {"detected": 55, "avg_fdr": 0.8482, "avg_f1": 0.177}}


def collect(rdir, rows):
    out = []
    for row in rows:
        ds = load_json(os.path.join(DATASET_STATE_DIR, "status", f"{row['slug']}.json"), {}) or {}
        db_ok = (ds.get("db") or {}).get("status") == "ok"
        b0 = load_json(os.path.join(rdir, "cases", row["eval_id"], "b0.json"), {}) or {}
        b2 = load_json(os.path.join(rdir, "cases", row["eval_id"], "b2.json"), {}) or {}
        for cfg in CONFIGS:
            rec = b0 if cfg == "b0" else b2
            status = rec.get("status") or ("not_run_db_failed" if not db_ok and ds else "pending")
            ev = rec.get("evaluation") or {}
            if cfg == "b2_raw":
                ev = ev.get("vanilla_result")
            elif cfg == "b2_filtered":
                ev = ev.get("posthoc_filter_result")
            m = row_metrics(ev) if status == "completed" else None
            r = {"eval_id": row["eval_id"], "slug": row["slug"], "cve": row["cve_id"], "cwe": row["cwe"],
                 "dataset_cwe": row["dataset_cwe"], "canonical": row["canonical"], "config": cfg, "status": status}
            if m:
                r.update(m)
            else:
                r.update({"alerts": 0, "paths": 0, "tp_alerts": 0, "tp_paths": 0, "recall": 0,
                          "precision": None, "f1": 0.0, "recall_file": 0})
            r["failure_stage"] = (rec.get("failure") or {}).get("stage")
            r["failure_reason"] = (ds.get("db") or {}).get("reason") if not db_ok and ds else None
            out.append(r)
    return out


def policy_metrics(prow, policy):
    res = {}
    for cfg in CONFIGS:
        sub = [r for r in prow if r["config"] == cfg and (policy == "artifact_compatible" or r["canonical"])]
        res[cfg] = aggregate(sub)
    return res


def miss_causes(prow, structural):
    """Classify B2 (filtered) misses among completed rows."""
    by = collections.defaultdict(dict)
    for r in prow:
        by[r["eval_id"]][r["config"]] = r
    causes = collections.Counter()
    detail = {}
    for eid, d in by.items():
        f, raw = d.get("b2_filtered"), d.get("b2_raw")
        if not f or f["status"] != "completed" or f["recall"] == 1:
            continue
        if f["slug"] in structural:
            c = "no evaluable fixed method in fix_info.csv (undetectable under evaluator)"
        elif raw["alerts"] == 0:
            c = "no CodeQL alerts with inferred specifications"
        elif raw["recall"] == 0:
            c = "alerts found but no path through a fixed method"
        else:
            c = "true-positive path removed by contextual filtering"
        causes[c] += 1
        detail[eid] = c
    return dict(causes), detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()
    rdir = run_dir(args.run_id)
    manifest = load_json(os.path.join(rdir, "run_manifest.json"))
    rows = cohort_rows(manifest["cohort"], manifest.get("projects"))
    mdir = os.path.join(rdir, "metrics")
    prow = collect(rdir, rows)

    write_csv_dicts(prow, os.path.join(mdir, "project_metrics.csv"),
                    ["eval_id", "slug", "cve", "cwe", "dataset_cwe", "canonical", "config", "status", "alerts", "paths",
                     "tp_alerts", "tp_paths", "recall", "precision", "f1", "recall_file", "failure_stage", "failure_reason"])

    # Raw vs filtered
    rvf = []
    by = collections.defaultdict(dict)
    for r in prow:
        by[r["eval_id"]][r["config"]] = r
    for eid, d in by.items():
        raw, fil = d["b2_raw"], d["b2_filtered"]
        rvf.append({"eval_id": eid, "cwe": raw["cwe"], "status": raw["status"],
                    "raw_alerts": raw["alerts"], "raw_paths": raw["paths"], "raw_recall": raw["recall"],
                    "raw_precision": raw["precision"], "filtered_alerts": fil["alerts"], "filtered_paths": fil["paths"],
                    "filtered_recall": fil["recall"], "filtered_precision": fil["precision"],
                    "lost_detection": int(raw["recall"] == 1 and fil["recall"] == 0),
                    "paths_removed": raw["paths"] - fil["paths"]})
    write_csv_dicts(rvf, os.path.join(mdir, "raw_vs_filtered.csv"))

    dm = load_json(os.path.join(DATASET_STATE_DIR, "dataset_manifest.json"), {}) or {}
    structural = set((dm.get("counts") or {}).get("cases_without_evaluable_fixed_method", []))

    ref = {}
    for name, fn in (("CodeQL", "CodeQL.csv"), ("IRIS + GPT-4", "IRIS+GPT-4.csv")):
        rs = artifact_csv_rows(os.path.join(IRIS_DIR, "results", fn))
        ref[name] = {"artifact_121_rows": aggregate(rs),
                     "canonical_120_rows": aggregate([r for r in rs if r["eval_id"] != "CVE-2021-21345/CWE-094"]),
                     "paper_table1": PAPER_TABLE1[name], "source_file": f"vendor/iris-v1/results/{fn}"}
    for r in ref.values():
        for k in ("artifact_121_rows", "canonical_120_rows"):
            r[k].pop("not_completed", None)

    per_cwe_rows = []
    for policy in ("artifact_compatible", "dataset_canonical"):
        pm = policy_metrics(prow, policy)
        out = {
            "run_id": args.run_id, "generated": now_iso(), "policy": policy, "cohort": manifest["cohort"],
            "official": manifest.get("official", False),
            "row_definition": ("every evaluation row of the run, including x-stream CVE-2021-21345 evaluated under "
                               "CWE-094 (121 rows in a full run, matching vendor/iris-v1/results/*.csv)")
            if policy == "artifact_compatible" else
            "the 120 canonical CWE-Bench-Java cases, each evaluated only under its dataset CWE",
            "metric_policy": {
                "detected": "rows with Recall == 1 (fixed-method intersection, IRIS evaluator)",
                "avg_fdr": "mean of (1 - TP Alerts/Alerts) over completed rows with Alerts > 0",
                "avg_f1": "mean F1 over all rows; rows without alerts or not completed contribute 0",
                "not_completed_rows": "counted as not detected and F1 = 0, excluded from AvgFDR; listed explicitly",
                "micro_fdr_NOT_PAPER_METRIC": "1 - sum(TP Alerts)/sum(Alerts); global, not the paper's AvgFDR",
            },
            "configs": pm,
            "reference_from_original_artifact_csv": ref,
            "inputs_sha256": {"project_metrics.csv": sha256_file(os.path.join(mdir, "project_metrics.csv"))},
        }
        dump_json(out, os.path.join(mdir, f"metrics_{policy}.json"))
        for cfg in CONFIGS:
            for cwe, v in pm[cfg]["per_cwe"].items():
                per_cwe_rows.append({"policy": policy, "config": cfg, "cwe": cwe, **v})
    write_csv_dicts(per_cwe_rows, os.path.join(mdir, "per_cwe_results.csv"))

    # Operational metrics
    slugs = sorted({r["slug"] for r in rows})
    ds = {s: load_json(os.path.join(DATASET_STATE_DIR, "status", f"{s}.json"), {}) or {} for s in slugs}
    cases = {r["eval_id"]: {c: load_json(os.path.join(rdir, "cases", r["eval_id"], f"{c}.json"), {}) or {}
                            for c in ("b0", "b2")} for r in rows}
    n_rows = len(rows)

    def rate(k, n):
        return {"count": k, "n": n, "rate": (k / n) if n else None}

    b2s = [c["b2"] for c in cases.values()]
    stage = lambda s: sum(1 for c in b2s if (c.get("stages") or {}).get(s))  # noqa: E731
    fail_causes = collections.Counter()
    for eid, c in cases.items():
        for cfg in ("b0", "b2"):
            st = c[cfg].get("status")
            if st and st != "completed":
                fail_causes[f"{cfg}:{st}:{(c[cfg].get('failure') or {}).get('stage')}"] += 1
    for s, d in ds.items():
        if (d.get("db") or {}).get("status") == "failed":
            fail_causes[f"db:{(d.get('db') or {}).get('reason')}"] += 1
    mc, mdetail = miss_causes(prow, structural)
    dur = lambda cfg: [c[cfg].get("duration_s") for c in cases.values() if c[cfg].get("status") == "completed"]  # noqa: E731
    op = {
        "run_id": args.run_id, "generated": now_iso(),
        "unique_projects": len(slugs), "evaluation_rows": n_rows,
        "source_acquisition_success": rate(sum(1 for d in ds.values() if (d.get("source") or {}).get("status") == "ok"), len(slugs)),
        "build_and_codeql_db_success": rate(sum(1 for d in ds.values() if (d.get("db") or {}).get("status") == "ok"), len(slugs)),
        "build_note": ("The project build is performed by CodeQL autobuild inside `codeql database create` "
                       "(upstream build_codeql_dbs.py), so build success and database success coincide."),
        "b0_codeql_analysis_success": rate(sum(1 for c in cases.values() if c["b0"].get("status") == "completed"), n_rows),
        "b2_candidate_extraction_success": rate(stage("candidate_extraction"), n_rows),
        "b2_spec_generation_success": rate(stage("spec_inference"), n_rows),
        "b2_query_generation_success": rate(stage("query_generation"), n_rows),
        "b2_codeql_query_compile_and_run_success": rate(stage("codeql_analysis"), n_rows),
        "b2_contextual_analysis_success": rate(stage("contextual_analysis"), n_rows),
        "b2_end_to_end_success": rate(sum(1 for c in b2s if c.get("status") == "completed"), n_rows),
        "runtime_s": {cfg: {"n": len(dur(cfg)), "total": sum(dur(cfg)), "mean": (sum(dur(cfg)) / len(dur(cfg))) if dur(cfg) else None,
                            "max": max(dur(cfg)) if dur(cfg) else None} for cfg in ("b0", "b2")},
        "db_build_runtime_s": {s: (d.get("db") or {}).get("duration_s") for s, d in ds.items()},
        "failure_causes": dict(fail_causes),
        "b2_filtered_miss_causes": mc,
        "b2_filtered_miss_detail": mdetail,
        "structurally_undetectable_cases": sorted(structural & set(slugs)),
        # fetch_func_params.ql keeps only public methods called from src/test; projects whose build
        # skips test compilation (e.g. a pom profile setting maven.test.skip) yield no candidates.
        "b2_rows_without_func_param_candidates": sorted(
            eid for eid, c in cases.items() if c["b2"].get("status") == "completed"
            and ((c["b2"].get("evaluation") or {}).get("statistics") or {}).get("num_public_func_candidates") == 0),
        "posthoc_stats": {eid: (c["b2"].get("artifacts") and load_json(os.path.join(REPO_ROOT, c["b2"]["artifacts"]["posthoc_stats"]["path"])))
                          for eid, c in cases.items() if c["b2"].get("status") == "completed"},
    }
    dump_json(op, os.path.join(mdir, "operational_metrics.json"))

    # Token / cost report
    led = os.path.join(rdir, "llm", "ledger.jsonl")
    tot = collections.Counter()
    by_proj = collections.defaultdict(collections.Counter)
    models, providers, finish = collections.Counter(), collections.Counter(), collections.Counter()
    if os.path.exists(led):
        for line in open(led):
            r = json.loads(line)
            proj = (r.get("context") or {}).get("project") or "?"
            key = f"{proj}|{(r.get('context') or {}).get('query')}"
            if r.get("cache_hit"):
                tot["cache_hits"] += 1; by_proj[key]["cache_hits"] += 1
                continue
            for k in ("prompt_tokens", "completion_tokens", "reasoning_tokens", "http_retries"):
                tot[k] += r.get(k) or 0; by_proj[key][k] += r.get(k) or 0
            tot["requests"] += 1; by_proj[key]["requests"] += 1
            tot["repair_rerequests"] += 1 if (r.get("repair_round") or 0) > 0 else 0
            tot["json_invalid"] += 0 if r.get("json_valid") else 1
            tot["cost_usd_micro"] += round((r.get("cost_usd") or 0) * 1e6, 3)
            by_proj[key]["cost_usd_micro"] += round((r.get("cost_usd") or 0) * 1e6, 3)
            models[r.get("returned_model")] += 1; providers[r.get("provider")] += 1; finish[r.get("finish_reason")] += 1
    tc = {"run_id": args.run_id, "generated": now_iso(),
          "requests": tot["requests"], "cache_hits": tot["cache_hits"], "http_retries": tot["http_retries"],
          "repair_rerequests": tot["repair_rerequests"], "json_invalid_responses": tot["json_invalid"],
          "prompt_tokens": tot["prompt_tokens"], "completion_tokens": tot["completion_tokens"],
          "reasoning_tokens": tot["reasoning_tokens"], "cost_usd": tot["cost_usd_micro"] / 1e6,
          "cost_limit_usd": load_json(os.path.join(rdir, "config", "llm_config.json"))["accounting"]["cost_limit_usd"],
          "returned_models": dict(models), "providers": dict(providers), "finish_reasons": dict(finish),
          "note": "Includes preflight requests (project '__preflight__'). Costs are OpenRouter-reported usage.cost."}
    dump_json(tc, os.path.join(mdir, "token_cost_report.json"))
    write_csv_dicts([{"project_query": k, **{("cost_usd" if kk == "cost_usd_micro" else kk): (v / 1e6 if kk == "cost_usd_micro" else v)
                                              for kk, v in c.items()}}
                     for k, c in sorted(by_proj.items())], os.path.join(mdir, "token_cost_by_project.csv"))
    print(f"evaluate: {len(prow)} project-config rows written to {mdir}")


if __name__ == "__main__":
    main()
