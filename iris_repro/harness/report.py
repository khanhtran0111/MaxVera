"""Generate runs/<run_id>/reports/{RUN_REPORT.md, comparison_with_paper.csv} from the metrics files.

The narrative reproduction report (iris_repro/REPRODUCTION_REPORT.md) references these
run-level, machine-generated tables; every number here is read from metrics/*.json.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import load_json, run_dir, now_iso, write_csv_dicts, DATASET_STATE_DIR  # noqa: E402

LABEL = {"b0": "B0 CodeQL baseline", "b2_raw": "B2 IRIS+GPT-OSS-20B (before contextual filtering)",
         "b2_filtered": "B2 IRIS+GPT-OSS-20B (after contextual filtering)"}


def pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"


def f3(x):
    return "n/a" if x is None else f"{x:.3f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()
    rdir = run_dir(args.run_id)
    md = os.path.join(rdir, "metrics")
    man = load_json(os.path.join(rdir, "run_manifest.json"))
    art = load_json(os.path.join(md, "metrics_artifact_compatible.json"))
    can = load_json(os.path.join(md, "metrics_dataset_canonical.json"))
    op = load_json(os.path.join(md, "operational_metrics.json"))
    tc = load_json(os.path.join(md, "token_cost_report.json"))
    ver = load_json(os.path.join(md, "verification.json"), {}) or {}
    api = load_json(os.path.join(rdir, "manifests", "api_preflight.json"), {}) or {}
    env = load_json(os.path.join(rdir, "manifests", "environment.json"), {}) or {}
    model = load_json(os.path.join(rdir, "manifests", "model_api.json"), {}) or {}

    comp = []
    ref = art["reference_from_original_artifact_csv"]
    for name, cfg, paper_key in (("CodeQL", "b0", "CodeQL"), ("IRIS (filtered)", "b2_filtered", "IRIS + GPT-4")):
        p = ref[paper_key]["paper_table1"]
        for policy, m in (("artifact_compatible", art), ("dataset_canonical", can)):
            c = m["configs"][cfg]
            comp.append({"method": name, "policy": policy, "rows": c["n_rows"], "completed": c["n_completed"],
                         "detected": c["detected"], "avg_fdr": c["avg_fdr"], "avg_f1": c["avg_f1"],
                         "paper_method": "CodeQL" if cfg == "b0" else "IRIS + GPT-4",
                         "paper_detected_of_120": p["detected"], "paper_avg_fdr": p["avg_fdr"], "paper_avg_f1": p["avg_f1"]})
    write_csv_dicts(comp, os.path.join(rdir, "reports", "comparison_with_paper.csv"))

    L = []
    L.append(f"# Run report: {args.run_id}\n")
    L.append(f"Generated {now_iso()} by `iris_repro/harness/report.py`. Cohort: **{man['cohort']}** "
             f"({'official' if man.get('official') else 'NOT official — smoke/diagnostic only'}). "
             f"IRIS commit `{man['iris_commit']}`, compatibility patch sha256 `{man['compat_patch_sha256'][:16]}…`.\n")
    L.append(f"Independent verification: **{ver.get('status', 'not run')}** "
             f"(row mismatches: {len(ver.get('row_level_mismatches', []))}, aggregate mismatches: "
             f"{sum(1 for c in ver.get('aggregate_checks', []) if not c['match'])}).\n")

    L.append("## Model / API\n")
    comp_chk = (api.get("checks") or {}).get("completion", {})
    L.append(f"- Requested model `{model.get('requested_model')}`; returned model(s) {tc['returned_models']}; "
             f"provider(s) {tc['providers']} (pinned `{model.get('provider_routing', {}).get('order')}`, "
             f"fallbacks={model.get('provider_routing', {}).get('allow_fallbacks')}, ZDR={model.get('provider_routing', {}).get('zdr')}, "
             f"data_collection={model.get('provider_routing', {}).get('data_collection')}).")
    L.append(f"- Decoding: {model.get('decoding')}; concurrency {model.get('concurrency')}.")
    L.append(f"- Preflight: ok={api.get('ok')}, served by {comp_chk.get('provider')} / {comp_chk.get('returned_model')}.")
    L.append(f"- Requests {tc['requests']} (cache hits {tc['cache_hits']}, HTTP retries {tc['http_retries']}, "
             f"identical re-requests for empty/truncated JSON {tc['repair_rerequests']}, responses without parseable JSON "
             f"{tc['json_invalid_responses']}); tokens: prompt {tc['prompt_tokens']:,}, completion {tc['completion_tokens']:,} "
             f"(reasoning {tc['reasoning_tokens']:,}); cost **${tc['cost_usd']:.4f}** (limit ${tc['cost_limit_usd']}). "
             f"Finish reasons: {tc['finish_reasons']}.\n")
    L.append(f"- CodeQL: {env.get('codeql', {}).get('version', '')[:120]}…\n")

    for title, m in (("Paper-compatible aggregate (artifact rows)", art), ("Canonical aggregate (120-case cohort)", can)):
        L.append(f"## {title}\n")
        L.append(f"Rows: {m['row_definition']}.\n")
        L.append("| Configuration | Rows | Completed | #Detected | Detection rate | AvgFDR | AvgF1 | AvgF1 (completed only) | MicroFDR (not paper metric) |")
        L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for cfg in ("b0", "b2_raw", "b2_filtered"):
            c = m["configs"][cfg]
            L.append(f"| {LABEL[cfg]} | {c['n_rows']} | {c['n_completed']} | {c['detected']} | {pct(c['detection_rate'])} | "
                     f"{pct(c['avg_fdr'])} | {f3(c['avg_f1'])} | {f3(c['avg_f1_completed_only'])} | {pct(c['micro_fdr_NOT_PAPER_METRIC'])} |")
        L.append("")
        L.append("Per CWE (#Detected / rows):\n")
        cwes = sorted(m["configs"]["b0"]["per_cwe"])
        L.append("| Configuration | " + " | ".join(cwes) + " |")
        L.append("|---|" + "---:|" * len(cwes))
        for cfg in ("b0", "b2_raw", "b2_filtered"):
            pc = m["configs"][cfg]["per_cwe"]
            L.append(f"| {LABEL[cfg]} | " + " | ".join(f"{pc[c]['detected']}/{pc[c]['n_rows']}" for c in cwes) + " |")
        L.append("")
        nc = m["configs"]["b2_filtered"]["not_completed"]
        if nc:
            L.append(f"B2 rows not completed ({len(nc)}): " + ", ".join(f"`{x}`" for x in nc) + "\n")
        nc0 = m["configs"]["b0"]["not_completed"]
        if nc0:
            L.append(f"B0 rows not completed ({len(nc0)}): " + ", ".join(f"`{x}`" for x in nc0) + "\n")

    L.append("## Comparison with IRIS Table 1 (reference values, not targets)\n")
    L.append("| Method | Policy | Detected | AvgFDR | AvgF1 | Paper method | Paper Detected/120 | Paper AvgFDR | Paper AvgF1 |")
    L.append("|---|---|---:|---:|---:|---|---:|---:|---:|")
    for c in comp:
        L.append(f"| {c['method']} | {c['policy']} | {c['detected']}/{c['rows']} | {pct(c['avg_fdr'])} | {f3(c['avg_f1'])} | "
                 f"{c['paper_method']} | {c['paper_detected_of_120']} | {pct(c['paper_avg_fdr'])} | {f3(c['paper_avg_f1'])} |")
    L.append("")
    L.append("Metric calibration on the original artifact CSVs (same formulas):\n")
    for name, r in ref.items():
        a, k = r["artifact_121_rows"], r["canonical_120_rows"]
        L.append(f"- {name}: 121 rows → {a['detected']} detected, AvgFDR {pct(a['avg_fdr'])}, AvgF1 {f3(a['avg_f1'])}; "
                 f"canonical 120 rows → {k['detected']}, {pct(k['avg_fdr'])}, {f3(k['avg_f1'])}. "
                 f"Paper: {r['paper_table1']['detected']}, {pct(r['paper_table1']['avg_fdr'])}, {r['paper_table1']['avg_f1']}.")
    L.append("")

    L.append("## Operational metrics\n")
    for k in ("source_acquisition_success", "build_and_codeql_db_success", "b0_codeql_analysis_success",
              "b2_candidate_extraction_success", "b2_spec_generation_success", "b2_query_generation_success",
              "b2_codeql_query_compile_and_run_success", "b2_contextual_analysis_success", "b2_end_to_end_success"):
        v = op[k]
        L.append(f"- {k}: {v['count']}/{v['n']} ({pct(v['rate'])})")
    L.append(f"- Runtime (s): {op['runtime_s']}")
    L.append(f"- Failure causes: {op['failure_causes'] or 'none'}")
    L.append(f"- B2 (filtered) miss causes among completed rows: {op['b2_filtered_miss_causes'] or 'none'}")
    L.append(f"- Structurally undetectable cases in cohort (no evaluable fixed method): {len(op['structurally_undetectable_cases'])}\n")

    L.append("## Artifacts\n")
    L.append("- `status/execution_status.csv` — per-row execution status (source, DB, B0, B2)")
    L.append("- `cases/<eval_id>/{b0,b2}.json` — commands, exit codes, stage flags, artifact paths + sha256, evaluator output, LLM usage")
    L.append("- `metrics/project_metrics.csv`, `metrics/per_cwe_results.csv`, `metrics/raw_vs_filtered.csv`")
    L.append("- `metrics/metrics_artifact_compatible.json`, `metrics/metrics_dataset_canonical.json`, `metrics/verification.json`")
    L.append("- `metrics/token_cost_report.json`, `metrics/token_cost_by_project.csv`, `metrics/operational_metrics.json`")
    L.append("- `manifests/` — environment, model/API (no secrets), preflight, dataset manifest snapshot")
    L.append("- IRIS per-project outputs (specs, generated .qll, SARIF): `vendor/iris-v1/output/<slug>/<run_id>[-b0]/`")
    os.makedirs(os.path.join(rdir, "reports"), exist_ok=True)
    with open(os.path.join(rdir, "reports", "RUN_REPORT.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    print(f"report: {os.path.join(rdir, 'reports', 'RUN_REPORT.md')}")


if __name__ == "__main__":
    main()
