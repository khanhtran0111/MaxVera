"""Independent verification of a run's metrics.

1. Re-evaluates every completed row directly from the SARIF files, the CodeQL function/class
   location CSVs and data/cwe-bench-java/data/fix_info.csv, with an implementation written
   from scratch (csv/json only, no pandas, no IRIS code), and compares Alerts / Paths /
   Recall / TP Alerts / TP Paths with the IRIS evaluator output embedded in the case records.
2. Recomputes #Detected / AvgFDR / AvgF1 for both row policies from those independent rows
   with separately written formulas, and compares them with metrics_*.json.
3. Recomputes Table 1 from the original artifact CSVs as a calibration of the formulas.

Writes runs/<run_id>/metrics/verification.json (status PASS/FAIL). Always exits 0 so that
reports are still produced; the status is surfaced in the report.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import REPO_ROOT, IRIS_DIR, CWE_BENCH_DIR, load_json, dump_json, run_dir, now_iso  # noqa: E402
from orchestrate import cohort_rows  # noqa: E402

PANDAS_NA = {"", "#N/A", "#N/A N/A", "#NA", "-1.#IND", "-1.#QNAN", "-NaN", "-nan", "1.#IND", "1.#QNAN",
             "<NA>", "N/A", "NA", "NULL", "NaN", "None", "n/a", "nan", "null"}


def na(v):
    # pd.read_csv turns these into NaN, which the IRIS evaluator formats as "nan"
    return "nan" if v in PANDAS_NA else v


def fixed_locations(slug):
    files, methods = set(), set()
    with open(os.path.join(CWE_BENCH_DIR, "data", "fix_info.csv"), newline="") as f:
        for r in csv.DictReader(f):
            if r["project_slug"] != slug or "src/test" in r["file"]:
                continue
            files.add(r["file"])
            methods.add(f"{na(r['file'])}:{na(r['class'])}:{na(r['method'])}")
    return files, methods


def load_decls(path):
    by_file = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            by_file.setdefault(r["file"], []).append((int(r["start_line"]), int(r["end_line"]), r["name"]))
    return by_file


def innermost(decls, file, line):
    best = None
    for (s, e, name) in decls.get(file, ()):
        if s <= line <= e and (best is None or s > best[0]):
            best = (s, e, name)
    return best[2] if best else None


def evaluate(sarif_path, func_csv, class_csv, slug):
    sarif = json.load(open(sarif_path))
    results = sarif["runs"][0]["results"]
    files, methods = fixed_locations(slug)
    funcs, classes = load_decls(func_csv), load_decls(class_csv)
    n_paths = tp_paths = tp_paths_file = 0
    tp_results, tp_results_file = set(), set()
    for rid, res in enumerate(results):
        for cf in res.get("codeFlows", []) or []:
            locs = cf["threadFlows"][0]["locations"]
            msg = lambda l: l["location"]["message"]["text"]  # noqa: E731
            if any(k in msg(locs[0]) or k in msg(locs[-1]) for k in ("toString", "println")):
                continue
            n_paths += 1
            passing_files, passing = set(), set()
            for l in locs:
                try:
                    pl = l["location"]["physicalLocation"]
                    uri, line = pl["artifactLocation"]["uri"], pl["region"]["startLine"]
                except (KeyError, TypeError):
                    continue
                passing_files.add(uri)
                c, m = innermost(classes, uri, line), innermost(funcs, uri, line)
                if c is not None and m is not None:
                    passing.add(f"{uri}:{c}:{m}")
            if passing_files & files:
                tp_paths_file += 1; tp_results_file.add(rid)
            if passing & methods:
                tp_paths += 1; tp_results.add(rid)
    return {"num_results": len(results), "num_paths": n_paths, "recall_method": tp_paths > 0,
            "num_tp_paths_method": tp_paths, "num_tp_results_method": len(tp_results)}


def agg(rows):
    n = len(rows)
    det = len([1 for r in rows if r["ok"] and r["recall"]])
    prec = [r["tp_alerts"] / r["alerts"] for r in rows if r["ok"] and r["alerts"]]
    f1s = []
    for r in rows:
        if r["ok"] and r["alerts"] and r["recall"] and r["tp_alerts"]:
            p = r["tp_alerts"] / r["alerts"]
            f1s.append(2 * p / (p + 1))
        else:
            f1s.append(0.0)
    return {"detected": det, "avg_fdr": (1 - sum(prec) / len(prec)) if prec else None,
            "avg_f1": sum(f1s) / n if n else None, "n_rows": n}


def close(a, b, tol=1e-9):
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= tol


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()
    rdir = run_dir(args.run_id)
    manifest = load_json(os.path.join(rdir, "run_manifest.json"))
    rows = cohort_rows(manifest["cohort"], manifest.get("projects"))
    mismatches, indep = [], {"b0": [], "b2_raw": [], "b2_filtered": []}
    keys = ("num_results", "num_paths", "recall_method", "num_tp_paths_method", "num_tp_results_method")

    for row in rows:
        for cfg_file, cfgs in (("b0", [("b0", "sarif", None)]),
                               ("b2", [("b2_raw", "sarif_pp", "vanilla_result"),
                                       ("b2_filtered", "sarif_filtered", "posthoc_filter_result")])):
            rec = load_json(os.path.join(rdir, "cases", row["eval_id"], f"{cfg_file}.json"), {}) or {}
            for cfg, sarif_key, ev_key in cfgs:
                ok = rec.get("status") == "completed"
                r = {"eval_id": row["eval_id"], "canonical": row["canonical"], "ok": ok,
                     "alerts": 0, "tp_alerts": 0, "recall": False}
                if ok:
                    a = rec["artifacts"]
                    mine = evaluate(os.path.join(REPO_ROOT, a[sarif_key]["path"]),
                                    os.path.join(REPO_ROOT, a["func_locs"]["path"]),
                                    os.path.join(REPO_ROOT, a["class_locs"]["path"]), row["slug"])
                    theirs = rec["evaluation"] if ev_key is None else rec["evaluation"][ev_key]
                    diff = {k: (theirs.get(k), mine[k]) for k in keys if theirs.get(k) != mine[k]}
                    if diff:
                        mismatches.append({"eval_id": row["eval_id"], "config": cfg, "iris_vs_independent": diff})
                    r.update({"alerts": mine["num_results"], "tp_alerts": mine["num_tp_results_method"],
                              "recall": mine["recall_method"]})
                indep[cfg].append(r)

    agg_checks = []
    for policy in ("artifact_compatible", "dataset_canonical"):
        m = load_json(os.path.join(rdir, "metrics", f"metrics_{policy}.json"))
        for cfg, rs in indep.items():
            sub = rs if policy == "artifact_compatible" else [r for r in rs if r["canonical"]]
            mine = agg(sub)
            rep = m["configs"][cfg]
            for k in ("detected", "avg_fdr", "avg_f1", "n_rows"):
                ok = close(float(mine[k]) if mine[k] is not None else None,
                           float(rep[k]) if rep[k] is not None else None)
                agg_checks.append({"policy": policy, "config": cfg, "metric": k, "reported": rep[k],
                                   "independent": mine[k], "match": ok})

    calib = {}
    for name, fn in (("CodeQL", "CodeQL.csv"), ("IRIS+GPT-4", "IRIS+GPT-4.csv")):
        rs = []
        for r in csv.DictReader(open(os.path.join(IRIS_DIR, "results", fn))):
            alerts = int(r["Alerts"]) if r["Alerts"].isdigit() else 0
            rs.append({"ok": True, "canonical": True, "alerts": alerts if r["Precision"] not in ("N/A", "None") else 0,
                       "tp_alerts": int(r["TP Alerts"]) if r["TP Alerts"].isdigit() else 0, "recall": r["Recall"] == "1"})
        calib[name] = agg(rs)

    status = "PASS" if not mismatches and all(c["match"] for c in agg_checks) else "FAIL"
    out = {"run_id": args.run_id, "generated": now_iso(), "status": status,
           "row_level_mismatches": mismatches, "aggregate_checks": agg_checks,
           "calibration_on_original_artifact_csv": calib,
           "paper_table1": {"CodeQL": {"detected": 27, "avg_fdr": 0.9003, "avg_f1": 0.076},
                            "IRIS+GPT-4": {"detected": 55, "avg_fdr": 0.8482, "avg_f1": 0.177}}}
    dump_json(out, os.path.join(rdir, "metrics", "verification.json"))
    print(f"verification: {status} (row mismatches={len(mismatches)}, "
          f"aggregate mismatches={sum(1 for c in agg_checks if not c['match'])})")


if __name__ == "__main__":
    main()
