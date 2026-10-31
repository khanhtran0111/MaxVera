"""Post-hoc diagnostic of IRIS's API-label merge (does not influence any prediction).

IRIS (neusym_vul.merge_llm_labeled_apis_and_cache) keeps an LLM label only when the returned
(package, class, method, signature) equals a candidate exactly. This script re-parses the raw
labelling responses with a copy of IRIS's parse_json and counts, per completed B2 row:
  returned          objects parsed from the responses
  merged_exact      objects whose 4-tuple equals a queried candidate (kept by IRIS)
  dropped_signature objects matching a candidate's (package, class, method) but not its signature
  dropped_other     objects matching no candidate (package, class, method)
Writes runs/<run_id>/metrics/label_merge_diagnostics.{csv,json}.
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import REPO_ROOT, load_json, dump_json, write_csv_dicts, run_dir  # noqa: E402
from orchestrate import cohort_rows  # noqa: E402


def iris_parse_json(json_str):
    """Copy of SAPipeline.parse_json (vendor/iris-v1/src/neusym_vul.py) without logging."""
    try:
        json_str = json_str.replace("\\n", "").replace("\\\n", "")
        json_str = re.sub("//.*", "", json_str)
        json_str = re.sub("\"\"", "\"", json_str)
        json_str = re.findall(r"\[[\s\S]*\]", json_str)[0]
        result = json.loads(json_str)
        return result if type(result) == list else []
    except Exception:
        try:
            return [json.loads(r.strip()) for r in re.findall(r"{[^}]*}", json_str)]
        except Exception:
            return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()
    rdir = run_dir(args.run_id)
    man = load_json(os.path.join(rdir, "run_manifest.json"))
    out, total = [], collections.Counter()
    for row in cohort_rows(man["cohort"], man.get("projects")):
        rec = load_json(os.path.join(rdir, "cases", row["eval_id"], "b2.json"), {}) or {}
        if rec.get("status") != "completed":
            continue
        cand_path = os.path.join(REPO_ROOT, rec["artifacts"]["candidate_apis"]["path"])
        cands = set()
        with open(cand_path, newline="") as f:
            for r in csv.DictReader(f):
                cands.add((r["package"], r["clazz"], r["func"], r["full_signature"]))
        cand3 = {c[:3] for c in cands}
        c = collections.Counter()
        for resp in glob.glob(os.path.join(os.path.dirname(cand_path), "logs", "label_apis", "raw_llm_response_*.txt")):
            for obj in iris_parse_json(open(resp).read()):
                if not isinstance(obj, dict) or not all(obj.get(k) for k in ("package", "class", "method", "signature")):
                    c["invalid_entry"] += 1
                    continue
                c["returned"] += 1
                key = (obj["package"], obj["class"], obj["method"], obj["signature"])
                t = obj.get("type", "none")
                if key in cands:
                    c["merged_exact"] += 1; c[f"merged_exact_{t}"] += 1
                elif key[:3] in cand3:
                    c["dropped_signature"] += 1; c[f"dropped_signature_{t}"] += 1
                else:
                    c["dropped_other"] += 1
        total.update(c)
        out.append({"eval_id": row["eval_id"], "cwe": row["cwe"], "candidates": len(cands), **c})
    write_csv_dicts(out, os.path.join(rdir, "metrics", "label_merge_diagnostics.csv"))
    summary = dict(total)
    if total["returned"]:
        summary["dropped_signature_share"] = total["dropped_signature"] / total["returned"]
        summary["merged_exact_share"] = total["merged_exact"] / total["returned"]
    dump_json({"run_id": args.run_id, "rows": len(out), "totals": summary,
               "note": "Diagnostic only; IRIS's exact-match merge is used unchanged for all predictions."},
              os.path.join(rdir, "metrics", "label_merge_diagnostics.json"))
    print(f"label diagnostics: {summary}")


if __name__ == "__main__":
    main()
