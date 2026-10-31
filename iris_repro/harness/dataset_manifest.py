"""Validate the CWE-Bench-Java v1 cohort and write the dataset manifest.

Checks: 120 unique slugs / CVEs, per-CWE counts (55/13/31/21), consistency between
project_info.csv, build_info.csv, fix_info.csv and package-names/, the upstream submodule
commit, file checksums, and (when present) the acquired source tree and CodeQL database
status of every case. Also documents the CVE-2021-21345 duplicated CWE-094 evaluation row
found in the original IRIS results/*.csv files.

Writes <out>/dataset_manifest.json and <out>/dataset_manifest.csv.
"""
import argparse
import collections
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (CWE_BENCH_DIR, IRIS_DIR, DATASET_STATE_DIR, CONFIG_DIR, project_info, build_info,  # noqa: E402
                    read_csv_dicts, load_json, dump_json, write_csv_dicts, sha256_file, now_iso)

EXPECTED = {"CWE-022": 55, "CWE-078": 13, "CWE-079": 31, "CWE-094": 21}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DATASET_STATE_DIR)
    args = ap.parse_args()
    pins = load_json(os.path.join(CONFIG_DIR, "pins.json"))
    errors = []

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=CWE_BENCH_DIR, capture_output=True, text=True).stdout.strip()
    if head != pins["cwe_bench_java"]["commit"]:
        errors.append(f"cwe-bench-java HEAD {head} != pinned {pins['cwe_bench_java']['commit']}")

    overrides = (load_json(os.path.join(CONFIG_DIR, "experiment.json"), {}).get("package_names_regeneration") or {}).get("internal_package", {})
    known_issues = []
    pinfo = project_info()
    binfo = build_info()
    fix = read_csv_dicts(os.path.join(CWE_BENCH_DIR, "data", "fix_info.csv"))
    fix_by = collections.defaultdict(list)
    for r in fix:
        fix_by[r["project_slug"]].append(r)

    counts = collections.Counter(r["cwe_id"] for r in pinfo)
    if dict(counts) != EXPECTED:
        errors.append(f"per-CWE counts {dict(counts)} != expected {EXPECTED}")
    slugs = [r["project_slug"] for r in pinfo]
    cves = [r["cve_id"] for r in pinfo]
    if len(set(slugs)) != 120 or len(set(cves)) != 120:
        errors.append(f"unique slugs={len(set(slugs))} cves={len(set(cves))} (expected 120/120)")
    if set(slugs) != set(binfo):
        errors.append("project_info / build_info slug sets differ")

    rows = []
    for r in pinfo:
        slug = r["project_slug"]
        pkg = os.path.join(CWE_BENCH_DIR, "package-names", f"{slug}.txt")
        patch = os.path.join(CWE_BENCH_DIR, "patches", f"{slug}.patch")
        fixes = fix_by.get(slug, [])
        eval_methods = {(f["file"], f["class"], f["method"]) for f in fixes
                        if "src/test" not in f["file"] and f["method"]}
        st = load_json(os.path.join(DATASET_STATE_DIR, "status", f"{slug}.json"), {}) or {}
        src, db = st.get("source") or {}, st.get("db") or {}
        b = binfo.get(slug, {})
        pkg_status = (st.get("package_names") or {}).get("status") or ("upstream" if os.path.exists(pkg) else "missing")
        if not os.path.exists(pkg) and pkg_status != "regenerated":
            if slug in overrides:
                known_issues.append(f"package-names missing for {slug}; regenerated after DB build (documented override)")
            else:
                errors.append(f"missing package-names for {slug}")
        rows.append({
            "id": r["id"], "project_slug": slug, "cve_id": r["cve_id"], "cwe_id": r["cwe_id"],
            "github_url": r["github_url"], "github_tag": r["github_tag"], "buggy_commit_id": r["buggy_commit_id"],
            "fix_commit_ids": r["fix_commit_ids"],
            "build_jdk": b.get("jdk_version"), "build_mvn": b.get("mvn_version"),
            "build_gradle": b.get("gradle_version"), "build_gradlew": b.get("use_gradlew"),
            "package_names_present": os.path.exists(pkg), "package_names_status": pkg_status,
            "dataset_patch_sha256": sha256_file(patch) if os.path.exists(patch) else "",
            "fix_info_rows": len(fixes), "evaluable_fixed_methods": len(eval_methods),
            "source_status": src.get("status", "not_fetched"), "source_head": src.get("head", ""),
            "source_commit_ok": src.get("commit_ok", ""), "source_patch_applied": src.get("patch_applied", ""),
            "source_tree": src.get("tree", ""), "source_worktree_diff_sha256": src.get("worktree_diff_sha256", ""),
            "db_status": db.get("status", "not_built"), "db_reason": db.get("reason") or "",
            "db_size_bytes": db.get("size_bytes") or "", "db_duration_s": db.get("duration_s") or "",
        })

    # CVE-2021-21345 duplication in the original artifact result files
    dup = []
    for fn in sorted(os.listdir(os.path.join(IRIS_DIR, "results"))):
        if not fn.endswith(".csv"):
            continue
        rs = read_csv_dicts(os.path.join(IRIS_DIR, "results", fn))
        keyed = [x for x in rs if x["CVE"] == "CVE-2021-21345"]
        dup.append({"file": fn, "rows": len(rs),
                    "cve_2021_21345_rows": [{"cwe": x["CWE ID"], "recall": x["Recall"], "alerts": x["Alerts"]} for x in keyed]})

    manifest = {
        "generated": now_iso(),
        "dataset": "CWE-Bench-Java (IRIS v1 artifact)",
        "upstream": {"iris_commit": pins["iris"]["commit"], "cwe_bench_java_commit": head,
                     "cwe_bench_java_url": pins["cwe_bench_java"]["url"]},
        "files_sha256": {f: sha256_file(os.path.join(CWE_BENCH_DIR, "data", f))
                         for f in ("project_info.csv", "build_info.csv", "fix_info.csv")},
        "counts": {"cases": len(pinfo), "unique_cves": len(set(cves)), "per_cwe": dict(counts),
                   "expected_per_cwe": EXPECTED,
                   "cases_without_evaluable_fixed_method": [x["project_slug"] for x in rows if x["evaluable_fixed_methods"] == 0],
                   "source_ok": sum(1 for x in rows if x["source_status"] == "ok"),
                   "db_ok": sum(1 for x in rows if x["db_status"] == "ok"),
                   "db_failed": sum(1 for x in rows if x["db_status"] == "failed")},
        "artifact_row_discrepancy": {
            "summary": ("The dataset has 120 unique CVE cases. The original IRIS results/*.csv files have 121 rows: "
                        "x-stream__xstream_CVE-2021-21345_1.4.15 (dataset CWE-078) appears once under CWE-078 and once "
                        "more under CWE-094. Paper Table 1 counts are reproducible from these 121 rows."),
            "per_file": dup,
        },
        "known_issues": known_issues,
        "errors": errors,
        "valid": not errors,
    }
    dump_json(manifest, os.path.join(args.out, "dataset_manifest.json"))
    write_csv_dicts(rows, os.path.join(args.out, "dataset_manifest.csv"))
    print(f"dataset manifest: valid={manifest['valid']} cases={len(rows)} per_cwe={dict(counts)} "
          f"source_ok={manifest['counts']['source_ok']} db_ok={manifest['counts']['db_ok']} errors={errors}")
    sys.exit(0 if not errors else 1)


if __name__ == "__main__":
    main()
