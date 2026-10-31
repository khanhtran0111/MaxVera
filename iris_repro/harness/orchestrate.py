"""Sequential orchestrator for an IRIS v1 reproduction run (one project at a time).

For every evaluation row of the cohort:
  1. prepare_case.py  (fetch + verify + CodeQL database; shared across runs in runs/_dataset)
  2. run_case.py --config b0  (original CodeQL queries, no LLM)
  3. run_case.py --config b2  (IRIS + GPT-OSS 20B via OpenRouter)

Evaluation rows: the 120 canonical CWE-Bench-Java cases (each with its own CWE) plus,
for artifact compatibility, x-stream__xstream_CVE-2021-21345_1.4.15 evaluated under CWE-094
(eval_id suffix "__CWE-094"), which the original IRIS results/*.csv files contain as a 121st row.

Resume: completed configurations are never re-run. Interrupted, budget-stopped and API-failed
configurations are retried; case-level failures are retried only with --retry-failed.
Stops immediately (exit 75/76/77) on budget exhaustion, persistent API failure or configuration error.
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import (DATASET_STATE_DIR, project_info, load_json, dump_json, now_iso, run_dir,  # noqa: E402
                    append_event, write_csv_dicts, CONFIG_DIR)

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_EXTRA = ("x-stream__xstream_CVE-2021-21345_1.4.15", "CWE-094")
SMOKE_DEFAULT = [
    "perwendel__spark_CVE-2018-9159_2.7.1",
]
RETRY_ALWAYS = {"running", "stopped_budget", "failed_api", "failed_config", None}


def cohort_rows(kind, projects=None):
    rows = project_info()
    by_slug = {r["project_slug"]: r for r in rows}
    out = []
    if kind == "full":
        for r in rows:
            out.append({"eval_id": r["project_slug"], "slug": r["project_slug"], "cwe": r["cwe_id"],
                        "cve_id": r["cve_id"], "dataset_cwe": r["cwe_id"], "canonical": True})
        slug, cwe = ARTIFACT_EXTRA
        out.append({"eval_id": f"{slug}__{cwe}", "slug": slug, "cwe": cwe, "cve_id": by_slug[slug]["cve_id"],
                    "dataset_cwe": by_slug[slug]["cwe_id"], "canonical": False})
    else:
        for slug in (projects or SMOKE_DEFAULT):
            r = by_slug[slug]
            out.append({"eval_id": slug, "slug": slug, "cwe": r["cwe_id"], "cve_id": r["cve_id"],
                        "dataset_cwe": r["cwe_id"], "canonical": True})
    return out


def run(cmd, timeout=None):
    p = subprocess.run(cmd, timeout=timeout)
    return p.returncode


def summarize(rdir, rows):
    table = []
    for row in rows:
        ds = load_json(os.path.join(DATASET_STATE_DIR, "status", f"{row['slug']}.json"), {}) or {}
        rec = {"eval_id": row["eval_id"], "slug": row["slug"], "cve_id": row["cve_id"], "cwe": row["cwe"],
               "canonical": row["canonical"],
               "source_status": (ds.get("source") or {}).get("status", "pending"),
               "db_status": (ds.get("db") or {}).get("status", "pending"),
               "db_reason": (ds.get("db") or {}).get("reason")}
        for cfg in ("b0", "b2"):
            c = load_json(os.path.join(rdir, "cases", row["eval_id"], f"{cfg}.json"), {}) or {}
            rec[f"{cfg}_status"] = c.get("status", "pending" if rec["db_status"] != "failed" else "not_run_db_failed")
            rec[f"{cfg}_duration_s"] = c.get("duration_s")
            rec[f"{cfg}_exit_code"] = c.get("exit_code")
            rec[f"{cfg}_failure_stage"] = (c.get("failure") or {}).get("stage")
            if cfg == "b2":
                u = c.get("llm_usage") or {}
                rec["b2_llm_requests"] = u.get("requests")
                rec["b2_cost_usd"] = round(u.get("cost_usd", 0.0), 6) if u else None
        table.append(rec)
    write_csv_dicts(table, os.path.join(rdir, "status", "execution_status.csv"))
    dump_json(table, os.path.join(rdir, "status", "execution_status.json"))
    return table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--retry-failed", action="store_true")
    args = ap.parse_args()
    rdir = run_dir(args.run_id)
    manifest = load_json(os.path.join(rdir, "run_manifest.json"))
    if manifest is None:
        print(f"run manifest missing for {args.run_id}; create the run with init_run.py"); sys.exit(77)
    rows = cohort_rows(manifest["cohort"], manifest.get("projects"))
    exp = load_json(os.path.join(rdir, "config", "experiment.json"))
    events = os.path.join(rdir, "events.jsonl")
    append_event(events, {"event": "orchestrator_start", "pid": os.getpid()})
    py = sys.executable

    for i, row in enumerate(rows):
        progress = {"run_id": args.run_id, "index": i + 1, "total": len(rows), "eval_id": row["eval_id"],
                    "updated": now_iso()}
        dump_json(progress, os.path.join(rdir, "status", "progress.json"))
        print(f"\n######## [{i + 1}/{len(rows)}] {row['eval_id']} ({row['cwe']}) @ {now_iso()}", flush=True)

        # 1. Dataset preparation (shared state across runs)
        ds_path = os.path.join(DATASET_STATE_DIR, "status", f"{row['slug']}.json")
        ds = load_json(ds_path, {}) or {}
        db_status = (ds.get("db") or {}).get("status")
        if db_status != "ok" and (db_status not in ("failed", "skipped") or args.retry_failed):
            progress["stage"] = "prepare"; dump_json(progress, os.path.join(rdir, "status", "progress.json"))
            rc = run([py, os.path.join(HERE, "prepare_case.py"), row["slug"]],
                     timeout=exp["build_limits"]["db_create_timeout_s"] + 1800)
            ds = load_json(ds_path, {}) or {}
            print(f"  prepare exit={rc} db={(ds.get('db') or {}).get('status')} reason={(ds.get('db') or {}).get('reason')}", flush=True)
        if (ds.get("db") or {}).get("status") != "ok":
            append_event(events, {"eval_id": row["eval_id"], "event": "skip_db_failed",
                                  "reason": (ds.get("db") or {}).get("reason") or (ds.get("source") or {}).get("status")})
            summarize(rdir, rows)
            continue

        # 2./3. Experiment configurations
        for cfg in ("b0", "b2"):
            c = load_json(os.path.join(rdir, "cases", row["eval_id"], f"{cfg}.json"), {}) or {}
            st = c.get("status")
            if st == "completed" or (st == "failed" and not args.retry_failed):
                continue
            progress["stage"] = cfg; progress["updated"] = now_iso()
            dump_json(progress, os.path.join(rdir, "status", "progress.json"))
            rc = run([py, os.path.join(HERE, "run_case.py"), "--run-id", args.run_id, "--config", cfg,
                      "--slug", row["slug"], "--cwe", row["cwe"], "--eval-id", row["eval_id"]])
            c = load_json(os.path.join(rdir, "cases", row["eval_id"], f"{cfg}.json"), {}) or {}
            print(f"  {cfg}: exit={rc} status={c.get('status')} duration={c.get('duration_s')}s", flush=True)
            if rc in (75, 76, 77):
                summarize(rdir, rows)
                append_event(events, {"event": "orchestrator_stop", "exit_code": rc, "eval_id": row["eval_id"]})
                print(f"!! fatal condition (exit {rc}); stopping with resumable state", flush=True)
                sys.exit(rc)
        summarize(rdir, rows)

    table = summarize(rdir, rows)
    append_event(events, {"event": "experiments_finished"})
    # Evaluation, independent verification and reports
    for script in ("evaluate.py", "label_diagnostics.py", "verify_metrics.py", "report.py"):
        rc = run([py, os.path.join(HERE, script), "--run-id", args.run_id])
        print(f"  {script}: exit={rc}", flush=True)
        if rc != 0:
            append_event(events, {"event": "postprocess_failed", "script": script, "exit_code": rc})
            sys.exit(1)
    dump_json({"finished": now_iso(), "rows": len(table),
               "b2_completed": sum(1 for t in table if t["b2_status"] == "completed"),
               "b0_completed": sum(1 for t in table if t["b0_status"] == "completed")},
              os.path.join(rdir, "DONE.json"))
    append_event(events, {"event": "orchestrator_done"})


if __name__ == "__main__":
    main()
