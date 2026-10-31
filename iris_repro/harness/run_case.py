"""Run one experiment configuration on one evaluation row.

  B0: vendor/iris-v1/src/codeql_vul.py   <slug> --query cwe-XXXwCodeQL --run-id <run_id>-b0 --overwrite
  B2: vendor/iris-v1/src/neusym_vul.py   <slug> --query cwe-XXXwLLM --run-id <run_id> --llm gpt-oss-20b
                                          --seed 1234 --label-api-batch-size 30
                                          --label-func-param-batch-size 20 --num-threads 1

Writes runs/<run_id>/cases/<eval_id>/<config>.json with the exit code, duration, stage
completion flags, artifact paths + sha256, IRIS evaluator output and LLM usage.

Exit codes: 0 completed; 1 failed (case-level); 75/76/77 propagated from the OpenRouter
adapter (budget exhausted / API failure / configuration error) so the orchestrator stops.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import (REPO_ROOT, IRIS_DIR, IRIS_SRC, CODEQL_DIR, IRIS_OUTPUT_DIR, CONFIG_DIR, DOTENV_PATH, CWE_TO_QUERY,  # noqa: E402
                    load_json, dump_json, now_iso, sha256_file, run_dir, append_event)

CONDA_PY = os.path.join(REPO_ROOT, "tools", "miniforge3", "envs", "iris", "bin", "python")
FATAL_CODES = (75, 76, 77)


def b0_paths(slug, run_id, query):
    base = os.path.join(IRIS_OUTPUT_DIR, slug, f"{run_id}-b0")
    return {
        "base": base,
        "sarif": os.path.join(base, query, "results.sarif"),
        "csv": os.path.join(base, query, "results.csv"),
        "eval": os.path.join(base, query, "results.json"),
        "func_locs": os.path.join(base, "fetch_func_locs", "results.csv"),
        "class_locs": os.path.join(base, "fetch_class_locs", "results.csv"),
    }


def b2_paths(slug, run_id, query):
    cwe = query.split("wLLM")[0]  # "cwe-022"
    base = os.path.join(IRIS_OUTPUT_DIR, slug, run_id)
    return {
        "base": base,
        "external_apis": os.path.join(base, cwe, "external_apis.csv"),
        "candidate_apis": os.path.join(base, cwe, "candidate_apis.csv"),
        "func_params": os.path.join(base, "common", "func_params.csv"),
        "func_param_candidates": os.path.join(base, "common", "source_func_param_candidates.csv"),
        "labelled_sources": os.path.join(base, cwe, "llm_labelled_source_apis.json"),
        "labelled_sinks": os.path.join(base, cwe, "llm_labelled_sink_apis.json"),
        "labelled_taint_props": os.path.join(base, cwe, "llm_labelled_taint_prop_apis.json"),
        "labelled_func_params": os.path.join(base, "common", "llm_labelled_source_func_params.json"),
        "sources_qll": os.path.join(base, cwe, "MySources.qll"),
        "sinks_qll": os.path.join(base, cwe, "MySinks.qll"),
        "summaries_qll": os.path.join(base, cwe, "MySummaries.qll"),
        "spec_yml": os.path.join(base, cwe, "Spec.yml"),
        "sarif_raw": os.path.join(base, query, "results.sarif"),
        "sarif_pp": os.path.join(base, query, "results_pp.sarif"),
        "results_csv": os.path.join(base, query, "results.csv"),
        "sarif_filtered": os.path.join(base, f"{query}-posthoc-filter", "results.sarif"),
        "posthoc_results": os.path.join(base, f"{query}-posthoc-filter", "results.json"),
        "posthoc_stats": os.path.join(base, f"{query}-posthoc-filter", "stats.json"),
        "eval": os.path.join(base, f"{query}-final", "results.json"),
        "func_locs": os.path.join(base, "fetch_func_locs", "results.csv"),
        "class_locs": os.path.join(base, "fetch_class_locs", "results.csv"),
    }


def artifacts(paths):
    out = {}
    for k, p in paths.items():
        if k == "base":
            continue
        out[k] = {"path": os.path.relpath(p, REPO_ROOT),
                  "exists": os.path.exists(p),
                  "sha256": sha256_file(p) if os.path.isfile(p) else None,
                  "bytes": os.path.getsize(p) if os.path.isfile(p) else None}
    return out


def llm_usage(rdir, slug, query):
    ledger = os.path.join(rdir, "llm", "ledger.jsonl")
    agg = {"requests": 0, "cache_hits": 0, "repair_rerequests": 0, "http_retries": 0, "prompt_tokens": 0,
           "completion_tokens": 0, "reasoning_tokens": 0, "cost_usd": 0.0, "json_invalid": 0,
           "finish_length": 0}
    if not os.path.exists(ledger):
        return agg
    with open(ledger) as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            c = r.get("context") or {}
            if c.get("project") != slug or c.get("query") != query:
                continue
            if r.get("cache_hit"):
                agg["cache_hits"] += 1
                continue
            agg["requests"] += 1
            agg["repair_rerequests"] += 1 if (r.get("repair_round") or 0) > 0 else 0
            agg["http_retries"] += r.get("http_retries") or 0
            for k in ("prompt_tokens", "completion_tokens", "reasoning_tokens"):
                agg[k] += r.get(k) or 0
            agg["cost_usd"] += r.get("cost_usd") or 0.0
            agg["json_invalid"] += 0 if r.get("json_valid") else 1
            agg["finish_length"] += 1 if r.get("finish_reason") == "length" else 0
    return agg


def run_cmd(cmd, env, log_path, timeout_s):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as log:
        log.write(f"\n===== {now_iso()} $ {' '.join(cmd)}\n"); log.flush()
        p = subprocess.Popen(cmd, cwd=IRIS_DIR, env=env, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=timeout_s)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
            rc, timed_out = -9, True
        log.write(f"===== exit {rc}{' (timeout)' if timed_out else ''} @ {now_iso()}\n")
    return rc, timed_out


def tail(path, n=40):
    try:
        with open(path, errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return ""


def finalize(record, args, paths, rdir, llm_query, rc, timed_out, log_path):
    """Fill artifacts, stage flags, evaluation, LLM usage and status into record."""
    ev = load_json(paths["eval"])
    record.update({"exit_code": rc, "timed_out": timed_out, "artifacts": artifacts(paths), "evaluation": ev})
    a = record["artifacts"]
    if args.config == "b0":
        record["stages"] = {"codeql_analysis": a["sarif"]["exists"], "evaluation": ev is not None}
        complete = a["sarif"]["exists"] and ev is not None and "num_results" in (ev or {})
    else:
        record["stages"] = {
            "candidate_extraction": a["candidate_apis"]["exists"] and a["func_param_candidates"]["exists"],
            "spec_inference": all(a[k]["exists"] for k in ("labelled_sources", "labelled_sinks",
                                                             "labelled_taint_props", "labelled_func_params")),
            "query_generation": all(a[k]["exists"] for k in ("sources_qll", "sinks_qll", "summaries_qll")),
            "codeql_analysis": a["sarif_raw"]["exists"],
            "postprocess": a["sarif_pp"]["exists"],
            "contextual_analysis": a["sarif_filtered"]["exists"],
            "evaluation": bool(ev and "vanilla_result" in ev and "posthoc_filter_result" in ev),
        }
        record["llm_usage"] = llm_usage(rdir, args.slug, llm_query)
        complete = record["stages"]["evaluation"]
        # neusym_vul.py exits 1 after re-evaluating cached complete results; that is a success.
    if rc in FATAL_CODES:
        record["status"] = {75: "stopped_budget", 76: "failed_api", 77: "failed_config"}[rc]
    elif complete:
        record["status"] = "completed"
    else:
        record["status"] = "failed"
    if record["status"] != "completed":
        failed_stage = next((s for s, ok in record.get("stages", {}).items() if not ok), None)
        record["failure"] = {"stage": failed_stage, "timed_out": timed_out, "exit_code": rc,
                             "log_tail": tail(log_path)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--config", choices=["b0", "b2"], required=True)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--cwe", required=True, help="CWE used for the query, e.g. CWE-022")
    ap.add_argument("--eval-id", required=True)
    ap.add_argument("--refresh-record", action="store_true")
    args = ap.parse_args()

    exp = load_json(os.path.join(CONFIG_DIR, "experiment.json"))
    rdir = run_dir(args.run_id)
    llm_query, codeql_query = CWE_TO_QUERY[args.cwe]
    out_path = os.path.join(rdir, "cases", args.eval_id, f"{args.config}.json")
    log_path = os.path.join(rdir, "logs", "cases", args.eval_id, f"{args.config}.log")
    prev = load_json(out_path, {}) or {}

    env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
    env["PATH"] = f"{CODEQL_DIR}:{os.path.dirname(os.path.abspath(CONDA_PY))}:{env.get('PATH', '')}"
    env["CODEQL_THREADS"] = str(exp["codeql_limits"]["threads"])
    env["CODEQL_RAM"] = str(exp["codeql_limits"].get("analysis_ram_mb", exp["codeql_limits"]["ram_mb"]))
    env["PYTHONUNBUFFERED"] = "1"
    env["IRIS_REPRO_CODEQL_RAM_MB"] = str(exp["codeql_limits"].get("analysis_ram_mb", ""))
    py = os.path.abspath(CONDA_PY)

    if args.config == "b0":
        paths = b0_paths(args.slug, args.run_id, codeql_query)
        query = codeql_query
        cmd = [py, os.path.join(IRIS_SRC, "codeql_vul.py"), args.slug, "--query", codeql_query,
               "--run-id", f"{args.run_id}-b0", "--overwrite"]
        timeout_s = exp["build_limits"]["b0_timeout_s"]
    else:
        paths = b2_paths(args.slug, args.run_id, llm_query)
        query = llm_query
        ia = exp["iris_args"]
        cmd = [py, os.path.join(IRIS_SRC, "neusym_vul.py"), args.slug, "--query", llm_query,
               "--run-id", args.run_id, "--llm", "gpt-oss-20b", "--seed", str(ia["seed"]),
               "--label-api-batch-size", str(ia["label_api_batch_size"]),
               "--label-func-param-batch-size", str(ia["label_func_param_batch_size"]),
               "--num-threads", str(ia["num_threads"])]
        assert not any(f in cmd for f in ia["ground_truth_flags_forbidden"])
        env.update({
            "IRIS_REPRO_LLM_CONFIG": os.path.join(rdir, "config", "llm_config.json"),
            "IRIS_REPRO_DOTENV": DOTENV_PATH,
            "IRIS_REPRO_PROJECT": args.slug,
            "IRIS_REPRO_QUERY": llm_query,
            "IRIS_REPRO_RUN_ID": args.run_id,
        })
        timeout_s = exp["build_limits"]["b2_timeout_s"]
        # A previous failed attempt may have left half-written stage files. Remove this
        # query's outputs; completed LLM calls are replayed from the run's response cache.
        if prev and prev.get("status") != "completed" and not args.refresh_record:
            for d in (os.path.join(paths["base"], query), os.path.join(paths["base"], f"{query}-posthoc-filter"),
                      os.path.join(paths["base"], f"{query}-final"), os.path.join(paths["base"], query.split("wLLM")[0])):
                shutil.rmtree(d, ignore_errors=True)
            if not os.path.exists(paths["labelled_func_params"]):
                shutil.rmtree(os.path.join(paths["base"], "common"), ignore_errors=True)

    if args.refresh_record:
        # Recompute artifact hashes / stage flags / status from existing outputs without re-running
        # (used after a harness-side path bug); the original timings and exit code are kept.
        if not prev:
            print("no record to refresh"); sys.exit(1)
        record = dict(prev)
        record.pop("failure", None)
        record["record_refreshed"] = now_iso()
        finalize(record, args, paths, rdir, llm_query, prev.get("exit_code"), prev.get("timed_out", False), log_path)
        dump_json(record, out_path)
        append_event(os.path.join(rdir, "events.jsonl"), {"eval_id": args.eval_id, "config": args.config,
                                                          "event": "record_refreshed", "status": record["status"]})
        sys.exit(0 if record["status"] == "completed" else 1)

    attempt = (prev.get("attempt") or 0) + 1
    record = {"eval_id": args.eval_id, "slug": args.slug, "cwe": args.cwe, "config": args.config,
              "query": query, "attempt": attempt, "started": now_iso(), "status": "running",
              "command": cmd}
    dump_json(record, out_path)
    append_event(os.path.join(rdir, "events.jsonl"), {"eval_id": args.eval_id, "config": args.config,
                                                      "event": "start", "attempt": attempt})
    t0 = time.time()
    rc, timed_out = run_cmd(cmd, env, log_path, timeout_s)
    duration = round(time.time() - t0, 1)

    record.update({"finished": now_iso(), "duration_s": duration})
    finalize(record, args, paths, rdir, llm_query, rc, timed_out, log_path)
    dump_json(record, out_path)
    append_event(os.path.join(rdir, "events.jsonl"), {"eval_id": args.eval_id, "config": args.config,
                                                      "event": "end", "status": record["status"],
                                                      "exit_code": rc, "duration_s": duration})
    if rc in FATAL_CODES:
        sys.exit(rc)
    sys.exit(0 if record["status"] == "completed" else 1)


if __name__ == "__main__":
    main()
