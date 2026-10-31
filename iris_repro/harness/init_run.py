"""Create an immutable run directory with frozen configuration and manifests.

runs/<run_id>/
  run_manifest.json            cohort, run type, cost limit, config hashes, upstream revisions
  config/llm_config.json       instantiated OpenRouter config (no secrets)
  config/experiment.json       snapshot of iris_repro/config/experiment.json
  manifests/environment.json   CodeQL / JDK / Maven / Gradle / Python versions, patch hash
  manifests/model_api.json     model + provider + decoding configuration (no secrets)
  manifests/dataset_manifest.* dataset manifest snapshot at run creation
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (REPO_ROOT, IRIS_DIR, CODEQL_BIN, JAVA_ENV_DIR, CONFIG_DIR, DATASET_STATE_DIR,  # noqa: E402
                    load_json, dump_json, now_iso, sha256_file, run_dir)


def sh(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
        return (p.stdout + p.stderr).strip()
    except Exception as e:
        return f"ERROR: {e}"


def environment_manifest():
    pins = load_json(os.path.join(CONFIG_DIR, "pins.json"))
    conda_py = os.path.join(REPO_ROOT, "tools", "miniforge3", "envs", "iris", "bin", "python")
    jdks = {}
    for v, info in pins["jdks"].items():
        jdks[v] = sh([os.path.join(JAVA_ENV_DIR, info["dir"], "bin", "java"), "-version"])
    qlpacks = sh(["bash", "-c", f"ls {IRIS_DIR}/codeql/qlpacks/codeql"])
    return {
        "generated": now_iso(),
        "host": {"platform": platform.platform(), "cpus": os.cpu_count(),
                 "mem_gb": round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 2**30, 1)},
        "iris": {"commit": sh(["git", "rev-parse", "HEAD"], IRIS_DIR),
                 "submodule": sh(["git", "submodule", "status", "--recursive"], IRIS_DIR),
                 "local_changes": sh(["git", "status", "--short"], IRIS_DIR).splitlines(),
                 "compat_patch_sha256": sha256_file(os.path.join(REPO_ROOT, "iris_repro", "patches", "iris-v1-compat.patch"))},
        "codeql": {"version": sh([CODEQL_BIN, "version", "--format=json"]),
                   "qlpacks": qlpacks.split(),
                   "java_queries_dir": sh(["bash", "-c", f"ls {IRIS_DIR}/codeql/qlpacks/codeql/java-queries"]),
                   "java_all_dir": sh(["bash", "-c", f"ls {IRIS_DIR}/codeql/qlpacks/codeql/java-all"]),
                   "zip_sha256": sha256_file(os.path.join(REPO_ROOT, "tools", "downloads", "codeql-0.8.3-patched.zip"))},
        "jdks": jdks,
        "maven": {v: sh([os.path.join(JAVA_ENV_DIR, f"apache-maven-{v}", "bin", "mvn"), "-v"]).splitlines()[:1]
                  for v in pins["maven"]},
        "gradle": sorted(d for d in os.listdir(JAVA_ENV_DIR) if d.startswith("gradle-")),
        "python": {"version": sh([conda_py, "--version"]),
                   "packages": sh([os.path.join(os.path.dirname(conda_py), "conda"), "list", "--json"]) if False else
                   sh([conda_py, "-c", "import importlib.metadata as m,json;print(json.dumps({d.metadata['Name']:d.version for d in m.distributions()},sort_keys=True))"])},
        "pins": pins,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--cohort", choices=["smoke", "full"], required=True)
    ap.add_argument("--projects", nargs="*")
    ap.add_argument("--cost-limit-usd", type=float, required=True)
    args = ap.parse_args()

    rdir = run_dir(args.run_id)
    if os.path.exists(os.path.join(rdir, "run_manifest.json")):
        print(f"run {args.run_id} already exists; refusing to overwrite (use resume)"); sys.exit(1)
    os.makedirs(os.path.join(rdir, "config"), exist_ok=True)

    tmpl = open(os.path.join(CONFIG_DIR, "llm_gpt_oss_20b_openrouter.json")).read()
    llm_cfg = json.loads(tmpl.replace("__RUN_DIR__", rdir).replace('"__COST_LIMIT__"', str(args.cost_limit_usd)))
    dump_json(llm_cfg, os.path.join(rdir, "config", "llm_config.json"))
    shutil.copy(os.path.join(CONFIG_DIR, "experiment.json"), os.path.join(rdir, "config", "experiment.json"))

    env_m = environment_manifest()
    dump_json(env_m, os.path.join(rdir, "manifests", "environment.json"))
    dotenv_provider = None
    if os.path.exists(os.path.join(REPO_ROOT, ".env")):
        for line in open(os.path.join(REPO_ROOT, ".env")):
            if line.startswith("MAXVERA_OPENROUTER_PROVIDER="):
                dotenv_provider = line.split("=", 1)[1].strip()
    dump_json({
        "provider_platform": "OpenRouter", "base_url": llm_cfg["base_url"], "requested_model": llm_cfg["model"],
        "iris_llm_name": llm_cfg["iris_llm_name"], "provider_routing": llm_cfg["provider"],
        "decoding": llm_cfg["decoding"], "concurrency": llm_cfg["concurrency"], "retry": llm_cfg["retry"],
        "timeouts": llm_cfg["timeouts"], "json_validation": llm_cfg["json_validation"],
        "cost_limit_usd": args.cost_limit_usd, "api_key": "read from .env at request time; never stored",
        "dotenv_provider_value": dotenv_provider,
        "note": ("The task specification pins the groq route; .env's MAXVERA_OPENROUTER_PROVIDER is recorded "
                 "here but not used for routing."),
        "config_sha256": sha256_file(os.path.join(rdir, "config", "llm_config.json")),
    }, os.path.join(rdir, "manifests", "model_api.json"))

    for f in ("dataset_manifest.json", "dataset_manifest.csv"):
        p = os.path.join(DATASET_STATE_DIR, f)
        if os.path.exists(p):
            shutil.copy(p, os.path.join(rdir, "manifests", f"at_init_{f}"))

    dump_json({
        "run_id": args.run_id, "created": now_iso(), "cohort": args.cohort, "projects": args.projects,
        "official": args.cohort == "full", "cost_limit_usd": args.cost_limit_usd,
        "iris_commit": env_m["iris"]["commit"], "compat_patch_sha256": env_m["iris"]["compat_patch_sha256"],
        "llm_config_sha256": sha256_file(os.path.join(rdir, "config", "llm_config.json")),
        "experiment_config_sha256": sha256_file(os.path.join(rdir, "config", "experiment.json")),
        "configs": ["b0", "b2"],
    }, os.path.join(rdir, "run_manifest.json"))
    print(f"initialized {rdir}")


if __name__ == "__main__":
    main()
