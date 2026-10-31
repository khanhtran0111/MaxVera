"""Acquire one CWE-Bench-Java case and build its CodeQL database.

Acquisition uses the upstream script data/cwe-bench-java/scripts/fetch_one.py unchanged
(shallow clone, fetch + checkout of buggy_commit_id, git apply of the dataset patch).
Database creation calls setup_environment() and create_codeql_database() from the upstream
scripts/build_codeql_dbs.py unchanged, i.e. `codeql database create --language java
--overwrite` with CodeQL autobuild under the JDK/Maven recorded in the frozen
data/build_info.csv.

Harness additions (documented in REPRODUCTION_REPORT.md):
  * verification of checked-out commit, patch application and source tree identity
  * CodeQL resource limits through CODEQL_THREADS / CODEQL_RAM, MAVEN_OPTS heap limit
  * Gradle on PATH for the cases whose frozen build metadata names a Gradle version
    (upstream build_codeql_dbs.py only adds Maven, so autobuild could not find `gradle`)
  * a durable per-case status record in runs/_dataset/status/<slug>.json

Exit code 0 when the case has a verified source tree and a finalized database.
"""
import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(__file__))
from common import (CWE_BENCH_DIR, PROJECT_SOURCES_DIR, JAVA_ENV_DIR, CODEQL_DIR, CODEQL_BIN,  # noqa: E402
                    CODEQL_DB_DIR, DATASET_STATE_DIR, IRIS_DIR, build_info, project_info, dump_json,
                    load_json, now_iso, sha256_file, sha256_text, append_event, CONFIG_DIR)


def git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


def verify_source(slug, row):
    src = os.path.join(PROJECT_SOURCES_DIR, slug)
    res = {"path": src, "exists": os.path.isdir(src)}
    if not res["exists"]:
        return False, res
    head = git(["rev-parse", "HEAD"], src).stdout.strip()
    res["head"] = head
    res["expected_commit"] = row["buggy_commit_id"]
    res["commit_ok"] = head == row["buggy_commit_id"]
    res["tree"] = git(["rev-parse", "HEAD^{tree}"], src).stdout.strip()
    patch = os.path.join(CWE_BENCH_DIR, "patches", f"{slug}.patch")
    res["has_patch"] = os.path.exists(patch)
    if res["has_patch"]:
        res["patch_sha256"] = sha256_file(patch)
        res["patch_applied"] = git(["apply", "--reverse", "--check", patch], src).returncode == 0
    else:
        res["patch_applied"] = None
    # Diff of tracked files against the buggy commit (== dataset patch when present)
    diff = git(["diff", "HEAD"], src).stdout
    res["worktree_diff_sha256"] = sha256_text(diff)
    ok = res["commit_ok"] and (res["patch_applied"] in (None, True))
    return ok, res


def fetch(slug, row, log, attempts=3):
    for attempt in range(1, attempts + 1):
        ok, info = verify_source(slug, row)
        if ok:
            return True, info
        if info["exists"]:
            log.write(f"[prepare] source tree invalid ({info}); removing and refetching (attempt {attempt})\n")
            shutil.rmtree(os.path.join(PROJECT_SOURCES_DIR, slug))
        os.makedirs(PROJECT_SOURCES_DIR, exist_ok=True)
        p = subprocess.run([sys.executable, os.path.join(CWE_BENCH_DIR, "scripts", "fetch_one.py"), slug],
                           stdout=log, stderr=subprocess.STDOUT)
        log.flush()
    return verify_source(slug, row)


def db_is_finalized(slug):
    db = os.path.join(CODEQL_DB_DIR, slug)
    yml = os.path.join(db, "codeql-database.yml")
    if not (os.path.isdir(os.path.join(db, "db-java")) and os.path.exists(yml)):
        return False
    with open(yml) as f:
        return "finalised: true" in f.read()


def dir_size(path):
    total = 0
    for dp, _, fns in os.walk(path):
        for fn in fns:
            try:
                total += os.path.getsize(os.path.join(dp, fn))
            except OSError:
                pass
    return total


def build_db(slug, brow, limits, log):
    sys.path.insert(0, os.path.join(IRIS_DIR, "scripts"))
    sys.path.insert(0, IRIS_DIR)
    import build_codeql_dbs as upstream  # noqa: E402

    with contextlib.redirect_stdout(log):
        env = upstream.setup_environment(brow, JAVA_ENV_DIR)
    env["PATH"] = f"{CODEQL_DIR}:{env['PATH']}"
    if brow.get("gradle_version", "n/a") not in ("n/a", ""):
        env["PATH"] = f"{os.path.join(JAVA_ENV_DIR, 'gradle-' + brow['gradle_version'], 'bin')}:{env['PATH']}"
        log.write(f"[prepare] compat: added gradle-{brow['gradle_version']} to PATH\n")
    # Fallback tools, appended AFTER the case-specific frozen JDK/Maven/Gradle: the host has no system-wide
    # mvn/gradle, whereas CodeQL autobuild helpers call `mvn dependency:copy` / `gradle wrapper` by name.
    # Only affects databases that are (re)built after this was added.
    fb = [os.path.join(JAVA_ENV_DIR, "apache-maven-3.5.0", "bin"), os.path.join(JAVA_ENV_DIR, "gradle-7.6.4", "bin")]
    env["PATH"] = env["PATH"] + ":" + ":".join(fb)
    env["CODEQL_THREADS"] = str(limits["codeql_limits"]["threads"])
    env["CODEQL_RAM"] = str(limits["codeql_limits"]["ram_mb"])
    env["MAVEN_OPTS"] = limits["build_limits"]["maven_opts"]
    env.pop("OPENROUTER_API_KEY", None)
    log.flush()
    # create_codeql_database prints through print(); route it to the log, and the codeql
    # subprocess inherits fd 1/2, which the caller already points at the log file.
    with contextlib.redirect_stdout(log):
        upstream.create_codeql_database(slug, env, CODEQL_DB_DIR, PROJECT_SOURCES_DIR)
    return env


def ensure_package_names(slug, limits, log):
    """Regenerate a missing package-names file with the upstream tool (documented override list only)."""
    target = os.path.join(CWE_BENCH_DIR, "package-names", f"{slug}.txt")
    if os.path.exists(target):
        return {"status": "upstream", "sha256": sha256_file(target)}
    override = limits.get("package_names_regeneration", {}).get("internal_package", {}).get(slug)
    if not override:
        return {"status": "missing", "reason": "package-names file absent and no documented regeneration override"}
    workdir = os.path.join(DATASET_STATE_DIR, "pkgnames_work", slug)
    os.makedirs(workdir, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
    env["PATH"] = f"{CODEQL_DIR}:{env.get('PATH', '')}"
    env["CODEQL_THREADS"] = str(limits["codeql_limits"]["threads"])
    env["CODEQL_RAM"] = str(limits["codeql_limits"]["ram_mb"])
    cmd = [sys.executable, os.path.join(IRIS_DIR, "scripts", "get_packages_codeql.py"), slug, "--internal-package", override]
    log.write(f"[prepare] regenerating package-names: {' '.join(cmd)}\n"); log.flush()
    subprocess.run(cmd, cwd=workdir, stdout=log, stderr=subprocess.STDOUT, env=env)
    if not os.path.exists(target) or os.path.getsize(target) == 0:
        return {"status": "failed", "reason": "get_packages_codeql.py produced no packages", "internal_package": override}
    n = sum(1 for l in open(target) if l.strip())
    return {"status": "regenerated", "internal_package": override, "num_packages": n, "sha256": sha256_file(target),
            "tool": "scripts/get_packages_codeql.py"}


def attempt_db(slug, brow, limits, log, t0):
    try:
        build_db(slug, brow, limits, log)
        finalized = db_is_finalized(slug)
        return {
            "status": "ok" if finalized else "failed",
            "reason": None if finalized else "database not finalized",
            "jdk": brow["jdk_version"], "mvn": brow["mvn_version"], "gradle": brow["gradle_version"],
            "use_gradlew": brow["use_gradlew"],
            "codeql_threads": limits["codeql_limits"]["threads"], "codeql_ram_mb": limits["codeql_limits"]["ram_mb"],
            "size_bytes": dir_size(os.path.join(CODEQL_DB_DIR, slug)) if finalized else None,
            "ts": now_iso(), "duration_s": round(time.time() - t0, 1),
        }
    except Exception as e:
        log.write(traceback.format_exc()); log.flush()
        return {"status": "failed", "reason": f"{type(e).__name__}: {str(e)[:500]}",
                "jdk": brow["jdk_version"], "mvn": brow["mvn_version"], "gradle": brow["gradle_version"],
                "ts": now_iso(), "duration_s": round(time.time() - t0, 1)}


def upstream_prebuild(slug, brow, log):
    """Run the upstream build_one.py attempt function with the frozen build configuration.

    build_one.build_one_project() is not used because it rewrites data/build_info.csv; the attempt
    functions only write build-info/<slug>.json. Output goes to the case log."""
    sys.path.insert(0, os.path.join(CWE_BENCH_DIR, "scripts"))
    import build_one as upstream_build  # noqa: E402
    attempt = {"jdk": brow["jdk_version"]}
    if brow.get("mvn_version", "n/a") != "n/a":
        attempt["mvn"] = brow["mvn_version"]; fn = upstream_build.build_one_project_with_maven_attempt
    elif brow.get("gradle_version", "n/a") != "n/a":
        attempt["gradle"] = brow["gradle_version"]; fn = upstream_build.build_one_project_with_gradle_attempt
    else:
        attempt["gradlew"] = 1; fn = upstream_build.build_one_project_with_gradlew
    t0 = time.time()
    log.write(f"[prepare] upstream prebuild (build_one.py) with {attempt}\n"); log.flush()
    with contextlib.redirect_stdout(log):
        result = fn(slug, attempt)
    log.flush()
    return {"attempt": attempt, "result": result, "status": "ok" if result == upstream_build.NEWLY_BUILT else "failed",
            "duration_s": round(time.time() - t0, 1), "ts": now_iso()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("slug")
    ap.add_argument("--force-db", action="store_true")
    args = ap.parse_args()
    slug = args.slug
    limits = load_json(os.path.join(CONFIG_DIR, "experiment.json"))

    rows = {r["project_slug"]: r for r in project_info()}
    if slug not in rows:
        print(f"unknown slug {slug}"); sys.exit(2)
    row, brow = rows[slug], build_info()[slug]
    status_path = os.path.join(DATASET_STATE_DIR, "status", f"{slug}.json")
    status = load_json(status_path, {}) or {}
    status.update({"slug": slug, "cve_id": row["cve_id"], "cwe_id": row["cwe_id"],
                   "frozen_build_info": brow})
    events = os.path.join(DATASET_STATE_DIR, "events.jsonl")
    log_path = os.path.join(DATASET_STATE_DIR, "logs", f"{slug}.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    with open(log_path, "a") as log:
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
        log.write(f"\n===== prepare {slug} @ {now_iso()} =====\n"); log.flush()

        t0 = time.time()
        ok, src_info = fetch(slug, row, log)
        status["source"] = {**src_info, "status": "ok" if ok else "failed",
                            "ts": now_iso(), "duration_s": round(time.time() - t0, 1)}
        dump_json(status, status_path)
        append_event(events, {"slug": slug, "stage": "fetch", "status": status["source"]["status"]})
        if not ok:
            status["db"] = {"status": "skipped", "reason": "source acquisition/verification failed"}
            dump_json(status, status_path)
            sys.exit(1)

        if db_is_finalized(slug) and not args.force_db and (status.get("db") or {}).get("status") == "ok":
            log.write("[prepare] finalized database already present; skipping\n")
            status["package_names"] = ensure_package_names(slug, limits, log)
            dump_json(status, status_path)
            sys.exit(0 if status["package_names"]["status"] in ("upstream", "regenerated") else 1)

        t0 = time.time()
        status["db"] = attempt_db(slug, brow, limits, log, t0)
        if status["db"]["status"] != "ok" and brow.get("status") == "success":
            # Upstream order is setup.py (build_one.py with the frozen JDK/Maven/Gradle, which fills the
            # local Maven/Gradle caches) followed by build_codeql_dbs.py. Run that upstream build step and
            # retry database creation once.
            first_failure = status["db"]
            status["prebuild"] = upstream_prebuild(slug, brow, log)
            dump_json(status, status_path)
            status["db"] = attempt_db(slug, brow, limits, log, time.time())
            status["db"]["first_attempt_failure"] = first_failure.get("reason")
            status["db"]["after_upstream_prebuild"] = True
        if status["db"]["status"] == "ok":
            status["package_names"] = ensure_package_names(slug, limits, log)
            if status["package_names"]["status"] not in ("upstream", "regenerated"):
                status["db"]["status"] = "failed"
                status["db"]["reason"] = f"package-names: {status['package_names'].get('reason')}"
        dump_json(status, status_path)
        append_event(events, {"slug": slug, "stage": "db", "status": status["db"]["status"],
                              "reason": status["db"].get("reason")})
        sys.exit(0 if status["db"]["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
