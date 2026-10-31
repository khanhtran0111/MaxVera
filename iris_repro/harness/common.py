"""Shared paths and helpers for the IRIS v1 reproduction harness."""
import csv
import datetime as _dt
import fcntl
import hashlib
import json
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPRO_DIR = os.path.join(REPO_ROOT, "iris_repro")
CONFIG_DIR = os.path.join(REPRO_DIR, "config")
IRIS_DIR = os.path.join(REPO_ROOT, "vendor", "iris-v1")
IRIS_SRC = os.path.join(IRIS_DIR, "src")
CWE_BENCH_DIR = os.path.join(IRIS_DIR, "data", "cwe-bench-java")
PROJECT_SOURCES_DIR = os.path.join(CWE_BENCH_DIR, "project-sources")
JAVA_ENV_DIR = os.path.join(CWE_BENCH_DIR, "java-env")
CODEQL_DIR = os.path.join(IRIS_DIR, "codeql")
CODEQL_BIN = os.path.join(CODEQL_DIR, "codeql")
CODEQL_DB_DIR = os.path.join(IRIS_DIR, "data", "codeql-dbs")
IRIS_OUTPUT_DIR = os.path.join(IRIS_DIR, "output")
RUNS_DIR = os.path.join(REPO_ROOT, "runs")
DATASET_STATE_DIR = os.path.join(REPO_ROOT, "runs", "_dataset")
DOTENV_PATH = os.path.join(REPO_ROOT, ".env")

CWE_TO_QUERY = {
    "CWE-022": ("cwe-022wLLM", "cwe-022wCodeQL"),
    "CWE-078": ("cwe-078wLLM", "cwe-078wCodeQL"),
    "CWE-079": ("cwe-079wLLM", "cwe-079wCodeQL"),
    "CWE-094": ("cwe-094wLLM", "cwe-094wCodeQL"),
}


def now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def md5_file(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_csv_dicts(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def write_csv_dicts(rows, path, fieldnames=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if fieldnames is None:
        fieldnames = []
        for r in rows:
            for k in r:
                if k not in fieldnames:
                    fieldnames.append(k)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    os.replace(tmp, path)


def project_info():
    """The 120-row CWE-Bench-Java manifest, in upstream order."""
    return read_csv_dicts(os.path.join(CWE_BENCH_DIR, "data", "project_info.csv"))


def build_info():
    return {r["project_slug"]: r for r in read_csv_dicts(os.path.join(CWE_BENCH_DIR, "data", "build_info.csv"))}


def append_event(path, record):
    """Append one JSON line under an exclusive lock (status/event logs)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    record = dict(record)
    record.setdefault("ts", now_iso())
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(record) + "\n")
        f.flush()
        fcntl.flock(f, fcntl.LOCK_UN)


def run_dir(run_id):
    return os.path.join(RUNS_DIR, run_id)
