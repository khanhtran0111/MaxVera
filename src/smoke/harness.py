"""Run and validate the disposable Phase 3 analysis/evaluation smoke path."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from src.common.envfile import effective_env
from src.common.provenance import collect_git, sha256_file, utc_now

CsvRow = dict[str, str]

SMOKE_FIELDS = (
    "schema_version",
    "mode",
    "slot_id",
    "project_id",
    "source_dir",
    "codeql_database",
)
FORBIDDEN_ANALYSIS_FIELDS = {
    "cve_id",
    "ground_truth_cwe",
    "advisory_text",
    "patch_commit",
    "fix_commit",
    "fixed_method",
    "fixed_line",
    "vulnerable_description",
}


def _read_csv(path: Path) -> list[CsvRow]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def validate_smoke_manifest(repo_root: Path) -> list[CsvRow]:
    """Validate that the retained smoke manifest is opaque and runnable."""
    path = repo_root / "data/processed/manifests/smoke.csv"
    rows = _read_csv(path)
    if len(rows) != 4:
        raise ValueError(f"smoke manifest must contain four projects, found {len(rows)}")
    if tuple(rows[0]) != SMOKE_FIELDS:
        raise ValueError("smoke manifest schema mismatch")
    if FORBIDDEN_ANALYSIS_FIELDS.intersection(rows[0]):
        raise ValueError("smoke manifest exposes evaluator-only fields")
    identifiers: set[str] = set()
    for row in rows:
        if row["schema_version"] != "1" or row["mode"] != "smoke":
            raise ValueError("every smoke row must declare schema_version=1 and mode=smoke")
        project_id = row["project_id"]
        if project_id in identifiers:
            raise ValueError(f"duplicate smoke project: {project_id}")
        identifiers.add(project_id)
        for field in ("source_dir", "codeql_database"):
            candidate = (repo_root / row[field]).resolve()
            if not candidate.is_dir():
                raise ValueError(f"smoke input is missing: {row[field]}")
    return rows


def validate_candidate(value: Any) -> dict[str, Any]:
    """Enforce the bounded candidate-extraction response schema."""
    if not isinstance(value, dict):
        raise ValueError("candidate response is not a JSON object")
    required = {"candidate_type", "source", "sink", "confidence", "abstain"}
    if set(value) != required:
        raise ValueError("candidate response fields do not match the smoke schema")
    for field in ("candidate_type", "source", "sink"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ValueError(f"candidate field {field} must be a non-empty string")
    confidence = value["confidence"]
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise ValueError("candidate confidence must be numeric")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("candidate confidence must be between zero and one")
    if not isinstance(value["abstain"], bool):
        raise ValueError("candidate abstain must be boolean")
    return cast(dict[str, Any], value)


def candidate_from_text(content: str) -> dict[str, Any]:
    """Extract one JSON object while tolerating harmless model wrappers."""
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            stripped = "\n".join(lines[1:-1]).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        preview = stripped[:120].replace("\n", " ")
        raise ValueError(f"model content has no JSON object; prefix={preview!r}")
    return validate_candidate(json.loads(stripped[start : end + 1]))


def parse_sarif(path: Path) -> int:
    """Validate the minimum SARIF contract and return its result count."""
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not str(loaded.get("version", "")).startswith("2.1"):
        raise ValueError(f"invalid SARIF version: {path}")
    runs = loaded.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError(f"SARIF has no runs: {path}")
    count = 0
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError(f"SARIF run is not an object: {path}")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError(f"SARIF results are not an array: {path}")
        count += len(results)
    return count


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _post_json(url: str, payload: Mapping[str, Any], timeout: int = 300) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        loaded = json.loads(response.read().decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("model endpoint returned a non-object response")
    return cast(dict[str, Any], loaded)


def _wait_for_endpoint(endpoint: str, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    health = f"{endpoint.rstrip('/')}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health, timeout=5) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise ValueError(f"model endpoint did not become healthy within {timeout} seconds")


def _candidate_from_model(endpoint: str) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt = (
        "Inspect this synthetic Java smoke fixture and return exactly one JSON object with "
        "candidate_type, source, sink, confidence, abstain. Do not use Markdown. "
        "Fixture: class Smoke { void run(String command) throws Exception { "
        "Runtime.getRuntime().exec(command); } }"
    )
    payload: dict[str, Any] = {
        "model": "qwen-smoke",
        "messages": [
            {"role": "system", "content": "You extract bounded security candidates as JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 1234,
        "max_tokens": 256,
        "response_format": {"type": "json_object"},
    }
    last_error = "no response"
    for _attempt in range(1, 4):
        response = _post_json(f"{endpoint.rstrip('/')}/v1/chat/completions", payload)
        try:
            choices = response["choices"]
            if not isinstance(choices, list) or not choices:
                raise ValueError("model response has no choices")
            choice = choices[0]
            if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
                raise ValueError("model response choice has no message")
            content = cast(dict[str, Any], choice["message"]).get("content")
            if not isinstance(content, str):
                raise ValueError("model response content is not text")
            candidate = candidate_from_text(content)
            usage = response.get("usage", {})
            return candidate, cast(dict[str, Any], usage) if isinstance(usage, dict) else {}
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            last_error = str(error)
            payload["messages"] = [
                *cast(list[dict[str, str]], payload["messages"]),
                {
                    "role": "user",
                    "content": "Retry with only the exact five-field JSON object.",
                },
            ]
    raise ValueError(f"candidate schema failed after three attempts: {last_error}")


def _codeql_binary(configured: str) -> Path:
    home = Path(configured).expanduser().resolve()
    candidates = (home, home / "codeql", home / "bin/codeql")
    binary = next((item for item in candidates if item.is_file()), None)
    if binary is None:
        raise ValueError("MAXVERA_CODEQL_HOME does not resolve to CodeQL")
    return binary


def analyze(
    repo_root: Path,
    run_id: str,
    result_dir: Path,
    log_dir: Path,
    endpoint: str,
) -> None:
    rows = validate_smoke_manifest(repo_root)
    machine = effective_env(repo_root / ".env")
    configured = machine.get("MAXVERA_CODEQL_HOME")
    if not configured:
        raise ValueError("MAXVERA_CODEQL_HOME is not configured")
    codeql = _codeql_binary(configured)
    manifest_path = repo_root / "data/processed/manifests/smoke.csv"
    _write_json(
        result_dir / "manifest.json",
        {
            "schema_version": 1,
            "mode": "smoke",
            "run_id": run_id,
            "started_at": utc_now(),
            "git": collect_git(repo_root),
            "smoke_manifest_sha256": sha256_file(manifest_path),
            "reuse_in_full_run": "forbidden",
            "seed": 1234,
        },
    )
    _wait_for_endpoint(endpoint)
    candidate, usage = _candidate_from_model(endpoint)
    _write_json(result_dir / "candidate.json", candidate)
    _write_json(result_dir / "llm_usage.json", usage)

    query = repo_root / "src/static_analysis/queries/smoke_method_inventory.ql"
    statuses: list[dict[str, Any]] = []
    sarif_counts: dict[str, int] = {}
    sarif_dir = result_dir / "sarif"
    sarif_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    for row in rows:
        project_id = row["project_id"]
        sarif = sarif_dir / f"{project_id}.sarif"
        command = [
            str(codeql),
            "database",
            "analyze",
            str((repo_root / row["codeql_database"]).resolve()),
            str(query),
            "--format=sarif-latest",
            f"--output={sarif}",
            "--threads=2",
            "--ram=4096",
            "--rerun",
        ]
        process = subprocess.run(command, check=False, capture_output=True, text=True, timeout=900)
        command_output = process.stdout + process.stderr
        (log_dir / f"codeql_{project_id}.log").write_text(
            command_output, encoding="utf-8"
        )
        if process.returncode != 0:
            tail = "\n".join(command_output.splitlines()[-12:])
            raise ValueError(
                f"CodeQL smoke query failed for {project_id}: {process.returncode}\n{tail}"
            )
        sarif_counts[project_id] = parse_sarif(sarif)
        statuses.append(
            {
                "schema_version": 1,
                "mode": "smoke",
                "project_id": project_id,
                "status": "SUCCESS",
                "sarif_results": sarif_counts[project_id],
            }
        )
    with (result_dir / "project_status.jsonl").open("w", encoding="utf-8") as handle:
        for status in statuses:
            handle.write(json.dumps(status, sort_keys=True) + "\n")
    _write_json(
        result_dir / "analysis_summary.json",
        {
            "schema_version": 1,
            "mode": "smoke",
            "candidate_schema_valid": True,
            "projects": len(statuses),
            "sarif_result_counts": sarif_counts,
        },
    )


def evaluate(repo_root: Path, result_dir: Path) -> None:
    rows = validate_smoke_manifest(repo_root)
    summary = json.loads((result_dir / "analysis_summary.json").read_text(encoding="utf-8"))
    labels = _read_csv(repo_root / "data/processed/evaluator_only/D_repro_v1_labels.csv")
    labels_by_id = {row["project_id"]: row for row in labels}
    evaluated: list[dict[str, Any]] = []
    for row in rows:
        project_id = row["project_id"]
        label = labels_by_id.get(project_id)
        if label is None:
            raise ValueError(f"evaluator label is missing for {project_id}")
        evaluated.append(
            {
                "project_id": project_id,
                "ground_truth_available": True,
                "ground_truth_family": label["ground_truth_cwe"],
                "analysis_status": "SUCCESS",
            }
        )
    _write_json(
        result_dir / "metrics_aggregate.json",
        {
            "schema_version": 1,
            "mode": "smoke",
            "technical_pass": bool(summary.get("candidate_schema_valid"))
            and len(evaluated) == 4,
            "evaluated_projects": len(evaluated),
            "scientific_result": False,
        },
    )
    with (result_dir / "metrics_project.jsonl").open("w", encoding="utf-8") as handle:
        for item in evaluated:
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def validate_result(repo_root: Path, result_dir: Path) -> None:
    rows = validate_smoke_manifest(repo_root)
    required = (
        "manifest.json",
        "candidate.json",
        "llm_usage.json",
        "analysis_summary.json",
        "project_status.jsonl",
        "metrics_project.jsonl",
        "metrics_aggregate.json",
    )
    missing = [name for name in required if not (result_dir / name).is_file()]
    if missing:
        raise ValueError("smoke result is incomplete: " + ", ".join(missing))
    manifest = json.loads((result_dir / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((result_dir / "metrics_aggregate.json").read_text(encoding="utf-8"))
    statuses = [
        json.loads(line)
        for line in (result_dir / "project_status.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    validate_candidate(json.loads((result_dir / "candidate.json").read_text(encoding="utf-8")))
    if manifest.get("mode") != "smoke" or manifest.get("reuse_in_full_run") != "forbidden":
        raise ValueError("smoke manifest does not enforce isolation")
    if metrics.get("technical_pass") is not True:
        raise ValueError("smoke evaluator did not pass")
    expected_ids = {row["project_id"] for row in rows}
    actual_ids = {str(item.get("project_id")) for item in statuses}
    if actual_ids != expected_ids or any(item.get("status") != "SUCCESS" for item in statuses):
        raise ValueError("smoke project statuses are incomplete")
    for row in rows:
        parse_sarif(result_dir / "sarif" / f"{row['project_id']}.sarif")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("analyze", "evaluate", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--repo-root", type=Path, default=Path.cwd())
        command.add_argument("--result-dir", type=Path, required=True)
        if name == "analyze":
            command.add_argument("--run-id", required=True)
            command.add_argument("--log-dir", type=Path, required=True)
            command.add_argument("--endpoint", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.repo_root.resolve()
    result = args.result_dir.resolve()
    try:
        if args.command == "analyze":
            analyze(root, str(args.run_id), result, args.log_dir.resolve(), str(args.endpoint))
        elif args.command == "evaluate":
            evaluate(root, result)
        else:
            validate_result(root, result)
    except (
        OSError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
        urllib.error.URLError,
    ) as error:
        print(f"ERROR: {error}")
        return 1
    print(f"Smoke {args.command} passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
