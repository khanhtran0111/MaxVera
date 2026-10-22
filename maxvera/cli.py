"""Single public CLI for preparation, pipelines and isolated evaluation."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from maxvera.contracts import PipelineConfig, digest, safe_id
from maxvera.dataset import select_cases
from maxvera.orchestration import Orchestrator
from src.common.provenance import sha256_file


def implementation_hash(root: Path) -> str:
    # Include source content and pinned third-party state, including dirty tracked files.
    files = {}
    for directory in ("maxvera", "src", "configs", "third_party/iris/src"):
        for p in sorted((root / directory).rglob("*")):
            if p.is_file() and p.suffix in {".py", ".ql", ".qll", ".yaml", ".yml"}:
                files[p.relative_to(root).as_posix()] = sha256_file(p)
    return digest(files)


def input_fingerprints(root: Path, cases: list[dict], *, research: bool) -> list[dict]:
    if not research:
        return cases
    view = (root / "data/processed/analysis_input").resolve()
    result = []
    for case in cases:
        source = (view / case["source_dir"]).resolve()
        if not source.is_relative_to(view):
            raise ValueError("source path escapes analysis_input")
        from maxvera.snapshots import source_inventory

        hashes = source_inventory(source) if source.exists() else {}
        result.append(
            {**case, "snapshot_content_hash": digest(hashes), "snapshot_available": source.is_dir()}
        )
    return result


def locate(root: Path, run_id: str) -> Path:
    safe_id(run_id)
    candidates = [
        root / "results" / d / run_id
        for d in ("reproduction", "research", "_smoke/reproduction", "_smoke/research")
    ]
    found = [p for p in candidates if p.is_dir() and (p / "manifest.json").is_file()]
    if len(found) != 1:
        raise ValueError("run ID missing or ambiguous across pipelines/modes")
    return found[0]


def _variant(root, config, name):
    definitions = {
        "static_only": {
            "candidate_sources": ["static_alerts"],
            "graph_enabled": False,
            "llm_enabled": False,
            "targeted_verification": False,
            "retrieval": None,
        },
        "graph_only": {
            "candidate_sources": ["static_alerts", "sink_backward_slice", "source_forward_slice"],
            "graph_enabled": True,
            "llm_enabled": False,
            "targeted_verification": False,
            "retrieval": "minimal_subgraph",
        },
    }
    if config.variants.get("config"):
        definitions = yaml.safe_load((root / config.variants["config"]).read_text())["variants"]
    name = name or config.research.get("default_variant", "graph_only")
    if name not in definitions:
        raise ValueError("unknown research variant")
    result = {**definitions[name], "name": name}
    if result.get("llm_enabled") or result.get("targeted_verification"):
        raise ValueError(
            "W7/W8 NOT_IMPLEMENTED: gated until frozen graph-only dev signal is reviewed (plan §10)"
        )
    return result


def doctor(root, path):
    from maxvera.sandbox import landlock_available
    from src.llm.providers.openrouter import OpenRouterSettings

    raw = yaml.safe_load(path.read_text())
    checks = {
        "python": sys.version.split()[0],
        "landlock_available": landlock_available(),
        "network_requests": 0,
    }
    for name in ("repro_binary", "research_binary"):
        p = (root / raw["codeql"][name]).resolve()
        checks[name] = {"present": p.is_file()}
        if p.is_file():
            result = subprocess.run(
                [str(p), "version", "--format=terse"], capture_output=True, text=True, timeout=30
            )
            checks[name].update({"exit_code": result.returncode, "version": result.stdout.strip()})
    try:
        settings = OpenRouterSettings.load(root, Path(raw["llm"]["model_config"]))
        checks["model"] = {
            "model": settings.model,
            "provider": settings.provider,
            "credentials_present": True,
            "route_live_verified": False,
        }
    except ValueError as e:
        checks["model"] = {"credentials_present": False, "error": str(e)}
    checks["dataset_manifest_present"] = (
        root / "data/processed/manifests/cwe_bench_v1.csv"
    ).is_file()
    print(json.dumps(checks, indent=2))
    return (
        0
        if all(
            checks[k].get("present") and checks[k].get("exit_code") == 0
            for k in ("repro_binary", "research_binary")
        )
        and checks["landlock_available"]
        and checks["model"]["credentials_present"]
        else 1
    )


def pipeline(root, args):
    config = PipelineConfig.load(args.config)
    if config.pipeline != args.pipeline:
        raise ValueError("pipeline/config mismatch")
    resolved = config.resolved()
    if args.pipeline == "research":
        resolved["selected_variant"] = _variant(root, config, args.variant)
        stages = [
            "ingest",
            "static_extract",
            "build_graph",
            "candidate_generate",
            "candidate_rank",
            "evidence_retrieve",
            "llm_reason",
            "targeted_verify",
            "final_rank",
        ]
    else:
        if args.variant:
            raise ValueError("reproduction has no zero-hint variant")
        stages = [
            "prepare",
            "codeql_db",
            "codeql_reference",
            "candidate_extract",
            "llm_specs",
            "static_taint",
            "context_filter",
            "finalize",
        ]
    cases = select_cases(
        root, config.dataset, args.mode, args.limit, oracle=args.pipeline == "reproduce"
    )
    dry = args.dry_run or (config.runtime.dry_run_default and not args.execute)
    if dry:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "pipeline": args.pipeline,
                    "mode": args.mode,
                    "run_id": args.run_id,
                    "cases": len(cases),
                    "dag": stages,
                    "expected_requests_upper_bound": len(cases) * config.budgets.max_calls_per_case
                    if args.pipeline == "reproduce"
                    else 0,
                    "configured_cost_ceiling_usd": len(cases) * config.budgets.max_cost_usd_per_case
                    if args.pipeline == "reproduce"
                    else 0,
                    "config": resolved,
                },
                indent=2,
            )
        )
        return 0
    cases = input_fingerprints(root, cases, research=args.pipeline == "research")
    # Fingerprint actual CLI versions and launcher content; do not probe during dry-run.
    tools = {}
    for name in ("repro_binary", "research_binary"):
        if name not in resolved.get("codeql", {}):
            continue
        binary = (root / resolved["codeql"][name]).resolve()
        if binary.is_file():
            version = subprocess.run(
                [str(binary), "version", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            tools[name] = {
                "launcher_hash": sha256_file(binary),
                "version": version.stdout.strip(),
                "exit_code": version.returncode,
            }
    resolved["tool_fingerprints"] = tools
    code_hash = implementation_hash(root)
    if args.pipeline == "research":
        request = {
            "root": str(root),
            "config": resolved,
            "cases": cases,
            "run_id": args.run_id,
            "mode": args.mode,
            "resume": args.resume,
            "implementation_hash": code_hash,
        }
        # No inherited oracle/CVE env values or .env; no LLM needed in graph-only.
        env = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TZ"}}
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
        result = subprocess.run(
            [sys.executable, "-m", "maxvera.research_worker"],
            cwd=root,
            input=json.dumps(request),
            text=True,
            env=env,
        )
        return result.returncode
    from maxvera.reproduction import finalize
    from maxvera.reproduction import stages as reproduction_stages

    run = Orchestrator(
        root,
        "reproduction",
        args.run_id,
        resolved,
        cases,
        reproduction_stages(),
        mode=args.mode,
        resume=args.resume,
        implementation_hash=code_hash,
        finalizer=finalize,
    )
    state = run.execute()
    print(json.dumps({"run_id": args.run_id, "status": state, "run_dir": str(run.path)}))
    return 0 if state == "COMPLETED" else 1


def parser():
    p = argparse.ArgumentParser(prog="maxvera")
    p.add_argument("--root", type=Path, default=Path.cwd())
    commands = p.add_subparsers(dest="command", required=True)
    d = commands.add_parser("doctor")
    d.add_argument("--config", type=Path, default=Path("configs/runtime.yaml"))
    dataset = commands.add_parser("dataset")
    sub = dataset.add_subparsers(dest="dataset_command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--sources", action="store_true")
    pipe = commands.add_parser("pipeline")
    pipe.add_argument("pipeline", choices=["reproduce", "research"])
    pipe.add_argument("--config", type=Path, required=True)
    pipe.add_argument("--run-id", required=True, type=safe_id)
    pipe.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    pipe.add_argument("--limit", type=int)
    pipe.add_argument("--variant")
    pipe.add_argument("--resume", action="store_true")
    execution = pipe.add_mutually_exclusive_group()
    execution.add_argument("--dry-run", action="store_true")
    execution.add_argument(
        "--execute", action="store_true", help="explicitly enable actual execution"
    )
    status = commands.add_parser("status")
    status.add_argument("--run-id", required=True)
    ev = commands.add_parser("evaluate")
    ev.add_argument("--run-id", required=True)
    ev.add_argument("--protocol", choices=["iris_paper", "zero_hint"], required=True)
    ev.add_argument("--labels", type=Path)
    ev.add_argument("--truth", type=Path)
    compare = commands.add_parser("compare")
    compare.add_argument("--runs", required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--paired-llm", action="store_true")
    legacy = commands.add_parser("legacy-index")
    legacy.add_argument("paths", nargs="+", type=Path)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    root = args.root.resolve()
    if hasattr(args, "config") and not args.config.is_absolute():
        args.config = root / args.config
    try:
        if args.command == "doctor":
            return doctor(root, args.config)
        if args.command == "dataset":
            from maxvera.dataset import prepare

            print(json.dumps(prepare(root, args.config, sources=args.sources), indent=2))
            return 0
        if args.command == "pipeline":
            return pipeline(root, args)
        if args.command == "status":
            from src.reproduction.common import read_jsonl

            path = locate(root, args.run_id)
            print(
                json.dumps(
                    {
                        "run_id": args.run_id,
                        "status": (path / "STATUS").read_text().strip(),
                        "cases": read_jsonl(path / "cases.jsonl"),
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "evaluate":
            from maxvera.evaluation import evaluate

            path = locate(root, args.run_id)
            config = yaml.safe_load((path / "config.resolved.yaml").read_text())
            ds = config["dataset"]
            prefix = "D_extended" if "extended" in ds.get("config", "") else "D_repro_v1"
            labels = args.labels or root / ds.get(
                "labels", f"data/processed/evaluator_only/{prefix}_labels.csv"
            )
            truth = args.truth or root / ds.get(
                "fix_locations", f"data/processed/evaluator_only/{prefix}_fix_locations.jsonl"
            )
            print(evaluate(root, path, args.protocol, labels=labels, truth=truth))
            return 0
        if args.command == "compare":
            from maxvera.evaluation import compare

            dirs = []
            for run_id in args.runs.split(","):
                path = locate(root, run_id)
                protocol = (
                    "iris_paper"
                    if json.loads((path / "manifest.json").read_text())["pipeline"]
                    == "reproduction"
                    else "zero_hint"
                )
                dirs.append(root / "results/evaluations" / run_id / protocol)
            print(compare(dirs, root / args.output, paired_llm=args.paired_llm))
            return 0
        if args.command == "legacy-index":
            from maxvera.legacy import index_exports

            print(json.dumps(index_exports(args.paths), indent=2))
            return 0
    except (ValueError, RuntimeError, OSError, KeyError) as e:
        from maxvera.contracts import redact

        print(json.dumps({"error": redact(str(e))}), file=sys.stderr)
        return 2
    return 2
