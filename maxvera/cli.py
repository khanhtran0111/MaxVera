"""Single public CLI for preparation, pipelines and isolated evaluation."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from maxvera.contracts import ORACLE_PATTERN, PipelineConfig, digest, require_keys, safe_id
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
    require_keys(
        result,
        {
            "name",
            "candidate_sources",
            "graph_enabled",
            "retrieval",
            "llm_enabled",
            "targeted_verification",
        },
        "research variant",
    )
    if ORACLE_PATTERN.search(json.dumps(result)) or "evaluator_only" in json.dumps(result):
        raise ValueError("protected oracle metadata in research variant")
    if any(
        type(result.get(key)) is not bool
        for key in ("graph_enabled", "llm_enabled", "targeted_verification")
    ):
        raise ValueError("research variant flags must be boolean")
    if name == "text_only":
        raise ValueError(
            "text_only NOT_IMPLEMENTED: text retrieval requires its own validated candidate pool"
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
    dry = args.dry_run or (config.runtime.dry_run_default and not args.execute)
    if args.pipeline == "research":
        resolved["selected_variant"] = _variant(root, config, args.variant)
        if (
            resolved["selected_variant"].get("llm_enabled")
            and args.mode == "smoke"
            and args.limit
            and args.limit > 2
        ):
            raise ValueError("LLM research smoke is limited to at most two cases")
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
    input_report = None
    if args.pipeline == "research":
        from maxvera.preflight import input_preflight

        input_report = input_preflight(root, cases)
        if getattr(args, "experiment_protocol", None):
            from maxvera.experiments import validate_experiment

            if args.mode != "full":
                raise ValueError("prospective experiment protocols require full mode")
            resolved["experiment_protocol"] = validate_experiment(
                root,
                config,
                resolved["selected_variant"],
                cases,
                run_id=args.run_id,
                protocol=args.experiment_protocol,
            )
        if (
            args.mode == "full"
            and not dry
            and resolved["selected_variant"].get("llm_enabled")
            and config.research.get("graph_signal_approved") is not True
            and "experiment_protocol" not in resolved
        ):
            raise ValueError(
                "full LLM research requires a reviewed frozen development signal or a "
                "prospectively registered exploratory experiment with development measurements"
            )
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
                    or resolved.get("selected_variant", {}).get("llm_enabled")
                    else 0,
                    "configured_cost_ceiling_usd": len(cases) * config.budgets.max_cost_usd_per_case
                    if args.pipeline == "reproduce"
                    or resolved.get("selected_variant", {}).get("llm_enabled")
                    else 0,
                    "config": resolved,
                    **({"input_preflight": input_report} if input_report is not None else {}),
                    "cost_control": "configured_stop_threshold_not_provider_prepaid_cap",
                },
                indent=2,
            )
        )
        return 0
    if input_report is not None and not input_report["ready"]:
        print(
            json.dumps(
                {"status": "INPUT_PREFLIGHT_FAILED", "input_preflight": input_report}, indent=2
            )
        )
        return 1
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
        if resolved["selected_variant"].get("llm_enabled"):
            from src.llm.providers.openrouter import OpenRouterSettings

            settings = OpenRouterSettings.load(root, Path(config.llm["model_config"]))
            if (
                settings.provider != config.llm["provider_route"]
                or settings.model != config.llm["model"]
            ):
                raise ValueError("research model/profile route mismatch")
            if settings.max_tokens != config.llm["max_output_tokens"]:
                raise ValueError("research model/profile output cap mismatch")
            private = dataclasses.asdict(settings)
            resolved["llm"]["runtime_parameters"] = {
                k: v for k, v in private.items() if k != "api_key"
            }
            if "experiment_protocol" in resolved and resolved["experiment_protocol"][
                "model_runtime_sha256"
            ] != digest(resolved["llm"]["runtime_parameters"]):
                raise ValueError("experiment model runtime changed after protocol validation")
            # Sent through stdin only, never config, environment, command line or artifacts.
            request["llm_settings"] = private
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
    prepare.add_argument("--view", help="prepare a new source view without rewriting the release")
    prepare.add_argument("--reuse-manifest", type=Path)
    prepare.add_argument("--fetch-timeout", type=int, default=600)
    prepare.add_argument("--offline", action="store_true")
    prepare.add_argument("--min-free-gib", type=float, default=20)
    prepare.add_argument(
        "--pipeline-config",
        type=Path,
        help="prepare only the selected cohort from this pipeline profile",
    )
    prepare.add_argument("--mode", choices=["smoke", "full"], default="full")
    prepare.add_argument("--limit", type=int)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--config", type=Path, required=True)
    preflight.add_argument("--mode", choices=["smoke", "full"], default="full")
    preflight.add_argument("--limit", type=int)
    preflight.add_argument("--variant")
    preflight.add_argument("--truth-alignment", type=Path)
    preflight.add_argument("--experiment-protocol", type=Path)
    preflight.add_argument("--run-id", type=safe_id)
    preflight.add_argument(
        "--require",
        choices=["all", "execution", "evaluation"],
        default="all",
        help="select the readiness gate used for the exit code; reports retain every gate",
    )
    experiment = commands.add_parser("experiment")
    experiment_sub = experiment.add_subparsers(dest="experiment_command", required=True)
    register = experiment_sub.add_parser("register")
    register.add_argument("--config", type=Path, required=True)
    register.add_argument("--variant", required=True)
    register.add_argument("--run-id", type=safe_id, required=True)
    register.add_argument("--output", type=Path, required=True)
    register.add_argument("--development-evaluations", nargs=2, type=Path, required=True)
    register.add_argument("--rationale", required=True)
    pipe = commands.add_parser("pipeline")
    pipe.add_argument("pipeline", choices=["reproduce", "research"])
    pipe.add_argument("--config", type=Path, required=True)
    pipe.add_argument("--run-id", required=True, type=safe_id)
    pipe.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    pipe.add_argument("--limit", type=int)
    pipe.add_argument("--variant")
    pipe.add_argument("--resume", action="store_true")
    pipe.add_argument("--experiment-protocol", type=Path)
    execution = pipe.add_mutually_exclusive_group()
    execution.add_argument("--dry-run", action="store_true")
    execution.add_argument(
        "--execute", action="store_true", help="explicitly enable actual execution"
    )
    status = commands.add_parser("status")
    status.add_argument("--run-id", required=True)
    ev = commands.add_parser("evaluate")
    ev.add_argument("--run-id", required=True)
    ev.add_argument(
        "--protocol",
        choices=["iris_paper", "legacy_artifact", "paper_formula_path", "zero_hint"],
        required=True,
    )
    ev.add_argument("--labels", type=Path)
    ev.add_argument("--truth", type=Path)
    ev.add_argument("--truth-alignment", type=Path)
    ev.add_argument("--missing-truth", choices=["error", "report"], default="error")
    compare = commands.add_parser("compare")
    comparison_inputs = compare.add_mutually_exclusive_group(required=True)
    comparison_inputs.add_argument("--runs")
    comparison_inputs.add_argument("--evaluations", nargs="+", type=Path)
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

            if args.view and not args.sources:
                raise ValueError("--view requires --sources")
            if not args.view and (
                args.reuse_manifest
                or args.offline
                or args.fetch_timeout != 600
                or args.min_free_gib != 20
            ):
                raise ValueError("versioned source options require --sources and --view")
            selected = None
            if args.pipeline_config:
                profile = PipelineConfig.load(root / args.pipeline_config)
                selected = [
                    c["case_id"]
                    for c in select_cases(
                        root,
                        profile.dataset,
                        args.mode,
                        args.limit,
                        oracle=profile.pipeline == "reproduce",
                    )
                ]
            elif args.limit is not None:
                raise ValueError("preparation --limit requires --pipeline-config")
            if args.view:
                from maxvera.preparation import prepare_sources

                report = prepare_sources(
                    root,
                    args.config,
                    view_name=args.view,
                    reuse_manifest=root / args.reuse_manifest if args.reuse_manifest else None,
                    selected_ids=selected,
                    timeout=args.fetch_timeout,
                    offline=args.offline,
                    min_free_gib=args.min_free_gib,
                )
                print(json.dumps(report, indent=2))
                return 0 if report["ready"] else 1
            report = prepare(root, args.config, sources=args.sources, selected_ids=selected)
            print(json.dumps(report, indent=2))
            return 0 if report.get("source_preparation", {}).get("ready", True) else 1
        if args.command == "preflight":
            from maxvera.preflight import readiness_preflight

            config = PipelineConfig.load(args.config)
            if config.pipeline != "research":
                raise ValueError("standalone input preflight currently supports research profiles")
            variant = _variant(root, config, args.variant)
            cases = select_cases(root, config.dataset, args.mode, args.limit)
            experiment = None
            if args.experiment_protocol:
                from maxvera.experiments import validate_experiment

                if args.mode != "full" or not args.run_id:
                    raise ValueError("experiment preflight requires full mode and --run-id")
                experiment = validate_experiment(
                    root,
                    config,
                    variant,
                    cases,
                    run_id=args.run_id,
                    protocol=args.experiment_protocol,
                )
            report = readiness_preflight(
                root,
                config,
                cases,
                variant,
                args.mode,
                truth_alignment=args.truth_alignment,
                experiment_protocol=experiment,
            )
            required = {
                "all": "ready",
                "execution": "execution_ready",
                "evaluation": "evaluation_ready",
            }
            report["required_gate"] = args.require
            print(json.dumps(report, indent=2))
            return 0 if report[required[args.require]] else 1
        if args.command == "experiment":
            from maxvera.experiments import register_experiment

            config = PipelineConfig.load(args.config)
            variant = _variant(root, config, args.variant)
            cases = select_cases(root, config.dataset, "full")
            output = register_experiment(
                root,
                config,
                variant,
                cases,
                run_id=args.run_id,
                output=args.output,
                development_evaluations=args.development_evaluations,
                rationale=args.rationale,
            )
            print(json.dumps({"protocol": str(output), "scientific_approved": False}, indent=2))
            return 0
        if args.command == "pipeline":
            return pipeline(root, args)
        if args.command == "status":
            from src.reproduction.common import read_jsonl

            path = locate(root, args.run_id)
            quality = {}
            if (path / "quality_report.json").is_file():
                report = json.loads((path / "quality_report.json").read_text())
                quality = {
                    "quality": {
                        key: report.get(key)
                        for key in (
                            "engineering_pass",
                            "blockers",
                            "verification_supported_fraction",
                            "full120_ready",
                        )
                    }
                }
            print(
                json.dumps(
                    {
                        "run_id": args.run_id,
                        "status": (path / "STATUS").read_text().strip(),
                        "cases": read_jsonl(path / "cases.jsonl"),
                        **quality,
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
            print(
                evaluate(
                    root,
                    path,
                    args.protocol,
                    labels=labels,
                    truth=truth,
                    missing_truth_policy=args.missing_truth,
                    truth_alignment=args.truth_alignment,
                )
            )
            return 0
        if args.command == "compare":
            from maxvera.evaluation import compare
            from maxvera.truth_alignment import EVALUATION_NAMESPACE

            dirs = [root / p for p in args.evaluations] if args.evaluations else []
            for run_id in args.runs.split(",") if args.runs else []:
                path = locate(root, run_id)
                protocol = (
                    "iris_paper"
                    if json.loads((path / "manifest.json").read_text())["pipeline"]
                    == "reproduction"
                    else EVALUATION_NAMESPACE
                )
                directory = root / "results/evaluations" / run_id / protocol
                if protocol == EVALUATION_NAMESPACE:
                    choices = sorted(directory.glob("*/evaluator_manifest.json"))
                    if len(choices) != 1:
                        raise ValueError(
                            f"run {run_id} has {len(choices)} aligned evaluations; "
                            "select exact output paths with compare --evaluations"
                        )
                    directory = choices[0].parent
                dirs.append(directory)
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
