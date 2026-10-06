"""Development-only stage entry points; analyzer and evaluator run separately."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from src.pipeline_v2.graphs import phase7, phase9
from src.pipeline_v2.runtime import configuration, development_ids, phase6
from src.pipeline_v2.specifications import phase10


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "stage",
        choices=["prepare", "phase6", "phase7", "phase9", "phase10", "phase11", "phase12", "auto"],
    )
    parser.add_argument("--config", default="configs/experiments/pipeline_v2_execution.yaml")
    parser.add_argument("--mode", choices=["pilot", "full"], default="pilot")
    parser.add_argument("--project-id")
    parser.add_argument("--run-id")
    parser.add_argument("--phase6-run")
    parser.add_argument("--phase7-run")
    parser.add_argument("--phase9-run")
    parser.add_argument("--phase10-run")
    parser.add_argument("--phase11-run")
    parser.add_argument("--inherit-run")
    parser.add_argument("--baseline", choices=["B6", "B7", "B8", "B9"], default="B9")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--confirm-api-spend", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    config_path = (root / args.config).resolve()
    config = configuration(root, config_path)
    if args.stage == "prepare":
        from src.pipeline_v2.recovery import prepare_databases

        if os.environ.get("MAXVERA_DATA_ROLE") == "evaluator":
            parser.error("database recovery must run in analyzer role")
        print(prepare_databases(root, config, config_path, resume=args.resume), flush=True)
        return
    if args.stage == "auto":
        from src.pipeline_v2.orchestrator import automate

        automate(root, config_path, resume=args.resume, confirm_api_spend=args.confirm_api_spend)
        return
    if args.mode == "full" and args.project_id:
        parser.error("full must select the entire development split")
    if args.mode == "pilot" and not args.project_id:
        parser.error("pilot requires an opaque development --project-id")
    selected = development_ids(root, project_id=args.project_id)
    if not args.run_id:
        parser.error("--run-id is required")
    evaluator = args.stage in {"phase11", "phase12"}
    if (os.environ.get("MAXVERA_DATA_ROLE") == "evaluator") != evaluator:
        parser.error(
            "stage process role must be analyzer for Phase 6-10, evaluator for Phase 11-12"
        )
    common = {"resume": args.resume, "full": args.mode == "full"}

    def required(name: str) -> str:
        value = getattr(args, name)
        if not value:
            parser.error("--" + name.replace("_", "-") + " is required")
        return str(value)

    if args.stage == "phase6":
        output = phase6(root, config, config_path, selected, args.run_id, **common)
    elif args.stage == "phase7":
        output = phase7(root, config_path, selected, args.run_id, required("phase6_run"), **common)
    elif args.stage == "phase9":
        output = phase9(
            root,
            config,
            config_path,
            selected,
            args.run_id,
            required("phase6_run"),
            required("phase7_run"),
            **common,
        )
    elif args.stage == "phase10":
        from src.pipeline_v2.specifications import RetryableSynthesisError

        try:
            output = phase10(
                root,
                config,
                config_path,
                selected,
                args.run_id,
                required("phase6_run"),
                required("phase9_run"),
                args.baseline,
                dry_run=args.dry_run,
                confirm_api_spend=args.confirm_api_spend,
                inherit_relative=args.inherit_run,
                **common,
            )
        except RetryableSynthesisError as error:
            print(f"Retryable API failure: {error}", flush=True)
            raise SystemExit(75) from error
    elif args.stage == "phase11":
        from src.pipeline_v2.verification import phase11

        output = phase11(
            root, config, config_path, selected, args.run_id, required("phase10_run"), **common
        )
    else:
        from src.pipeline_v2.calibration import phase12

        output = phase12(
            root,
            config,
            config_path,
            selected,
            args.run_id,
            required("phase6_run"),
            required("phase10_run"),
            required("phase11_run"),
            **common,
        )
    print(output.relative_to(root), flush=True)


if __name__ == "__main__":
    main()
