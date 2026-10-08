"""Validate a baseline config and dispatch implemented experiment runners."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from src.baselines.runner import main as phase5_main
from src.reproduction.runner import main as reproduction_main
from src.specification.runner import main as phase10_main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("baseline_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = list(args.baseline_args)
    if forwarded[:1] == ["--"]:
        forwarded = forwarded[1:]
    if "--pipeline-v2" in forwarded:
        if args.baseline_id != "B9":
            parser.error("--pipeline-v2 end-to-end entrypoint requires B9")
        from src.pipeline_v2.b9 import main as b9_main

        forwarded.remove("--pipeline-v2")
        return b9_main(forwarded)
    with args.config.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict) or config.get("baseline_id") != args.baseline_id:
        parser.error("baseline ID does not match config")
    if args.baseline_id in {"B0", "B1", "B2"}:
        forwarded = list(args.baseline_args)
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return reproduction_main(["--baseline-id", args.baseline_id, *forwarded])
    if args.baseline_id in {"B3", "B4", "B5"}:
        forwarded = list(args.baseline_args)
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return phase5_main(
            [
                "--baseline-id",
                args.baseline_id,
                "--config",
                str(args.config),
                *forwarded,
            ]
        )
    if args.baseline_id in {"B6", "B7", "B8", "B9"}:
        forwarded = list(args.baseline_args)
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return phase10_main(
            [
                "--baseline-id",
                args.baseline_id,
                "--config",
                str(args.config),
                *forwarded,
            ]
        )
    status = config.get("status", "unknown")
    blockers = config.get("blocked_by", [])
    blocker_text = f"; dependencies: {', '.join(map(str, blockers))}" if blockers else ""
    print(
        f"{args.baseline_id} is intentionally disabled ({status}). "
        f"Its implementation phase has not passed{blocker_text}. No result was created."
    )
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
