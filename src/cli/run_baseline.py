"""Guarded placeholder for baseline phases that are not implemented yet."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("baseline_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    with args.config.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict) or config.get("baseline_id") != args.baseline_id:
        parser.error("baseline ID does not match config")
    status = config.get("status", "unknown")
    print(
        f"{args.baseline_id} is intentionally disabled ({status}). "
        "Phase 0-1 define protocol and infrastructure only; no result was created."
    )
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
