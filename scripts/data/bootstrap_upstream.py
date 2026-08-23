#!/usr/bin/env python3
"""Fetch and verify every immutable Phase 0 upstream Git checkout."""

from __future__ import annotations

import argparse
from pathlib import Path

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data.upstream import (  # noqa: E402
    UpstreamBootstrapError,
    bootstrap_phase0_upstreams,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument(
        "--legacy-config",
        type=Path,
        default=Path("configs/datasets/legacy_paper.yaml"),
    )
    parser.add_argument(
        "--v2-config",
        type=Path,
        default=Path("configs/datasets/v2_snapshot.yaml"),
    )
    parser.add_argument(
        "--toolchain-config",
        type=Path,
        default=Path("configs/toolchain/phase0.yaml"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        results = bootstrap_phase0_upstreams(
            args.workspace,
            legacy_config=args.legacy_config,
            v2_config=args.v2_config,
            toolchain_config=args.toolchain_config,
        )
    except UpstreamBootstrapError as exc:
        raise SystemExit(str(exc)) from exc
    for result in results:
        print(f"{result.disposition.value} {result.name}: {result.commit} -> {result.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
