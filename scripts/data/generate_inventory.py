#!/usr/bin/env python3
"""Generate deterministic Phase 0 dataset inventory and leakage-audit reports."""

from __future__ import annotations

import argparse

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data import (  # noqa: E402
    generate_inventory_reports,
    load_cwe_bench,
    read_snapshot_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--track", required=True, choices=("legacy", "v2"))
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--runtime-manifest")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    snapshot = read_snapshot_manifest(args.dataset_manifest)
    if snapshot.get("track") != args.track:
        raise SystemExit("Dataset manifest track does not match --track")
    bundle = load_cwe_bench(args.dataset_root, args.track)
    paths = generate_inventory_reports(
        bundle,
        snapshot,
        args.output_directory,
        runtime_manifest=args.runtime_manifest,
    )
    print(f"Generated {len(paths)} inventory reports in {args.output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
