#!/usr/bin/env python3
"""Create physically separated runtime and evaluator-only dataset views."""

from __future__ import annotations

import argparse

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data import (  # noqa: E402
    load_cwe_bench,
    materialize_dataset_views,
    read_snapshot_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--track", required=True, choices=("legacy", "v2"))
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--ground-truth-root", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    snapshot = read_snapshot_manifest(args.dataset_manifest)
    if snapshot.get("track") != args.track:
        raise SystemExit("Dataset manifest track does not match --track")
    bundle = load_cwe_bench(args.dataset_root, args.track)
    paths = materialize_dataset_views(
        bundle,
        str(snapshot["snapshot_id"]),
        args.runtime_root,
        args.ground_truth_root,
    )
    print(f"Runtime manifest: {paths.runtime_manifest}")
    print(f"Evaluator-only ground truth: {paths.ground_truth}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
