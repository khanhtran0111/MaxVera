#!/usr/bin/env python3
"""Create a deterministic repository-holdout split from a sanitized runtime manifest."""

from __future__ import annotations

import argparse

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data import (  # noqa: E402
    create_repository_split_from_manifest,
    read_snapshot_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--split-id")
    parser.add_argument("--seed", default="0")
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--dev-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dataset = read_snapshot_manifest(args.dataset_manifest)
    split = create_repository_split_from_manifest(
        args.runtime_manifest,
        args.output,
        dataset_snapshot_id=str(dataset["snapshot_id"]),
        dataset_manifest_sha256=str(dataset["sha256_manifest"]),
        seed=args.seed,
        ratios={
            "train": args.train_ratio,
            "dev": args.dev_ratio,
            "test": args.test_ratio,
        },
        split_id=args.split_id,
    )
    print(
        f"Created {split['split_id']}: "
        + ", ".join(
            f"{name}={split['counts'][name]['instances']}" for name in ("train", "dev", "test")
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
