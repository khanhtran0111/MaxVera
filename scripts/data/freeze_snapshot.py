#!/usr/bin/env python3
"""Freeze CWE-Bench-Java metadata and all source files into a hashed YAML manifest."""

from __future__ import annotations

import argparse

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data import freeze_snapshot, load_cwe_bench  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--track", required=True, choices=("legacy", "v2"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--snapshot-id")
    parser.add_argument("--source-url")
    parser.add_argument("--git-commit")
    parser.add_argument(
        "--downloaded-at",
        help="Acquisition timestamp (ISO 8601); omitted values stay null for determinism",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bundle = load_cwe_bench(args.dataset_root, args.track)
    manifest = freeze_snapshot(
        bundle,
        args.output,
        snapshot_id=args.snapshot_id,
        source_url=args.source_url,
        git_commit=args.git_commit,
        downloaded_at=args.downloaded_at,
    )
    print(
        f"Frozen {manifest['num_instances']} instances as {manifest['snapshot_id']} "
        f"({manifest['sha256_manifest']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
