#!/usr/bin/env python3
"""Materialize one fetched checkout into an opaque sanitized runtime directory."""

from __future__ import annotations

import argparse

from _bootstrap import add_source_tree

add_source_tree()

from openiris.data import materialize_runtime_repository, read_runtime_manifest  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument(
        "--skip-revision-check",
        action="store_true",
        help="Allow a non-Git source tree (unsafe for paper runs)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    instances = {
        instance.instance_id: instance for instance in read_runtime_manifest(args.runtime_manifest)
    }
    try:
        instance = instances[args.instance_id]
    except KeyError as exc:
        raise SystemExit(f"Unknown runtime instance ID: {args.instance_id}") from exc
    destination = materialize_runtime_repository(
        instance,
        args.source_repository,
        args.runtime_root,
        verify_revision=not args.skip_revision_check,
    )
    print(f"Materialized runtime repository: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
