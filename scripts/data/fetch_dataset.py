#!/usr/bin/env python3
"""Fetch a dataset at an explicit immutable commit (never at a floating ref)."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
_SOURCES = {
    "legacy": "https://github.com/iris-sast/cwe-bench-java.git",
    "v2": "https://github.com/iris-sast/iris.git",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--track", required=True, choices=sorted(_SOURCES))
    parser.add_argument("--commit", required=True, help="Full 40-character commit SHA")
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--source-url", help="Override the official Git URL")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not _COMMIT.fullmatch(args.commit):
        raise SystemExit("--commit must be a full 40-character hexadecimal SHA")
    destination = args.destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"Destination must not exist or must be empty: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_url = args.source_url or _SOURCES[args.track]
    subprocess.run(["git", "clone", "--no-checkout", source_url, str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "checkout", "--detach", args.commit], check=True)
    actual = subprocess.run(
        ["git", "-C", str(destination), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if actual.casefold() != args.commit.casefold():
        raise SystemExit(f"Checked out {actual}, expected {args.commit}")
    print(f"Fetched {args.track} dataset at {actual} into {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
