#!/usr/bin/env python3
"""Run the pinned Phase 0 CodeQL smoke inside the reproducible Docker image."""

from __future__ import annotations

import argparse
from pathlib import Path

from openiris.codeql.docker_smoke import run_from_config
from openiris.config import load_yaml
from openiris.experiments import RunStatus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument(
        "--results-root", type=Path, default=Path("results/phases/phase_00/baselines")
    )
    parser.add_argument("--runtime-root", type=Path, default=Path("data/runtime_views"))
    parser.add_argument("--gradle-cache", type=Path, default=Path("artifacts/caches/gradle"))
    parser.add_argument("--image", default="maxvera-phase0:codeql")
    parser.add_argument("--docker", default="docker", dest="docker_executable")
    parser.add_argument(
        "--reuse-database",
        type=Path,
        help="Copy a completed CodeQL database containing db-java/ into the immutable run",
    )
    args = parser.parse_args()
    run_path = run_from_config(
        args.config,
        run_id=args.run_id,
        runs_root=args.runs_root,
        results_root=args.results_root,
        runtime_root=args.runtime_root,
        gradle_cache=args.gradle_cache,
        image=args.image,
        docker_executable=args.docker_executable,
        reuse_database=args.reuse_database,
    )
    manifest = load_yaml(run_path / "manifest.yaml")
    print(f"Run: {run_path}")
    print(f"Database: {run_path / 'workspace' / 'database'}")
    return 0 if manifest["status"] == RunStatus.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
