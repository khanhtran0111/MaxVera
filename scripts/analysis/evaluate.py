#!/usr/bin/env python3
"""Evaluate a CodeQL SARIF file with CWE-Bench-Java fix locations."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

# Keep the source-tree entrypoint usable before the package is installed.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from openiris.evaluation.evaluator import SarifEvaluator  # noqa: E402
from openiris.evaluation.ground_truth import GroundTruthError  # noqa: E402
from openiris.evaluation.locations import LocationMapError  # noqa: E402
from openiris.utils.io import write_json  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate SARIF code flows using the file/method overlap semantics "
            "of the IRIS v1 EvaluationPipeline."
        )
    )
    parser.add_argument("--sarif", type=Path, required=True, help="CodeQL path-query SARIF")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        required=True,
        help="CWE-Bench-Java fix_info.csv or a project-specific subset",
    )
    parser.add_argument(
        "--class-locations",
        type=Path,
        required=True,
        help="CSV from the IRIS fetch_class_locs query",
    )
    parser.add_argument(
        "--method-locations",
        "--function-locations",
        dest="method_locations",
        type=Path,
        required=True,
        help="CSV from the IRIS fetch_func_locs query",
    )
    parser.add_argument(
        "--project-slug",
        help="Select one project_slug (or legacy db_name) from ground truth",
    )
    parser.add_argument("--cve-id", help="Optionally select one CVE from ground truth")
    parser.add_argument(
        "--repository-root",
        type=Path,
        help="Relativize absolute Windows/POSIX SARIF URIs against this source root",
    )
    parser.add_argument("--output", type=Path, help="Write metrics JSON to this path")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact rather than indented JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        evaluator = SarifEvaluator.from_files(
            args.ground_truth,
            args.class_locations,
            args.method_locations,
            repository_root=args.repository_root,
            project_slug=args.project_slug,
            cve_id=args.cve_id,
        )
        metrics = evaluator.evaluate_path(args.sarif).to_dict()
    except (OSError, ValueError, GroundTruthError, LocationMapError) as error:
        parser.error(str(error))

    if args.output is not None:
        write_json(args.output, metrics)

    indent = None if args.compact else 2
    print(json.dumps(metrics, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
