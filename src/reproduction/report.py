"""Create Phase 4 paper-reference tables and variance reports from project outputs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from src.reproduction.common import write_checksums
from src.reproduction.runner import BASELINE_ROOTS

PAPER_REFERENCE = {
    "B1": {
        "label": "IRIS public CodeQL.csv (121 artifact rows)",
        "detected_projects": 27,
        "macro_fdr_successes": 0.9003,
        "macro_f1_successes": 0.076,
    },
    "B2": {
        "label": "IRIS paper reference (32B model, 120 projects)",
        "detected_projects": 47,
        "macro_fdr_successes": 0.9238,
        "macro_f1_successes": 0.097,
    },
}


def _load(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected JSON object: {path}")
    return loaded


def create_report(root: Path, run_id: str) -> Path:
    rows: list[dict[str, Any]] = []
    for baseline_id, reference in PAPER_REFERENCE.items():
        rows.append(
            {
                "run_id": "paper_reference",
                "baseline_id": baseline_id,
                "scope": "published_reference",
                **reference,
                "projects": 121 if baseline_id == "B1" else 120,
                "analysis_successes": "N/A",
                "paper_comparable": "reference_only",
            }
        )
    for baseline_id, directory in BASELINE_ROOTS.items():
        run_root = root / "results/reproduction" / directory / run_id
        if not run_root.is_dir():
            continue
        manifest = _load(run_root / "manifest.json")
        for scope, filename in (
            ("dataset_canonical", "metrics_dataset_canonical.json"),
            ("artifact_compatible", "metrics_artifact_compatible.json"),
        ):
            path = run_root / filename
            if not path.is_file():
                continue
            metrics = _load(path)
            rows.append(
                {
                    "run_id": run_id,
                    "baseline_id": baseline_id,
                    "scope": scope,
                    "label": manifest["claim"],
                    "projects": metrics["projects"],
                    "analysis_successes": metrics["analysis_successes"],
                    "detected_projects": metrics["detected_projects"],
                    "macro_fdr_successes": metrics["macro_fdr_successes"],
                    "macro_f1_successes": metrics["macro_f1_successes"],
                    "paper_comparable": False,
                }
            )
        variance = (
            "# Reproduction variance\n\n"
            f"Run: `{run_id}`; baseline: `{baseline_id}`; mode: `{manifest['mode']}`.\n\n"
            "- Effective analyzer: CodeQL 2.26.2 with the 104 Phase 2 databases; "
            "the older patched IRIS CLI is incompatible with these databases.\n"
            "- The IRIS condition is **IRIS pipeline reproduction with GPT-OSS 20B "
            "via OpenRouter**, "
            "not an exact or numerical reproduction of the paper.\n"
            "- OpenRouter model `openai/gpt-oss-20b` replaces the paper's 32B model; "
            "the provider route is pinned and model fallback is disabled.\n"
            "- Effective generation limit is 2,048 tokens, matching the paper text; "
            "reasoning tokens count against this completion budget.\n"
            "- README context is read from the pinned local project checkout; runtime network "
            "fetching is disabled.\n"
            "- Canonical metrics contain 120 project rows. Artifact-compatible metrics add "
            "CVE-2021-21345 under CWE-094 to reproduce the public CSV's 121st row when run.\n"
            "- Phase 2 failures remain explicit misses/statuses; they are never silently skipped.\n"
            "- Independent ground-truth matching prefers method ranges, falls back to class "
            "ranges when method lines are blank, and uses file-level matching only when both "
            "method and class ranges are unavailable. The aggregate metrics record the count "
            "at each granularity.\n"
        )
        (run_root / "reproduction_variance.md").write_text(variance, encoding="utf-8")
        write_checksums(run_root)

    table = root / "results/paper/table_reproduction.csv"
    table.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "run_id",
        "baseline_id",
        "scope",
        "label",
        "projects",
        "analysis_successes",
        "detected_projects",
        "macro_fdr_successes",
        "macro_f1_successes",
        "paper_comparable",
    ]
    with table.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return table


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(create_report(args.repo_root.resolve(), args.run_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
