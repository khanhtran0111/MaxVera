from __future__ import annotations

import argparse
import json
from pathlib import Path

from openiris.baselines.reference import import_reference_csv
from openiris.utils.io import write_json

IRIS_PAPER_COMMIT = "7aa94755d43898a623307935e853b954afc79a5d"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iris-root", type=Path, default=Path("data/external/iris_v1"))
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results/phases/phase_00/baselines/published_reference"),
    )
    args = parser.parse_args()

    tables = {
        "codeql": "CodeQL.csv",
        "iris_gpt4": "IRIS+GPT-4.csv",
        "iris_qwen_32b": "IRIS+Qwen2.5-32B.csv",
    }
    summaries = []
    for name, filename in tables.items():
        output = args.output_root / f"{name}.jsonl"
        summaries.append(
            import_reference_csv(
                args.iris_root / "results" / filename,
                output,
                source_name=name,
                source_commit=IRIS_PAPER_COMMIT,
            )
        )
    summary = {"schema_version": 1, "references": summaries}
    write_json(args.output_root / "manifest.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
