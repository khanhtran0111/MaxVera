"""Offline Phase 6 hybrid-rerank budget ceiling."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

import yaml

from src.reproduction.common import read_csv


def estimate(
    repo_root: Path,
    *,
    input_price_per_million: float | None,
    output_price_per_million: float | None,
) -> dict[str, object]:
    config = yaml.safe_load(
        (repo_root / "configs/experiments/phase6_hypotheses.yaml").read_text(encoding="utf-8")
    )
    projects = len(read_csv(repo_root / config["dataset"]["development_split"]))
    llm = config["llm"]
    model = yaml.safe_load((repo_root / llm["model_config"]).read_text(encoding="utf-8"))
    configured_prices = model["provider_pricing_usd_per_million_tokens"]
    overridden = input_price_per_million is not None
    if input_price_per_million is None:
        input_price_per_million = float(configured_prices["input"])
    if output_price_per_million is None:
        output_price_per_million = float(configured_prices["output"])
    input_tokens = projects * int(llm["max_total_input_tokens_per_project"])
    output_tokens = projects * int(llm["max_output_tokens_per_call"])
    cost = (
        input_tokens * input_price_per_million + output_tokens * output_price_per_million
    ) / 1_000_000
    return {
        "schema_version": 1,
        "network_called": False,
        "generator": "hybrid",
        "model": llm["model_id"],
        "provider_route": llm["provider_route"],
        "development_projects": projects,
        "maximum_successful_calls": projects * int(llm["max_calls_per_project"]),
        "input_token_ceiling": input_tokens,
        "billed_output_token_ceiling": output_tokens,
        "cost_ceiling_usd": round(cost, 8),
        "reasoning_accounting": "reasoning is included in billed completion tokens",
        "price_source": "cli_override" if overridden else "configured_snapshot",
        "configured_price_snapshot": {
            "date": model["provider_metadata_snapshot_date"],
            "input_usd_per_million": configured_prices["input"],
            "output_usd_per_million": configured_prices["output"],
        },
        "prices_usd_per_million": {
            "input": input_price_per_million,
            "output": output_price_per_million,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--input-price-per-million", type=float)
    parser.add_argument("--output-price-per-million", type=float)
    args = parser.parse_args(argv)
    if (args.input_price_per_million is None) != (args.output_price_per_million is None):
        parser.error("provide both input and output prices, or neither")
    result = estimate(
        args.repo_root.resolve(),
        input_price_per_million=args.input_price_per_million,
        output_price_per_million=args.output_price_per_million,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
