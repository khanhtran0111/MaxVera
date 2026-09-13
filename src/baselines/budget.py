"""Offline Phase 5 API-budget estimator; it never contacts OpenRouter."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.reproduction.common import read_csv


def estimate(
    repo_root: Path,
    split: Path,
    *,
    input_price_per_million: float | None,
    output_price_per_million: float | None,
) -> dict[str, Any]:
    experiment_path = repo_root / "configs/experiments/phase5_baselines.yaml"
    experiment = yaml.safe_load(experiment_path.read_text(encoding="utf-8"))
    budget = experiment["budget"]["budget_matched"]
    model = yaml.safe_load(
        (repo_root / "configs/models/gpt_oss_20b_openrouter.yaml").read_text(encoding="utf-8")
    )
    projects = len(read_csv(split))
    llm_baselines = 2
    nominal_calls = projects * llm_baselines
    maximum_calls = nominal_calls * int(budget["max_calls_per_project"])
    nominal_input_tokens = nominal_calls * int(budget["max_context_tokens_per_call"])
    nominal_billed_output_tokens = nominal_calls * int(budget["max_output_tokens_per_call"])
    maximum_input_tokens = (
        projects * llm_baselines * int(budget["max_total_input_tokens_per_project"])
    )
    maximum_billed_output_tokens = maximum_calls * int(budget["max_output_tokens_per_call"])
    machine = effective_env(repo_root / ".env")
    configured_provider = str(experiment["llm"]["provider_route"])
    result: dict[str, Any] = {
        "schema_version": 1,
        "network_called": False,
        "provider_route": configured_provider,
        "environment_provider_route": machine.get(
            "MAXVERA_OPENROUTER_PROVIDER", "UNCONFIGURED"
        ),
        "projects": projects,
        "llm_baselines": ["B3", "B4"],
        "nominal_assumption": "one successful call per project and LLM baseline",
        "nominal_calls": nominal_calls,
        "nominal_input_tokens": nominal_input_tokens,
        "nominal_billed_output_token_ceiling": nominal_billed_output_tokens,
        "reasoning_accounting": (
            "reasoning_tokens are included in the billed completion-token ceiling; "
            "do not add them a second time"
        ),
        "protocol_hard_ceiling_calls": maximum_calls,
        "protocol_hard_ceiling_input_tokens": maximum_input_tokens,
        "protocol_hard_ceiling_billed_output_tokens": maximum_billed_output_tokens,
    }
    configured_prices = model["provider_pricing_usd_per_million_tokens"]
    result["configured_price_snapshot"] = {
        "date": model["provider_metadata_snapshot_date"],
        "input_usd_per_million": configured_prices["input"],
        "output_usd_per_million": configured_prices["output"],
    }
    prices_overridden = input_price_per_million is not None
    if input_price_per_million is None and output_price_per_million is None:
        input_price_per_million = float(configured_prices["input"])
        output_price_per_million = float(configured_prices["output"])
    if input_price_per_million is not None and output_price_per_million is not None:
        result["price_source"] = "cli_override" if prices_overridden else "configured_snapshot"
        result["effective_prices_usd_per_million"] = {
            "input": input_price_per_million,
            "output": output_price_per_million,
        }
        if prices_overridden:
            result["user_supplied_prices_usd_per_million"] = {
                "input": input_price_per_million,
                "output": output_price_per_million,
            }
        result["nominal_cost_ceiling_usd"] = round(
            nominal_input_tokens / 1_000_000 * input_price_per_million
            + nominal_billed_output_tokens / 1_000_000 * output_price_per_million,
            6,
        )
        result["protocol_hard_cost_ceiling_usd"] = round(
            maximum_input_tokens / 1_000_000 * input_price_per_million
            + maximum_billed_output_tokens / 1_000_000 * output_price_per_million,
            6,
        )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--split", type=Path, default=Path("data/processed/analysis_input/D_repro_v1_projects.csv")
    )
    parser.add_argument("--input-price-per-million", type=float)
    parser.add_argument("--output-price-per-million", type=float)
    args = parser.parse_args(argv)
    if (args.input_price_per_million is None) != (args.output_price_per_million is None):
        parser.error("provide both input and output prices, or neither")
    root = args.repo_root.resolve()
    split = args.split if args.split.is_absolute() else root / args.split
    print(
        json.dumps(
            estimate(
                root,
                split,
                input_price_per_million=args.input_price_per_million,
                output_price_per_million=args.output_price_per_million,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
