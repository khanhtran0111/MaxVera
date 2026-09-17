"""Offline Phase 10 API-budget estimator; it never contacts OpenRouter."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from src.common.envfile import effective_env
from src.reproduction.common import read_jsonl


def estimate(repo_root: Path, *, baselines: int = 4) -> dict[str, Any]:
    experiment = yaml.safe_load(
        (repo_root / "configs/experiments/phase10_retrieval_specification.yaml").read_text(
            encoding="utf-8"
        )
    )
    model = yaml.safe_load(
        (repo_root / "configs/models/gpt_oss_20b_openrouter.yaml").read_text(encoding="utf-8")
    )
    phase9_root = repo_root / experiment["development_dependency"]["phase9"]["run_root"]
    statuses = read_jsonl(phase9_root / "project_status.jsonl")
    successful_projects = sum(row.get("status") == "SUCCESS" for row in statuses)
    hypotheses_per_project = int(experiment["retrieval"]["hypothesis_limit_per_project"])
    budget = experiment["budget"]["budget_matched"]
    nominal_calls = successful_projects * hypotheses_per_project * baselines
    selected_projects = len(statuses)
    maximum_calls = selected_projects * int(budget["max_calls_per_project"]) * baselines
    nominal_input = nominal_calls * int(budget["max_context_tokens_per_call"])
    nominal_output = nominal_calls * int(budget["max_output_tokens_per_call"])
    maximum_input = (
        selected_projects * int(budget["max_total_input_tokens_per_project"]) * baselines
    )
    maximum_output = maximum_calls * int(budget["max_output_tokens_per_call"])
    prices = model["provider_pricing_usd_per_million_tokens"]
    machine = effective_env(repo_root / ".env")

    def cost(input_tokens: int, output_tokens: int) -> float:
        return round(
            input_tokens / 1_000_000 * float(prices["input"])
            + output_tokens / 1_000_000 * float(prices["output"]),
            6,
        )

    return {
        "schema_version": 1,
        "phase": 10,
        "network_called": False,
        "baselines": [f"B{index}" for index in range(6, 6 + baselines)],
        "selected_projects": selected_projects,
        "phase9_successful_projects": successful_projects,
        "hypotheses_per_successful_project": hypotheses_per_project,
        "provider_route": experiment["llm"]["provider_route"],
        "environment_provider_route": machine.get(
            "MAXVERA_OPENROUTER_PROVIDER", "UNCONFIGURED"
        ),
        "nominal_assumption": "one successful synthesis call per hypothesis and baseline",
        "nominal_calls": nominal_calls,
        "nominal_input_token_ceiling": nominal_input,
        "nominal_billed_output_token_ceiling": nominal_output,
        "nominal_cost_ceiling_usd": cost(nominal_input, nominal_output),
        "protocol_hard_ceiling_calls": maximum_calls,
        "protocol_hard_ceiling_input_tokens": maximum_input,
        "protocol_hard_ceiling_billed_output_tokens": maximum_output,
        "protocol_hard_cost_ceiling_usd": cost(maximum_input, maximum_output),
        "price_snapshot_date": model["provider_metadata_snapshot_date"],
        "reasoning_accounting": (
            "reasoning tokens share the billed completion ceiling and are not added twice"
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--baselines", type=int, choices=(1, 2, 3, 4), default=4)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            estimate(args.repo_root.resolve(), baselines=args.baselines),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
