"""Paired repository-cluster bootstrap and exact paired detection statistics."""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered or not 0 <= probability <= 1:
        raise ValueError("percentile requires values and a probability in [0, 1]")
    offset = (len(ordered) - 1) * probability
    lower = math.floor(offset)
    upper = math.ceil(offset)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (offset - lower)


def holm(p_values: Sequence[float]) -> list[float]:
    if any(not 0 <= value <= 1 for value in p_values):
        raise ValueError("p-values must be in [0, 1]")
    result = [0.0] * len(p_values)
    previous = 0.0
    for rank, index in enumerate(sorted(range(len(p_values)), key=lambda i: p_values[i])):
        previous = max(previous, min(1.0, p_values[index] * (len(p_values) - rank)))
        result[index] = previous
    return result


def mcnemar(left: Sequence[bool], right: Sequence[bool]) -> dict[str, Any]:
    if len(left) != len(right) or not left:
        raise ValueError("McNemar requires nonempty aligned outcomes")
    wins = sum(a and not b for a, b in zip(left, right, strict=True))
    losses = sum(b and not a for a, b in zip(left, right, strict=True))
    discordant = wins + losses
    # Exact binomial two-sided test; no asymptotic approximation on small samples.
    p = min(
        1.0, 2 * sum(math.comb(discordant, i) for i in range(min(wins, losses) + 1)) / 2**discordant
    )
    return {
        "left_only": wins,
        "right_only": losses,
        "discordant": discordant,
        "p_value": p,
        "test": "exact_mcnemar_project_outcomes",
    }


def paired_bootstrap(
    left: Mapping[str, Mapping[str, Any]],
    right: Mapping[str, Mapping[str, Any]],
    repository_groups: Mapping[str, str],
    *,
    samples: int = 10000,
    seed: int = 1234,
    successful_only: bool = False,
) -> dict[str, Any]:
    if set(left) != set(right) or not left or samples < 1:
        raise ValueError("paired bootstrap requires exact, nonempty project coverage")
    selected = sorted(left)
    if set(selected) - set(repository_groups):
        raise ValueError("missing repository groups")
    if successful_only:
        selected = [p for p in selected if left[p]["status"] == right[p]["status"] == "SUCCESS"]
    if not selected:
        return {"status": "NO_COMMON_SUCCESSFUL_PROJECTS", "projects": 0}
    groups: dict[str, list[str]] = defaultdict(list)
    for project in selected:
        groups[repository_groups[project]].append(project)

    def detected(row: Mapping[str, Any]) -> bool:
        return row["status"] == "SUCCESS" and bool(row["detected"])

    totals = [
        (
            sum(float(detected(left[p])) - float(detected(right[p])) for p in ids),
            len(ids),
        )
        for _, ids in sorted(groups.items())
    ]
    random_source = random.Random(seed)
    draws = []
    for _ in range(samples):
        chosen = [totals[random_source.randrange(len(totals))] for _ in totals]
        draws.append(sum(total for total, _ in chosen) / sum(size for _, size in chosen))
    effect = sum(total for total, _ in totals) / len(selected)
    return {
        "status": "SUCCESS",
        "metric": "project_recall_left_minus_right",
        "projects": len(selected),
        "repository_groups": len(groups),
        "samples": samples,
        "seed": seed,
        "effect_size": effect,
        "confidence_level": 0.95,
        "ci_lower": percentile(draws, 0.025),
        "ci_upper": percentile(draws, 0.975),
        "bootstrap_unit": "repository_project",
        "sensitivity": "common_analysis_successes" if successful_only else "failures_as_miss",
        "paired_detection": mcnemar(
            [detected(left[p]) for p in selected],
            [detected(right[p]) for p in selected],
        ),
        "mcnemar_independence_limit": "multiple rows in one repository may be dependent",
    }
