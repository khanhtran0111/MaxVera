"""Dependency-free calibration models and selective-risk metrics."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

EPSILON = 1e-6


def clip_probability(value: float) -> float:
    return min(1.0 - EPSILON, max(EPSILON, value))


def sigmoid(value: float) -> float:
    if value >= 0.0:
        inverse = math.exp(-value)
        return 1.0 / (1.0 + inverse)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def _constant_model(labels: Sequence[int], feature_names: Sequence[str]) -> dict[str, Any]:
    probability = (sum(labels) + 1.0) / (len(labels) + 2.0)
    return {
        "kind": "constant",
        "feature_names": list(feature_names),
        "probability": probability,
    }


def fit_logistic(
    rows: Sequence[Mapping[str, float]],
    labels: Sequence[int],
    feature_names: Sequence[str],
    *,
    l2: float,
    iterations: int,
    learning_rate: float,
) -> dict[str, Any]:
    """Fit a deterministic L2 logistic model with full-batch gradient descent."""
    if len(rows) != len(labels) or not rows:
        raise ValueError("logistic training requires aligned non-empty rows and labels")
    if len(set(labels)) < 2:
        return _constant_model(labels, feature_names)
    weights = [0.0] * (len(feature_names) + 1)
    count = float(len(rows))
    for iteration in range(iterations):
        gradients = [0.0] * len(weights)
        for row, label in zip(rows, labels, strict=True):
            values = [1.0, *(float(row[name]) for name in feature_names)]
            error = sigmoid(
                sum(
                    weight * value
                    for weight, value in zip(weights, values, strict=True)
                )
            ) - label
            for index, value in enumerate(values):
                gradients[index] += error * value
        step = learning_rate / math.sqrt(1.0 + iteration / 100.0)
        weights[0] -= step * gradients[0] / count
        for index in range(1, len(weights)):
            regularized = gradients[index] / count + l2 * weights[index]
            weights[index] -= step * regularized
    return {
        "kind": "logistic",
        "feature_names": list(feature_names),
        "intercept": weights[0],
        "weights": weights[1:],
        "l2": l2,
        "iterations": iterations,
        "learning_rate": learning_rate,
    }


def fit_isotonic(scores: Sequence[float], labels: Sequence[int]) -> dict[str, Any]:
    """Fit increasing isotonic regression with the pair-adjacent violators algorithm."""
    if len(scores) != len(labels) or not scores:
        raise ValueError("isotonic training requires aligned non-empty scores and labels")
    ordered = sorted(zip(scores, labels, strict=True), key=lambda item: item[0])
    grouped: list[dict[str, float]] = []
    for score, label in ordered:
        if grouped and score == grouped[-1]["maximum"]:
            block = grouped[-1]
            block["total"] += label
            block["weight"] += 1.0
            block["value"] = block["total"] / block["weight"]
        else:
            grouped.append(
                {
                    "minimum": score,
                    "maximum": score,
                    "total": float(label),
                    "weight": 1.0,
                    "value": float(label),
                }
            )
        while len(grouped) >= 2 and grouped[-2]["value"] > grouped[-1]["value"]:
            right = grouped.pop()
            left = grouped.pop()
            total = left["total"] + right["total"]
            weight = left["weight"] + right["weight"]
            grouped.append(
                {
                    "minimum": left["minimum"],
                    "maximum": right["maximum"],
                    "total": total,
                    "weight": weight,
                    "value": total / weight,
                }
            )
    return {
        "kind": "isotonic",
        "feature_names": ["raw_score"],
        "blocks": [
            {
                "minimum": block["minimum"],
                "maximum": block["maximum"],
                "probability": clip_probability(block["value"]),
                "weight": int(block["weight"]),
            }
            for block in grouped
        ],
    }


def predict(model: Mapping[str, Any], features: Mapping[str, float]) -> float:
    kind = str(model["kind"])
    if kind == "constant":
        return clip_probability(float(model["probability"]))
    if kind == "logistic":
        names = [str(name) for name in model["feature_names"]]
        weights = [float(weight) for weight in model["weights"]]
        value = float(model["intercept"]) + sum(
            weight * float(features[name]) for name, weight in zip(names, weights, strict=True)
        )
        return clip_probability(sigmoid(value))
    if kind == "isotonic":
        score = float(features["raw_score"])
        blocks = list(model["blocks"])
        for block in blocks:
            if score <= float(block["maximum"]):
                return clip_probability(float(block["probability"]))
        return clip_probability(float(blocks[-1]["probability"]))
    raise ValueError(f"unknown calibration model kind: {kind}")


def fit_candidate(
    name: str,
    rows: Sequence[Mapping[str, float]],
    labels: Sequence[int],
    feature_names: Sequence[str],
    optimization: Mapping[str, Any],
) -> dict[str, Any]:
    if name == "platt":
        return fit_logistic(
            rows,
            labels,
            ["raw_score"],
            l2=float(optimization["l2"]),
            iterations=int(optimization["iterations"]),
            learning_rate=float(optimization["learning_rate"]),
        )
    if name == "isotonic":
        return fit_isotonic([float(row["raw_score"]) for row in rows], labels)
    if name == "logistic":
        return fit_logistic(
            rows,
            labels,
            feature_names,
            l2=float(optimization["l2"]),
            iterations=int(optimization["iterations"]),
            learning_rate=float(optimization["learning_rate"]),
        )
    raise ValueError(f"unknown calibration candidate: {name}")


def grouped_oof_predictions(
    name: str,
    rows: Sequence[Mapping[str, float]],
    labels: Sequence[int],
    groups: Sequence[str],
    feature_names: Sequence[str],
    optimization: Mapping[str, Any],
) -> list[float]:
    if not (len(rows) == len(labels) == len(groups)) or not rows:
        raise ValueError("OOF inputs must be aligned and non-empty")
    unique_groups = sorted(set(groups))
    if len(unique_groups) < 2:
        raise ValueError("grouped OOF calibration requires at least two groups")
    predictions = [0.0] * len(rows)
    for held_out in unique_groups:
        train = [index for index, group in enumerate(groups) if group != held_out]
        test = [index for index, group in enumerate(groups) if group == held_out]
        model = fit_candidate(
            name,
            [rows[index] for index in train],
            [labels[index] for index in train],
            feature_names,
            optimization,
        )
        for index in test:
            predictions[index] = predict(model, rows[index])
    return predictions


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    total = sum(
        (probability - label) ** 2
        for probability, label in zip(probabilities, labels, strict=True)
    )
    return total / len(labels)


def ece_equal_width(
    probabilities: Sequence[float], labels: Sequence[int], bins: int
) -> float:
    total = len(labels)
    error = 0.0
    for bin_index in range(bins):
        lower = bin_index / bins
        upper = (bin_index + 1) / bins
        indexes = [
            index
            for index, probability in enumerate(probabilities)
            if lower <= probability < upper or (bin_index == bins - 1 and probability == 1.0)
        ]
        if not indexes:
            continue
        confidence = sum(probabilities[index] for index in indexes) / len(indexes)
        accuracy = sum(labels[index] for index in indexes) / len(indexes)
        error += len(indexes) / total * abs(confidence - accuracy)
    return error


def ece_equal_mass(
    probabilities: Sequence[float], labels: Sequence[int], bins: int
) -> float:
    ordered = sorted(range(len(labels)), key=lambda index: (probabilities[index], index))
    error = 0.0
    for bin_index in range(bins):
        start = bin_index * len(ordered) // bins
        end = (bin_index + 1) * len(ordered) // bins
        indexes = ordered[start:end]
        if not indexes:
            continue
        confidence = sum(probabilities[index] for index in indexes) / len(indexes)
        accuracy = sum(labels[index] for index in indexes) / len(indexes)
        error += len(indexes) / len(labels) * abs(confidence - accuracy)
    return error


def risk_coverage_curve(
    probabilities: Sequence[float], labels: Sequence[int]
) -> list[dict[str, float | int]]:
    ordered = sorted(
        range(len(labels)), key=lambda index: (-probabilities[index], index)
    )
    errors = 0
    curve: list[dict[str, float | int]] = []
    for rank, index in enumerate(ordered, start=1):
        errors += 1 - labels[index]
        curve.append(
            {
                "rank": rank,
                "coverage": rank / len(labels),
                "risk": errors / rank,
                "threshold": probabilities[index],
            }
        )
    return curve


def calibration_metrics(
    probabilities: Sequence[float], labels: Sequence[int], bins: int
) -> dict[str, float]:
    curve = risk_coverage_curve(probabilities, labels)
    return {
        "brier": brier_score(probabilities, labels),
        "ece_equal_width": ece_equal_width(probabilities, labels, bins),
        "ece_equal_mass": ece_equal_mass(probabilities, labels, bins),
        "aurc": sum(float(point["risk"]) for point in curve) / len(curve),
    }


def select_thresholds(
    probabilities: Sequence[float],
    labels: Sequence[int],
    *,
    target_accept_precision: float,
    target_verify_recall: float,
    max_abstain_risk: float,
    minimum_accept_count: int,
) -> dict[str, float]:
    unique = sorted(set(probabilities), reverse=True)
    accept = 1.0
    for threshold in unique:
        selected = [index for index, value in enumerate(probabilities) if value >= threshold]
        precision = sum(labels[index] for index in selected) / len(selected)
        if len(selected) >= minimum_accept_count and precision >= target_accept_precision:
            accept = threshold
    positives = sum(labels)
    verify = accept
    if positives:
        for threshold in unique:
            recalled = sum(
                labels[index]
                for index, value in enumerate(probabilities)
                if value >= threshold
            )
            if recalled / positives >= target_verify_recall:
                verify = min(accept, threshold)
                break
    abstain = 0.0
    for threshold in sorted(set(probabilities)):
        selected = [index for index, value in enumerate(probabilities) if value <= threshold]
        risk = sum(labels[index] for index in selected) / len(selected)
        if threshold < verify and risk <= max_abstain_risk:
            abstain = threshold
    return {
        "tau_accept": accept,
        "tau_verify": verify,
        "tau_abstain": min(abstain, verify),
    }


def route(probability: float, thresholds: Mapping[str, float]) -> str:
    if probability >= float(thresholds["tau_accept"]):
        return "ACCEPT"
    if probability >= float(thresholds["tau_verify"]):
        return "VERIFY"
    return "ABSTAIN"
