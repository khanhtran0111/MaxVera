"""Evaluation-only helpers for reproducing the IRIS benchmark protocol.

This package is the only application package allowed to load benchmark ground
truth.  Runtime analysis modules must not import it.
"""

from openiris.evaluation.evaluator import (
    EvaluationMetrics,
    EvaluationPipeline,
    SarifEvaluator,
    evaluate_sarif,
)
from openiris.evaluation.ground_truth import (
    FixedMethod,
    GroundTruth,
    load_ground_truth,
)
from openiris.evaluation.locations import DeclarationLocation, LocationIndex
from openiris.evaluation.paths import normalize_uri

__all__ = [
    "DeclarationLocation",
    "EvaluationMetrics",
    "EvaluationPipeline",
    "FixedMethod",
    "GroundTruth",
    "LocationIndex",
    "SarifEvaluator",
    "evaluate_sarif",
    "load_ground_truth",
    "normalize_uri",
]
