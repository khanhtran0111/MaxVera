"""Evaluator-only process using pinned upstream IRIS program-point matching verbatim."""

import json
import sys
from pathlib import Path


def main():
    request = json.load(sys.stdin)
    from maxvera.evaluator_identity import verified_upstream

    upstream = verified_upstream(Path(request["iris_root"]))
    if request.get("upstream_identity") and upstream != request["upstream_identity"]:
        raise ValueError("upstream evaluator identity changed before worker invocation")
    import pandas as pd

    for name in tuple(sys.modules):
        if name == "src" or name.startswith("src."):
            del sys.modules[name]
    sys.path.insert(0, request["iris_root"])
    from src.modules.evaluation_pipeline import EvaluationPipeline

    evaluator = EvaluationPipeline.__new__(EvaluationPipeline)
    evaluator.test_run = False
    evaluator.class_locs_path = request["classes"]
    evaluator.func_locs_path = request["methods"]
    evaluator.project_fixed_methods = pd.DataFrame(request["truth"])
    result = evaluator.evaluate_sarif_result(request["sarif"])
    print("MAXVERA_METRIC=" + json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
