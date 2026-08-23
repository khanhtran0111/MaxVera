from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parents[1] / "fixtures" / "evaluation"
PROJECT_ROOT = Path(__file__).parents[2]


def test_evaluate_cli_writes_reference_metrics(tmp_path: Path) -> None:
    output = tmp_path / "metrics.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "analysis" / "evaluate.py"),
            "--sarif",
            str(FIXTURES / "iris_v1_paths.sarif.json"),
            "--ground-truth",
            str(FIXTURES / "fix_info.csv"),
            "--class-locations",
            str(FIXTURES / "class_locations.csv"),
            "--function-locations",
            str(FIXTURES / "function_locations.csv"),
            "--project-slug",
            "fixture_project",
            "--repository-root",
            r"C:\workspace\repo",
            "--output",
            str(output),
            "--compact",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    stdout_metrics = json.loads(completed.stdout)
    file_metrics = json.loads(output.read_text(encoding="utf-8"))
    assert stdout_metrics == file_metrics
    assert file_metrics["num_paths"] == 4
    assert file_metrics["num_tp_paths_method"] == 2
