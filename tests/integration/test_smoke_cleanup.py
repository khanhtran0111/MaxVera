from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "scripts/tools/run_smoke_suite.sh"
ASSERTION = REPO_ROOT / "scripts/tools/assert_no_smoke_artifacts.sh"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(RUNNER), *arguments],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_success_path_removes_every_smoke_artifact() -> None:
    process = _run("--run-id", "pytest_smoke_pass", "--test-mode")
    assert process.returncode == 0, process.stdout + process.stderr
    assertion = subprocess.run(
        ["bash", str(ASSERTION)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert assertion.returncode == 0, assertion.stdout + assertion.stderr


def test_injected_failure_still_removes_every_smoke_artifact() -> None:
    process = _run(
        "--run-id",
        "pytest_smoke_failure",
        "--test-mode",
        "--fail-after",
        "setup",
    )
    assert process.returncode == 97, process.stdout + process.stderr
    for relative in (
        "results/smoke/pytest_smoke_failure",
        "data/interim/smoke/pytest_smoke_failure",
        ".cache/experiments/smoke/pytest_smoke_failure",
        "logs/smoke/pytest_smoke_failure",
    ):
        assert not (REPO_ROOT / relative).exists()
