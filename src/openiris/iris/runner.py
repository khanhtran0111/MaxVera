"""Thin orchestration of the pinned upstream IRIS implementation."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from openiris.experiments.baseline import BaselineRecord, BaselineStatus, baseline_status
from openiris.experiments.subprocess import ProcessExecutor

_IRIS_QUERY = re.compile(r"^cwe-(?P<cwe>\d{3})wLLM$")
_CVE = re.compile(r"(?:^|_)(CVE-\d{4}-\d+)(?:_|$)", re.IGNORECASE)
_OWNED_OPTIONS = {"--query", "--llm", "--run-id", "--seed"}


def _selected_timeout(default: float | None, override: float | None) -> float | None:
    return default if override is None else override


def _iris_metrics(document: Any) -> tuple[int | None, bool | None]:
    if not isinstance(document, dict):
        return None, None
    for section_name in ("posthoc_filter_result", "vanilla_result"):
        section = document.get(section_name)
        if isinstance(section, dict) and isinstance(section.get("num_paths"), int):
            recall_method = section.get("recall_method")
            return int(section["num_paths"]), (
                recall_method if isinstance(recall_method, bool) else None
            )
    if isinstance(document.get("num_paths"), int):
        recall_method = document.get("recall_method")
        return int(document["num_paths"]), (
            recall_method if isinstance(recall_method, bool) else None
        )
    return None, None


class IrisRunner:
    """Call ``src/neusym_vul.py``; do not reimplement IRIS stages locally."""

    def __init__(
        self,
        iris_root: str | Path,
        *,
        python_executable: str | os.PathLike[str] = sys.executable,
        timeout_seconds: float | None = None,
        executor: ProcessExecutor | None = None,
    ) -> None:
        self.iris_root = Path(iris_root).resolve()
        self.python_executable = os.fspath(python_executable)
        self.timeout_seconds = timeout_seconds
        self.executor = executor or ProcessExecutor(timeout_seconds)

    def run(
        self,
        *,
        run_id: str,
        project: str,
        query: str,
        model: str,
        seed: int,
        artifact_dir: str | Path,
        track: str = "legacy",
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
        extra_args: Sequence[str] = (),
    ) -> BaselineRecord:
        match = _IRIS_QUERY.fullmatch(query)
        if match is None:
            raise ValueError("IRIS query must look like cwe-022wLLM")
        if not run_id or any(character in run_id for character in "/\\"):
            raise ValueError("upstream run_id must be a non-empty path-safe value")
        if not model.strip():
            raise ValueError("IRIS model name cannot be empty")
        if isinstance(extra_args, (str, bytes)):
            raise TypeError("extra_args must be an argument sequence")
        if any(argument in _OWNED_OPTIONS for argument in extra_args):
            raise ValueError("extra_args cannot override query/model/run-id/seed")

        script = self.iris_root / "src" / "neusym_vul.py"
        if not script.is_file():
            raise FileNotFoundError(script)
        upstream_output = self.iris_root / "output" / project / run_id
        if upstream_output.exists():
            raise FileExistsError(
                f"refusing to reuse or overwrite upstream IRIS output: {upstream_output}"
            )

        argv = [
            self.python_executable,
            str(script),
            project,
            "--query",
            query,
            "--llm",
            model,
            "--run-id",
            run_id,
            "--seed",
            str(seed),
            *extra_args,
        ]
        command_artifacts = Path(artifact_dir).resolve()
        process = self.executor.run(
            argv,
            artifact_dir=artifact_dir,
            cwd=self.iris_root,
            env=env,
            timeout_seconds=_selected_timeout(self.timeout_seconds, timeout_seconds),
        )

        retained_output = command_artifacts / "upstream_output"
        status = baseline_status(process)
        error = process.error
        if upstream_output.exists():
            try:
                shutil.copytree(upstream_output, retained_output, symlinks=True)
            except OSError as exc:
                if status is BaselineStatus.COMPLETE:
                    status = BaselineStatus.FAILED
                error = f"could not retain upstream output: {exc}"

        final_json = retained_output / f"{query}-final" / "results.json"
        query_sarif = retained_output / query / "results.sarif"
        filtered_sarif = retained_output / f"{query}-posthoc-filter" / "results.sarif"
        artifacts = [path for path in (final_json, query_sarif, filtered_sarif) if path.is_file()]
        paths: int | None = None
        detected: bool | None = None
        if status is BaselineStatus.COMPLETE:
            if final_json.is_file():
                try:
                    with final_json.open("r", encoding="utf-8") as handle:
                        paths, detected = _iris_metrics(json.load(handle))
                    if paths is None:
                        status = BaselineStatus.FAILED
                        error = "IRIS results.json has no recognized num_paths field"
                    elif detected is None:
                        status = BaselineStatus.FAILED
                        error = "IRIS results.json has no boolean recall_method field"
                except (OSError, ValueError) as exc:
                    status = BaselineStatus.FAILED
                    error = f"invalid IRIS results.json: {exc}"
            else:
                status = BaselineStatus.FAILED
                error = "upstream process exited successfully without producing final results.json"

        cve_match = _CVE.search(project)
        return BaselineRecord(
            run_id=run_id,
            baseline="iris",
            track=track,
            project=project,
            cve=cve_match.group(1).upper() if cve_match else None,
            cwe=f"CWE-{match.group('cwe')}",
            query=query,
            status=status,
            number_of_paths=paths,
            vulnerability_detected=detected,
            runtime_seconds=process.duration_seconds,
            exit_code=process.exit_code,
            command_record=process.record_path,
            output_artifacts=tuple(str(path) for path in artifacts),
            error=error,
            metadata={
                "model": model,
                "seed": seed,
                "orchestrator": "iris_v1_upstream",
                "upstream_output": str(upstream_output),
                "detection_metric": "recall_method",
            },
        )
