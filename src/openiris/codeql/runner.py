"""Thin wrappers around the pinned CodeQL CLI and IRIS v1 baseline."""

from __future__ import annotations

import os
import re
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from openiris.experiments.baseline import (
    BaselineRecord,
    BaselineStatus,
    baseline_status,
    count_sarif_paths,
)
from openiris.experiments.subprocess import ProcessExecutor, ProcessResult

_CODEQL_QUERY = re.compile(r"^cwe-(?P<cwe>\d{3})wCodeQL$")
_CVE = re.compile(r"(?:^|_)(CVE-\d{4}-\d+)(?:_|$)", re.IGNORECASE)


def _selected_timeout(default: float | None, override: float | None) -> float | None:
    return default if override is None else override


class CodeQLRunner:
    """Build and run CodeQL commands without hiding upstream behavior."""

    def __init__(
        self,
        executable: str | os.PathLike[str] = "codeql",
        *,
        timeout_seconds: float | None = None,
        executor: ProcessExecutor | None = None,
    ) -> None:
        self.executable = os.fspath(executable)
        self.timeout_seconds = timeout_seconds
        self.executor = executor or ProcessExecutor(timeout_seconds)

    def create_database(
        self,
        *,
        source_root: str | Path,
        database: str | Path,
        artifact_dir: str | Path,
        language: str = "java",
        build_command: str | None = None,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProcessResult:
        """Run ``codeql database create`` for a fresh database directory."""

        source = Path(source_root).resolve()
        if not source.is_dir():
            raise NotADirectoryError(source)
        target = Path(database).resolve()
        if target.exists():
            raise FileExistsError(f"refusing to replace CodeQL database: {target}")
        if not language.strip():
            raise ValueError("CodeQL language cannot be empty")

        argv = [
            self.executable,
            "database",
            "create",
            str(target),
            f"--language={language}",
            f"--source-root={source}",
        ]
        if build_command is not None:
            if not build_command.strip():
                raise ValueError("build_command cannot be blank")
            argv.append(f"--command={build_command}")
        return self.executor.run(
            argv,
            artifact_dir=artifact_dir,
            cwd=cwd or source,
            env=env,
            timeout_seconds=_selected_timeout(self.timeout_seconds, timeout_seconds),
        )

    def analyze_database(
        self,
        *,
        database: str | Path,
        queries: str | Path | Sequence[str | Path],
        sarif_output: str | Path,
        artifact_dir: str | Path,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
        threads: int | None = None,
        ram_mb: int | None = None,
        rerun: bool = False,
    ) -> ProcessResult:
        """Run ``codeql database analyze`` and retain SARIF plus process logs."""

        database_path = Path(database).resolve()
        if not database_path.is_dir():
            raise NotADirectoryError(database_path)
        if isinstance(queries, (str, os.PathLike)):
            query_args = [os.fspath(queries)]
        else:
            query_args = [os.fspath(query) for query in queries]
        if not query_args:
            raise ValueError("at least one CodeQL query or query suite is required")
        output = Path(sarif_output).resolve()
        if output.exists():
            raise FileExistsError(f"refusing to replace SARIF output: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        if threads is not None and threads <= 0:
            raise ValueError("threads must be greater than zero")
        if ram_mb is not None and ram_mb <= 0:
            raise ValueError("ram_mb must be greater than zero")

        argv = [self.executable, "database", "analyze"]
        if rerun:
            argv.append("--rerun")
        argv.extend(
            [
                str(database_path),
                *query_args,
                "--format=sarifv2.1.0",
                f"--output={output}",
            ]
        )
        if threads is not None:
            argv.append(f"--threads={threads}")
        if ram_mb is not None:
            argv.append(f"--ram={ram_mb}")
        return self.executor.run(
            argv,
            artifact_dir=artifact_dir,
            cwd=cwd or database_path.parent,
            env=env,
            timeout_seconds=_selected_timeout(self.timeout_seconds, timeout_seconds),
        )

    def run_pinned_iris_baseline(
        self,
        *,
        run_id: str,
        project: str,
        query: str,
        iris_root: str | Path,
        artifact_dir: str | Path,
        track: str = "legacy",
        python_executable: str | os.PathLike[str] = sys.executable,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> BaselineRecord:
        """Invoke IRIS v1's unmodified built-in CodeQL baseline entrypoint.

        This adapter intentionally calls ``src/codeql_vul.py`` rather than
        copying its evaluation or query logic into MaxVera.
        """

        match = _CODEQL_QUERY.fullmatch(query)
        if match is None:
            raise ValueError("IRIS v1 CodeQL query must look like cwe-022wCodeQL")
        root = Path(iris_root).resolve()
        script = root / "src" / "codeql_vul.py"
        if not script.is_file():
            raise FileNotFoundError(script)
        result_json = root / "output" / project / "common" / query / "results.json"
        result_sarif = root / "output" / project / "common" / query / "results.sarif"
        if result_json.exists() or result_sarif.exists():
            raise FileExistsError(
                "upstream CodeQL output already exists; use a clean pinned checkout "
                "to avoid silently reusing an earlier result"
            )

        command_artifacts = Path(artifact_dir).resolve()
        process = self.executor.run(
            [os.fspath(python_executable), str(script), project, "--query", query],
            artifact_dir=artifact_dir,
            cwd=root,
            env=env,
            timeout_seconds=_selected_timeout(self.timeout_seconds, timeout_seconds),
        )
        status = baseline_status(process)
        paths: int | None = None
        error = process.error
        snapshot = command_artifacts / "upstream_output"
        upstream_query_output = result_sarif.parent
        if upstream_query_output.exists():
            try:
                shutil.copytree(upstream_query_output, snapshot, symlinks=True)
            except OSError as exc:
                if status is BaselineStatus.COMPLETE:
                    status = BaselineStatus.FAILED
                error = f"could not retain upstream output: {exc}"
        retained_sarif = snapshot / "results.sarif"
        retained_json = snapshot / "results.json"
        artifacts = [path for path in (retained_sarif, retained_json) if path.is_file()]
        if status is BaselineStatus.COMPLETE:
            if retained_sarif.is_file():
                try:
                    paths = count_sarif_paths(retained_sarif)
                except (OSError, ValueError) as exc:
                    status = BaselineStatus.FAILED
                    error = f"invalid SARIF output: {exc}"
            else:
                status = BaselineStatus.FAILED
                error = "upstream process exited successfully without producing results.sarif"

        cve_match = _CVE.search(project)
        return BaselineRecord(
            run_id=run_id,
            baseline="codeql",
            track=track,
            project=project,
            cve=cve_match.group(1).upper() if cve_match else None,
            cwe=f"CWE-{match.group('cwe')}",
            query=query,
            status=status,
            number_of_paths=paths,
            vulnerability_detected=paths > 0 if paths is not None else None,
            runtime_seconds=process.duration_seconds,
            exit_code=process.exit_code,
            command_record=process.record_path,
            output_artifacts=tuple(str(path) for path in artifacts),
            error=error,
            metadata={
                "orchestrator": "iris_v1_builtin_codeql",
                "upstream_output": str(upstream_query_output),
            },
        )
