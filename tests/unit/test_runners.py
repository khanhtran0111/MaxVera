from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from openiris.codeql import CodeQLRunner
from openiris.experiments import BaselineRecord, BaselineStatus
from openiris.experiments.baseline import count_sarif_paths
from openiris.experiments.subprocess import ProcessExecutor, ProcessResult, ProcessStatus


def test_process_executor_retains_stdout_stderr_and_argv(tmp_path: Path) -> None:
    result = ProcessExecutor().run(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ],
        artifact_dir=tmp_path / "command",
        timeout_seconds=5,
    )

    assert result.status is ProcessStatus.COMPLETE
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == "out"
    assert Path(result.stderr_path).read_text(encoding="utf-8").strip() == "err"
    command = json.loads(Path(result.record_path).read_text(encoding="utf-8"))
    assert command["argv"] == list(result.argv)
    assert command["timeout_seconds"] == 5


def test_process_executor_retains_partial_output_on_timeout(tmp_path: Path) -> None:
    result = ProcessExecutor().run(
        [
            sys.executable,
            "-c",
            "import time; print('before timeout', flush=True); time.sleep(5)",
        ],
        artifact_dir=tmp_path / "timeout",
        timeout_seconds=0.1,
    )

    assert result.status is ProcessStatus.TIMEOUT
    assert "before timeout" in Path(result.stdout_path).read_text(encoding="utf-8")
    assert Path(result.stderr_path).is_file()


def test_process_executor_rejects_shell_string_and_overwrite(tmp_path: Path) -> None:
    executor = ProcessExecutor()
    with pytest.raises(TypeError, match="sequence"):
        executor.run("echo unsafe", artifact_dir=tmp_path / "bad")  # type: ignore[arg-type]

    target = tmp_path / "once"
    executor.run([sys.executable, "-c", "pass"], artifact_dir=target)
    with pytest.raises(FileExistsError, match="overwrite"):
        executor.run([sys.executable, "-c", "pass"], artifact_dir=target)


def test_process_executor_normalizes_spawn_error(tmp_path: Path) -> None:
    result = ProcessExecutor().run(
        [str(tmp_path / "definitely-not-an-executable")],
        artifact_dir=tmp_path / "spawn",
    )
    assert result.status is ProcessStatus.SPAWN_ERROR
    assert result.exit_code is None
    assert "FileNotFoundError" in (result.error or "")
    assert Path(result.stdout_path).is_file()
    assert Path(result.stderr_path).is_file()


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(self, argv: list[str], **kwargs: Any) -> ProcessResult:
        self.calls.append((tuple(argv), kwargs))
        artifact_dir = Path(kwargs["artifact_dir"])
        return ProcessResult(
            status=ProcessStatus.COMPLETE,
            argv=tuple(argv),
            cwd=str(kwargs["cwd"]),
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_seconds=1.0,
            exit_code=0,
            timeout_seconds=kwargs.get("timeout_seconds"),
            stdout_path=str(artifact_dir / "stdout.log"),
            stderr_path=str(artifact_dir / "stderr.log"),
            record_path=str(artifact_dir / "command.json"),
        )


def test_codeql_generic_commands_are_argument_lists(tmp_path: Path) -> None:
    source = tmp_path / "source"
    database = tmp_path / "database"
    source.mkdir()
    recorder = RecordingExecutor()
    runner = CodeQLRunner("pinned-codeql", executor=recorder)  # type: ignore[arg-type]

    runner.create_database(
        source_root=source,
        database=database,
        build_command="mvn -DskipTests package",
        artifact_dir=tmp_path / "create-command",
    )
    create_argv = recorder.calls[-1][0]
    assert create_argv[:3] == ("pinned-codeql", "database", "create")
    assert "--language=java" in create_argv
    assert "--command=mvn -DskipTests package" in create_argv

    database.mkdir()
    runner.analyze_database(
        database=database,
        queries=["suite-a.qls", "suite-b.ql"],
        sarif_output=tmp_path / "result.sarif",
        artifact_dir=tmp_path / "analyze-command",
        threads=2,
        ram_mb=4096,
    )
    analyze_argv = recorder.calls[-1][0]
    assert analyze_argv[:3] == ("pinned-codeql", "database", "analyze")
    assert "suite-a.qls" in analyze_argv
    assert "--format=sarifv2.1.0" in analyze_argv
    assert "--threads=2" in analyze_argv


def test_sarif_path_counter_and_baseline_schema(tmp_path: Path) -> None:
    fixture = tmp_path / "tiny.sarif"
    fixture.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {"ruleId": "a", "codeFlows": [{}, {}]},
                            {"ruleId": "b"},
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert count_sarif_paths(fixture) == 3
    record = BaselineRecord(
        run_id="r1",
        baseline="codeql",
        track="legacy",
        project="owner__repo_CVE-2020-1_v1",
        cve="CVE-2020-1",
        cwe="CWE-022",
        query="cwe-022wCodeQL",
        status=BaselineStatus.COMPLETE,
        number_of_paths=3,
        vulnerability_detected=True,
        runtime_seconds=1.0,
    )
    schema = json.loads(
        (Path.cwd() / "schemas" / "baseline_record.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(record.to_dict())
