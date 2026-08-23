from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from openiris.codeql.docker_smoke import DockerCodeQLSmokeRunner
from openiris.experiments import ProcessResult, ProcessStatus, RunRegistry

FIXTURES = Path(__file__).parents[1] / "fixtures" / "evaluation"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class DockerRecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    @staticmethod
    def _workspace(argv: tuple[str, ...]) -> Path:
        for index, argument in enumerate(argv):
            if argument == "--mount":
                value = argv[index + 1]
                if value.endswith("target=/workspace"):
                    source = value.split("source=", 1)[1].split(",target=", 1)[0]
                    return Path(source)
        raise AssertionError("workspace mount is missing")

    def run(self, argv: list[str], **kwargs: Any) -> ProcessResult:
        normalized = tuple(argv)
        self.calls.append((normalized, kwargs))
        artifact_dir = Path(kwargs["artifact_dir"])
        stage = artifact_dir.name
        workspace = self._workspace(normalized)
        output = workspace / "output"
        if stage == "database_create":
            (workspace / "database" / "db-java").mkdir(parents=True)
        elif stage == "builtin_sarif":
            shutil.copyfile(FIXTURES / "iris_v1_paths.sarif.json", output / "results.sarif")
        elif stage == "builtin_csv":
            (output / "results.csv").write_text("name\nfixture\n", encoding="utf-8")
        elif stage == "fetch_class_locations":
            (output / "fetch_class_locs.bqrs").write_bytes(b"fixture")
        elif stage == "decode_class_locations":
            shutil.copyfile(FIXTURES / "class_locations.csv", output / "fetch_class_locs.csv")
        elif stage == "fetch_func_locations":
            (output / "fetch_func_locs.bqrs").write_bytes(b"fixture")
        elif stage == "decode_func_locations":
            shutil.copyfile(FIXTURES / "function_locations.csv", output / "fetch_func_locs.csv")
        artifact_dir.joinpath("stdout.log").write_text("", encoding="utf-8")
        artifact_dir.joinpath("stderr.log").write_text("", encoding="utf-8")
        record = artifact_dir / "command.json"
        record.write_text(json.dumps({"argv": argv}), encoding="utf-8")
        return ProcessResult(
            status=ProcessStatus.COMPLETE,
            argv=normalized,
            cwd=str(kwargs["cwd"]),
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_seconds=1.0,
            exit_code=0,
            timeout_seconds=kwargs.get("timeout_seconds"),
            stdout_path=str(artifact_dir / "stdout.log"),
            stderr_path=str(artifact_dir / "stderr.log"),
            record_path=str(record),
        )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    instance_id = f"oi_{'a' * 32}"
    repository = tmp_path / "runtime" / "snapshot" / instance_id / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "Example.java").write_text("class Example {}\n", encoding="utf-8")
    iris = tmp_path / "iris"
    queries = iris / "src" / "queries"
    queries.mkdir(parents=True)
    (queries / "fetch_class_locs.ql").write_text("import java\n", encoding="utf-8")
    (queries / "fetch_func_locs.ql").write_text("import java\n", encoding="utf-8")
    return repository, iris, tmp_path / "gradle-cache"


def test_docker_smoke_uses_opaque_copy_and_shell_free_host_argv(tmp_path: Path) -> None:
    repository, iris, cache = _inputs(tmp_path)
    recorder = DockerRecordingExecutor()
    registry = RunRegistry(tmp_path / "runs", workspace=tmp_path)
    run = registry.create_run("docker_smoke", {"fixture": True})
    runner = DockerCodeQLSmokeRunner(executor=recorder)  # type: ignore[arg-type]

    outcome = runner.run(
        run=run,
        runtime_repository=repository,
        instance_id=f"oi_{'a' * 32}",
        snapshot_id="snapshot",
        project_slug="fixture_project",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        track="legacy",
        iris_root=iris,
        ground_truth_csv=FIXTURES / "fix_info.csv",
        gradle_cache=cache,
        build_helper=PROJECT_ROOT / "scripts" / "baselines" / "codeql_gradle_build.sh",
    )

    assert outcome.database == run.path / "workspace" / "database"
    assert (run.path / "workspace" / "source" / "src" / "Example.java").is_file()
    assert outcome.record.query == "cwe-022wCodeQL"
    assert outcome.record.number_of_paths == 4
    assert outcome.record.vulnerability_detected is True
    assert len(recorder.calls) == 7
    for argv, _ in recorder.calls:
        assert argv[:2] == ("docker", "run")
        assert "maxvera-phase0:codeql" in argv
        assert any("target=/opt/iris,readonly" in argument for argument in argv)
    create_argv = recorder.calls[0][0]
    assert "--command=bash /opt/maxvera/codeql_gradle_build.sh" in create_argv
    assert (
        "/opt/codeql/qlpacks/codeql/java-queries/0.8.3/Security/CWE/CWE-022/"
        in (recorder.calls[1][0])
    )
    location_argv = recorder.calls[3][0]
    assert "bash" in location_argv
    assert "-lc" in location_argv
    assert any("myqueries/maxvera_phase0" in argument for argument in location_argv)
    assert "fetch_class_locs.ql" in location_argv


def test_reuse_database_is_hashed_copied_and_skips_create(tmp_path: Path) -> None:
    repository, iris, cache = _inputs(tmp_path)
    reusable = tmp_path / "reusable-db"
    (reusable / "db-java").mkdir(parents=True)
    (reusable / "db-java" / "codeql-database.yml").write_text("fixture\n", encoding="utf-8")
    recorder = DockerRecordingExecutor()
    run = RunRegistry(tmp_path / "runs", workspace=tmp_path).create_run(
        "reuse_smoke", {"fixture": True}
    )

    outcome = DockerCodeQLSmokeRunner(executor=recorder).run(  # type: ignore[arg-type]
        run=run,
        runtime_repository=repository,
        instance_id=f"oi_{'a' * 32}",
        snapshot_id="snapshot",
        project_slug="fixture_project",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        track="legacy",
        iris_root=iris,
        ground_truth_csv=FIXTURES / "fix_info.csv",
        gradle_cache=cache,
        build_helper=PROJECT_ROOT / "scripts" / "baselines" / "codeql_gradle_build.sh",
        reuse_database=reusable,
    )

    provenance = outcome.record.metadata["database_provenance"]
    assert provenance["mode"] == "reused_copy"
    assert len(provenance["source_sha256"]) == 64
    assert provenance["source_file_count"] == 1
    assert (outcome.database / "db-java" / "codeql-database.yml").is_file()
    assert len(recorder.calls) == 6
    assert all(call[1]["artifact_dir"].name != "database_create" for call in recorder.calls)


def test_gradle_helper_is_strict_and_crlf_safe() -> None:
    helper = (PROJECT_ROOT / "scripts" / "baselines" / "codeql_gradle_build.sh").read_text(
        encoding="utf-8"
    )

    assert "set -euo pipefail" in helper
    assert "tr -d '\\r'" in helper
    assert "clean classes" in helper
