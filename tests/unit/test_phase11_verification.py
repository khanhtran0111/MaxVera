from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from src.common.provenance import sha256_file
from src.verification import runner as verification_runner
from src.verification.prepare_fixed import (
    _checkout_fixed_revision,
    _compatible_attempts,
    _maven_modules,
    _stabilize_build_environment,
    _tailored_build_command,
)
from src.verification.query import query_id, render_endpoint_query, render_path_query
from src.verification.runner import (
    _fixed_database_status,
    _needs_fixed_verification,
    _status,
    build_parser,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_phase11_canonical_selection_is_locked_for_phase12() -> None:
    main = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/main.yaml").read_text(encoding="utf-8")
    )
    lock = main["development_stages"]["phase11_static_verification"]
    canonical = lock["canonical_run"]
    fixed = lock["fixed_databases"]

    assert lock["status"] == "locked_for_phase12_development"
    assert canonical["run_id"] == "p11_diff_dev_full_002"
    assert canonical["run_commit"] == "4b898bfe9a3f16c494ec1942caf95f51e29db221"
    assert canonical["run_git_dirty"] is False
    assert canonical["selected_projects"] == 96
    assert canonical["verified_differential"] == 28
    assert canonical["validator_status"] == "PASS_WITH_ANALYSIS_FAILURES"
    assert canonical["manifest_sha256"] == (
        "6d22442cb41877b79c274e23aa2a3d4b0a97f2400384e14ebbc6a8c5262467f7"
    )
    assert fixed["required"] == fixed["successful"] == 78
    assert fixed["failed"] == 0
    assert lock["next_gate"] == "phase12_calibration_and_selective_routing"


def _spec() -> dict[str, object]:
    return {
        "specification_id": "spec_example_001",
        "candidate_cwe": "CWE-78",
        "sources": [{"node_id": "source"}],
        "sinks": [{"node_id": "sink"}],
        "sanitizers": [],
        "propagators": [],
    }


def _nodes() -> dict[str, dict[str, object]]:
    return {
        "source": {
            "layer": "program",
            "properties": {"location": {"file": "src/Main.java", "start_line": 10}},
        },
        "sink": {
            "layer": "security",
            "properties": {"fact_properties": {"callable": "exec", "type": "Runtime"}},
        },
    }


def test_unresolved_endpoints_skip_taint_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def record_query(**kwargs: object) -> None:
        calls.append(str(kwargs["query_kind"]))

    monkeypatch.setattr(verification_runner, "_run_query", record_query)
    monkeypatch.setattr(
        verification_runner,
        "_endpoint_counts",
        lambda *_args: {"source": 0, "sink": 1},
    )
    result = verification_runner._analyze_version(
        codeql=tmp_path / "codeql",
        database=tmp_path / "database",
        work=tmp_path,
        project_id="proj_example",
        version="vulnerable",
        specification=_spec(),
        nodes=_nodes(),
        timeout=30,
        threads=2,
        ram_mb=1024,
        max_paths=2,
    )
    assert calls == ["endpoint_inventory"]
    assert result["path_count"] == 0
    assert result["sarif"] is None
    assert not _needs_fixed_verification(result)
    assert not _needs_fixed_verification(
        {"source_endpoints": 1, "sink_endpoints": 1, "path_count": 0}
    )
    assert _needs_fixed_verification({"source_endpoints": 1, "sink_endpoints": 1, "path_count": 1})


def test_phase11_pilot_accepts_single_spec_and_timeout() -> None:
    args = build_parser().parse_args(
        [
            "--run-id",
            "pilot_001",
            "--project-id",
            "proj_example",
            "--specification-id",
            "spec_example_001",
            "--query-timeout",
            "1200",
        ]
    )
    assert args.specification_id == "spec_example_001"
    assert args.query_timeout == 1200


def test_rendered_queries_use_global_taint_tracking_and_valid_ids() -> None:
    endpoint = render_endpoint_query(_spec(), _nodes())
    path = render_path_query(_spec(), _nodes())
    assert "@kind table" in endpoint
    assert "phase11Source(endpoint)" in endpoint
    assert "TaintTracking::Global<Phase11Config>" in path
    assert "Phase11Flow::flowPath(source, sink)" in path
    assert query_id("spec_example_001") == "java/maxvera/phase11/spec-example-001"
    assert "SYNTHESIZED_UNVERIFIED" not in path


def test_only_vulnerable_fixed_disappearance_is_verified() -> None:
    path = {"source_endpoints": 1, "sink_endpoints": 1, "path_count": 1}
    no_path = {"source_endpoints": 1, "sink_endpoints": 1, "path_count": 0}
    assert _status(path, no_path)[0] == "VERIFIED_DIFFERENTIAL"
    assert _status(path, None)[0] == "UNVERIFIED_FIXED_NOT_RUN"
    assert _status(path, path)[0] == "UNVERIFIED_PERSISTS_FIXED"
    assert _status(no_path, None)[0] == "UNVERIFIED_NO_VULNERABLE_PATH"
    assert (
        _status({"source_endpoints": 0, "sink_endpoints": 1, "path_count": 0}, None)[0]
        == "UNVERIFIED_UNRESOLVED_SOURCE"
    )


def test_fixed_database_failures_are_counted_instead_of_blocking_run(tmp_path: Path) -> None:
    status_path = tmp_path / "build_status.jsonl"
    rows = [
        {"project_id": "available", "status": "SUCCESS"},
        {"project_id": "failed", "status": "CODEQL_DB_FAILED"},
    ]
    status_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (tmp_path / "available").mkdir()
    (tmp_path / "available" / "codeql-database.yml").write_text("sourceLocationPrefix: /\n")
    (tmp_path / "preparation_manifest.json").write_text(
        json.dumps(
            {
                "development_only": True,
                "locked_test_prepared": False,
                "identity_mapping_persisted": False,
                "status_sha256": sha256_file(status_path),
            }
        ),
        encoding="utf-8",
    )

    result = _fixed_database_status(
        tmp_path,
        ["available", "failed", "phase10_failed"],
        [
            {"project_id": "available", "status": "SUCCESS"},
            {"project_id": "failed", "status": "SUCCESS"},
            {"project_id": "phase10_failed", "status": "ANALYSIS_FAILED"},
        ],
    )

    assert result["required_databases"] == 2
    assert result["available_databases"] == 1
    assert result["unavailable_databases"] == 1


def test_targeted_maven_command_compiles_only_endpoint_modules(tmp_path: Path) -> None:
    (tmp_path / "module-a/src/main/java").mkdir(parents=True)
    (tmp_path / "module-a/pom.xml").write_text("<project />\n", encoding="utf-8")
    (tmp_path / "module-b/src/main/java").mkdir(parents=True)
    (tmp_path / "module-b/pom.xml").write_text("<project />\n", encoding="utf-8")

    modules = _maven_modules(
        tmp_path,
        [
            "module-a/src/main/java/A.java",
            "module-b/src/main/java/B.java",
            "missing/src/main/java/Missing.java",
        ],
    )
    command = _tailored_build_command(
        ["mvn", "clean", "package", "-B", "-DskipTests"],
        {"jdk": "17", "maven": "3.9.8"},
        modules,
    )

    assert modules == ("module-a", "module-b")
    assert command[:5] == ["mvn", "-pl", "module-a,module-b", "-am", "compile"]
    assert "clean" not in command
    assert "package" not in command
    assert "-U" in command


def test_build_attempts_match_the_checked_out_build_system(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project />\n", encoding="utf-8")
    toolchain = {
        "build_attempts": [
            {"jdk": "8u202", "maven": "3.5.0"},
            {"jdk": "17", "gradle": "8.9"},
            {"jdk": "17", "gradlew": True},
        ]
    }
    row = {
        "jdk_version": "8u202",
        "maven_version": "3.5.0",
        "gradle_version": "n/a",
        "use_gradlew": "n/a",
    }

    assert _compatible_attempts(row, toolchain, tmp_path) == [{"jdk": "8u202", "maven": "3.5.0"}]


def test_gradle_wrapper_runs_classes_instead_of_only_clean() -> None:
    command = _tailored_build_command(
        ["./gradlew", "--no-daemon", "clean"],
        {"jdk": "17", "gradlew": True},
        (),
    )

    assert command == ["./gradlew", "--no-daemon", "classes"]


def test_jdk17_builds_disable_legacy_container_detection() -> None:
    environment = _stabilize_build_environment(
        {"JAVA_HOME": "/jdk/17", "PATH": "/tools", "JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8"},
        {"jdk": "17", "maven": "3.9.8"},
    )

    assert environment["JAVA_TOOL_OPTIONS"] == ("-Dfile.encoding=UTF-8 -XX:-UseContainerSupport")
    assert environment["PATH"].startswith(f"/jdk/17/bin{os.pathsep}")
    assert _stabilize_build_environment({}, {"jdk": "8u202"}) == {}


def test_fixed_checkout_uses_commit_already_available_locally(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
    (source / "pom.xml").write_text("<project />\n", encoding="utf-8")
    subprocess.run(["git", "add", "pom.xml"], cwd=source, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=source, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    checkout = tmp_path / "checkout"
    fetched, method = _checkout_fixed_revision(
        source,
        checkout,
        revision,
        "https://invalid.example/not-used.git",
        timeout=10,
    )

    assert fetched is True
    assert method == "local"
    assert (checkout / "pom.xml").is_file()
