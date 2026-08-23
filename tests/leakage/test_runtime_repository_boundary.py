from __future__ import annotations

from pathlib import Path

import pytest

from openiris.data import (
    BuildInfo,
    LeakageError,
    RuntimeInstance,
    RuntimeRepository,
    audit_runtime_repository,
    materialize_runtime_repository,
)


def _instance() -> RuntimeInstance:
    return RuntimeInstance(
        instance_id="oi_" + "1" * 32,
        snapshot_id="fixture",
        track="legacy",
        repository=RuntimeRepository(
            host="github.com",
            owner="acme",
            name="widget",
            url="https://github.com/acme/widget",
        ),
        revision="a" * 40,
        build=BuildInfo(status="success"),
    )


def test_materialized_repository_omits_git_directory(tmp_path: Path) -> None:
    source = tmp_path / "fetched" / "widget"
    (source / "src").mkdir(parents=True)
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    (source / ".git" / "objects").mkdir(parents=True)
    (source / ".git" / "config").write_text("secret metadata\n", encoding="utf-8")

    destination = materialize_runtime_repository(
        _instance(), source, tmp_path / "runtime", verify_revision=False
    )

    expected = tmp_path / "runtime" / "fixture" / _instance().instance_id / "repository"
    assert destination == expected
    assert (destination / "src" / "Main.java").is_file()
    assert not (destination / ".git").exists()
    assert audit_runtime_repository(destination)["status"] == "PASS"


@pytest.mark.parametrize(
    "forbidden_relative",
    [
        Path("advisory") / "notice.json",
        Path("patches") / "change.patch",
        Path("metadata") / "fix_info.csv",
        Path("ground_truth") / "labels.json",
    ],
)
def test_rejects_evaluator_only_files_before_copy(tmp_path: Path, forbidden_relative: Path) -> None:
    source = tmp_path / "fetched" / "widget"
    forbidden = source / forbidden_relative
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("evaluation only\n", encoding="utf-8")
    runtime_root = tmp_path / "runtime"

    with pytest.raises(LeakageError, match="evaluator-only"):
        materialize_runtime_repository(_instance(), source, runtime_root, verify_revision=False)

    assert not (runtime_root / "fixture" / _instance().instance_id / "repository").exists()


def test_rejects_nested_source_and_runtime_paths(tmp_path: Path) -> None:
    source = tmp_path / "fetched"
    source.mkdir()

    with pytest.raises(LeakageError, match="non-nested"):
        materialize_runtime_repository(
            _instance(), source, source / "runtime", verify_revision=False
        )
