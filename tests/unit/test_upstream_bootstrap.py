from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from openiris.data.upstream import (
    CheckoutDisposition,
    UpstreamBootstrapError,
    bootstrap_phase0_upstreams,
)


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def _repository(path: Path, name: str) -> tuple[Path, str]:
    path.mkdir(parents=True)
    _git("init", "--quiet", cwd=path)
    _git("config", "user.name", "OpenIRIS Test", cwd=path)
    _git("config", "user.email", "openiris@example.invalid", cwd=path)
    (path / "content.txt").write_text(f"{name}\n", encoding="utf-8")
    _git("add", "content.txt", cwd=path)
    _git("commit", "--quiet", "-m", f"initial {name}", cwd=path)
    return path.resolve(), _git("rev-parse", "HEAD", cwd=path)


def _next_commit(repository: Path, content: str) -> str:
    (repository / "content.txt").write_text(content + "\n", encoding="utf-8")
    _git("add", "content.txt", cwd=repository)
    _git("commit", "--quiet", "-m", content, cwd=repository)
    return _git("rev-parse", "HEAD", cwd=repository)


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")


def _configs(
    workspace: Path,
    *,
    legacy: tuple[Path, str],
    v2: tuple[Path, str],
    iris_v1: tuple[Path, str],
) -> None:
    _write_yaml(
        workspace / "configs/datasets/legacy_paper.yaml",
        {
            "source_url": str(legacy[0]),
            "git_commit": legacy[1],
            "source_path": "data/external/legacy",
        },
    )
    _write_yaml(
        workspace / "configs/datasets/v2_snapshot.yaml",
        {
            "source_url": str(v2[0]),
            "git_commit": v2[1],
            "source_path": "data/external/v2",
        },
    )
    _write_yaml(
        workspace / "configs/toolchain/phase0.yaml",
        {
            "iris": {
                "source_url": str(iris_v1[0]),
                "git_commit": iris_v1[1],
                "source_path": "data/external/iris_v1",
            }
        },
    )


def _three_sources(tmp_path: Path) -> tuple[tuple[Path, str], ...]:
    return (
        _repository(tmp_path / "remotes/legacy", "legacy"),
        _repository(tmp_path / "remotes/v2", "v2"),
        _repository(tmp_path / "remotes/iris-v1", "iris-v1"),
    )


def test_bootstrap_uses_pinned_commits_and_is_idempotent(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy, v2, iris_v1 = _three_sources(tmp_path)
    pinned_legacy_commit = legacy[1]
    _next_commit(legacy[0], "floating-head-must-not-be-used")
    _configs(workspace, legacy=(legacy[0], pinned_legacy_commit), v2=v2, iris_v1=iris_v1)
    # An explicitly empty destination is safe to adopt.
    (workspace / "data/external/v2").mkdir(parents=True)

    created = bootstrap_phase0_upstreams(workspace)
    reused = bootstrap_phase0_upstreams(workspace)

    assert [result.disposition for result in created] == [
        CheckoutDisposition.CREATED,
        CheckoutDisposition.CREATED,
        CheckoutDisposition.CREATED,
    ]
    assert all(result.disposition is CheckoutDisposition.REUSED for result in reused)
    expected = {
        "legacy": pinned_legacy_commit,
        "v2": v2[1],
        "iris_v1": iris_v1[1],
    }
    for destination_name, commit in expected.items():
        checkout = workspace / "data/external" / destination_name
        assert _git("rev-parse", "HEAD", cwd=checkout) == commit
        assert _git("rev-parse", "--abbrev-ref", "HEAD", cwd=checkout) == "HEAD"


def test_nonempty_unknown_destination_refuses_before_fetching(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy, v2, iris_v1 = _three_sources(tmp_path)
    _configs(workspace, legacy=legacy, v2=v2, iris_v1=iris_v1)
    unknown = workspace / "data/external/v2"
    unknown.mkdir(parents=True)
    (unknown / "keep.txt").write_text("user data\n", encoding="utf-8")

    with pytest.raises(UpstreamBootstrapError, match="nonempty unknown"):
        bootstrap_phase0_upstreams(workspace)

    assert not (workspace / "data/external/legacy").exists()
    assert (unknown / "keep.txt").read_text(encoding="utf-8") == "user data\n"


def test_existing_commit_mismatch_is_refused_without_replacement(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy, v2, iris_v1 = _three_sources(tmp_path)
    _configs(workspace, legacy=legacy, v2=v2, iris_v1=iris_v1)
    bootstrap_phase0_upstreams(workspace)
    checkout = workspace / "data/external/legacy"
    original_head = _git("rev-parse", "HEAD", cwd=checkout)
    new_commit = _next_commit(legacy[0], "new-pinned-commit")
    _configs(workspace, legacy=(legacy[0], new_commit), v2=v2, iris_v1=iris_v1)

    with pytest.raises(UpstreamBootstrapError, match="commit mismatch"):
        bootstrap_phase0_upstreams(workspace)

    assert _git("rev-parse", "HEAD", cwd=checkout) == original_head


def test_existing_origin_mismatch_is_refused(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy, v2, iris_v1 = _three_sources(tmp_path)
    _configs(workspace, legacy=legacy, v2=v2, iris_v1=iris_v1)
    bootstrap_phase0_upstreams(workspace)
    checkout = workspace / "data/external/legacy"
    _git("remote", "set-url", "origin", str(v2[0]), cwd=checkout)

    with pytest.raises(UpstreamBootstrapError, match="origin mismatch"):
        bootstrap_phase0_upstreams(workspace)
