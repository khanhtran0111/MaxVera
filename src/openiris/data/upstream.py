"""Reproducible bootstrap for the three pinned Phase 0 upstream checkouts."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from openiris.config import load_yaml

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SCP_GIT_URL = re.compile(r"^[^/\\]+@[^:]+:.+$")


class UpstreamBootstrapError(RuntimeError):
    """Raised before an unsafe or non-reproducible checkout is accepted."""


class CheckoutDisposition(StrEnum):
    CREATED = "CREATED"
    REUSED = "REUSED"


@dataclass(frozen=True, slots=True)
class CheckoutSpec:
    """One immutable Git source declared by a Phase 0 config."""

    name: str
    source_url: str
    commit: str
    destination: Path


@dataclass(frozen=True, slots=True)
class CheckoutResult:
    name: str
    destination: Path
    source_url: str
    commit: str
    disposition: CheckoutDisposition


def _run_git(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603,S607 - fixed executable, shell disabled
            ["git", *argv],
            cwd=cwd,
            check=check,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except FileNotFoundError as exc:
        raise UpstreamBootstrapError("git executable is not available") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise UpstreamBootstrapError(f"git command failed: {detail}") from exc


def _is_remote_url(value: str) -> bool:
    return bool(_URL_SCHEME.match(value) or _SCP_GIT_URL.match(value))


def _normalized_source(value: str, workspace: Path) -> str:
    source = value.strip()
    if not source:
        raise UpstreamBootstrapError("Git source URL cannot be empty")
    if _is_remote_url(source):
        return source.rstrip("/")
    local = Path(source)
    if not local.is_absolute():
        local = workspace / local
    return str(local.resolve())


def _source_identity(value: str) -> str:
    if _is_remote_url(value):
        return value.rstrip("/")
    return os.path.normcase(str(Path(value).resolve()))


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UpstreamBootstrapError(f"{label} config section must be a mapping")
    return value


def _config_spec(
    name: str,
    config: Mapping[str, Any],
    workspace: Path,
) -> CheckoutSpec:
    try:
        source_value = str(config["source_url"])
        commit = str(config["git_commit"]).lower()
        path_value = Path(str(config["source_path"]))
    except KeyError as exc:
        raise UpstreamBootstrapError(f"{name} config is missing {exc.args[0]!r}") from exc
    if _COMMIT.fullmatch(commit) is None:
        raise UpstreamBootstrapError(f"{name} commit must be a full lowercase 40-hex SHA")
    destination = path_value if path_value.is_absolute() else workspace / path_value
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise UpstreamBootstrapError(
            f"{name} destination must stay inside the workspace: {destination}"
        ) from exc
    if destination == workspace:
        raise UpstreamBootstrapError(f"{name} destination cannot be the workspace root")
    return CheckoutSpec(
        name=name,
        source_url=_normalized_source(source_value, workspace),
        commit=commit,
        destination=destination,
    )


def load_phase0_checkout_specs(
    workspace: str | Path,
    *,
    legacy_config: str | Path = "configs/datasets/legacy_paper.yaml",
    v2_config: str | Path = "configs/datasets/v2_snapshot.yaml",
    toolchain_config: str | Path = "configs/toolchain/phase0.yaml",
) -> tuple[CheckoutSpec, ...]:
    """Load the immutable source URL, commit, and destination from configs."""

    root = Path(workspace).resolve()

    def config_path(value: str | Path) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (root / path).resolve()

    legacy = load_yaml(config_path(legacy_config))
    v2 = load_yaml(config_path(v2_config))
    toolchain = load_yaml(config_path(toolchain_config))
    iris = _mapping(toolchain.get("iris"), "toolchain.iris")
    specs = (
        _config_spec("legacy_dataset", legacy, root),
        _config_spec("iris_v2_snapshot", v2, root),
        _config_spec("iris_v1_source", iris, root),
    )
    destinations = [spec.destination for spec in specs]
    if len(destinations) != len(set(destinations)):
        raise UpstreamBootstrapError("upstream checkout destinations must be unique")
    for index, left in enumerate(destinations):
        for right in destinations[index + 1 :]:
            if left in right.parents or right in left.parents:
                raise UpstreamBootstrapError(
                    f"upstream checkout destinations cannot be nested: {left}, {right}"
                )
    return specs


def verify_checkout(spec: CheckoutSpec) -> None:
    """Require exact origin, detached commit, and an unmodified worktree."""

    destination = spec.destination
    if not destination.is_dir() or not (destination / ".git").exists():
        raise UpstreamBootstrapError(f"not a Git checkout: {destination}")
    actual_commit = _run_git(["-C", str(destination), "rev-parse", "HEAD"]).stdout.strip()
    if actual_commit.casefold() != spec.commit:
        raise UpstreamBootstrapError(
            f"{spec.name} commit mismatch at {destination}: "
            f"expected {spec.commit}, found {actual_commit}"
        )
    branch = _run_git(["-C", str(destination), "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    if branch != "HEAD":
        raise UpstreamBootstrapError(
            f"{spec.name} checkout must be detached, found branch {branch!r}"
        )
    actual_source = _run_git(["-C", str(destination), "remote", "get-url", "origin"]).stdout.strip()
    if _source_identity(actual_source) != _source_identity(spec.source_url):
        raise UpstreamBootstrapError(
            f"{spec.name} origin mismatch at {destination}: "
            f"expected {spec.source_url!r}, found {actual_source!r}"
        )
    dirty = _run_git(
        ["-C", str(destination), "status", "--porcelain=v1", "--untracked-files=all"]
    ).stdout
    if dirty.strip():
        raise UpstreamBootstrapError(
            f"{spec.name} checkout is modified or has untracked files: {destination}"
        )


def _existing_disposition(spec: CheckoutSpec) -> CheckoutDisposition | None:
    destination = spec.destination
    if not destination.exists():
        return None
    if not destination.is_dir():
        raise UpstreamBootstrapError(f"checkout destination is not a directory: {destination}")
    if not any(destination.iterdir()):
        return None
    if not (destination / ".git").exists():
        raise UpstreamBootstrapError(
            f"refusing nonempty unknown checkout destination: {destination}"
        )
    verify_checkout(spec)
    return CheckoutDisposition.REUSED


def _safe_cleanup_staging(staging: Path, parent: Path, prefix: str) -> None:
    resolved = staging.resolve()
    if resolved.parent != parent.resolve() or not resolved.name.startswith(prefix):
        raise UpstreamBootstrapError(f"refusing to clean unexpected staging path: {resolved}")
    shutil.rmtree(resolved)


def _fetch_exact(spec: CheckoutSpec) -> CheckoutResult:
    destination = spec.destination
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    prefix = f".{destination.name}.bootstrap-"
    staging = Path(tempfile.mkdtemp(prefix=prefix, dir=parent)).resolve()
    try:
        _run_git(["init", "--quiet", str(staging)])
        _run_git(["-C", str(staging), "remote", "add", "origin", spec.source_url])
        _run_git(
            [
                "-C",
                str(staging),
                "fetch",
                "--quiet",
                "--depth=1",
                "--no-tags",
                "origin",
                spec.commit,
            ]
        )
        _run_git(["-C", str(staging), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
        verify_checkout(
            CheckoutSpec(
                name=spec.name,
                source_url=spec.source_url,
                commit=spec.commit,
                destination=staging,
            )
        )
        if destination.exists():
            if not destination.is_dir() or any(destination.iterdir()):
                raise UpstreamBootstrapError(
                    f"checkout destination changed during fetch: {destination}"
                )
            destination.rmdir()
        staging.rename(destination)
    except BaseException:
        if staging.exists():
            _safe_cleanup_staging(staging, parent, prefix)
        raise
    verify_checkout(spec)
    return CheckoutResult(
        name=spec.name,
        destination=destination,
        source_url=spec.source_url,
        commit=spec.commit,
        disposition=CheckoutDisposition.CREATED,
    )


def bootstrap_checkouts(specs: Sequence[CheckoutSpec]) -> tuple[CheckoutResult, ...]:
    """Preflight every destination, then fetch only missing exact commits."""

    dispositions: dict[str, CheckoutDisposition | None] = {}
    for spec in specs:
        dispositions[spec.name] = _existing_disposition(spec)

    results: list[CheckoutResult] = []
    for spec in specs:
        disposition = dispositions[spec.name]
        if disposition is None:
            results.append(_fetch_exact(spec))
        else:
            results.append(
                CheckoutResult(
                    name=spec.name,
                    destination=spec.destination,
                    source_url=spec.source_url,
                    commit=spec.commit,
                    disposition=disposition,
                )
            )
    return tuple(results)


def bootstrap_phase0_upstreams(
    workspace: str | Path,
    *,
    legacy_config: str | Path = "configs/datasets/legacy_paper.yaml",
    v2_config: str | Path = "configs/datasets/v2_snapshot.yaml",
    toolchain_config: str | Path = "configs/toolchain/phase0.yaml",
) -> tuple[CheckoutResult, ...]:
    specs = load_phase0_checkout_specs(
        workspace,
        legacy_config=legacy_config,
        v2_config=v2_config,
        toolchain_config=toolchain_config,
    )
    return bootstrap_checkouts(specs)
