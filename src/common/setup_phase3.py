"""Install and verify the checksum/commit-pinned Phase 3 dependencies."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import set_env_value_if_empty
from src.common.provenance import sha256_file, utc_now


def _load_pins(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"invalid upstream pin file: {path}")
    return cast(dict[str, Any], loaded)


def _run(command: Sequence[str], *, cwd: Path | None = None, timeout: int = 3600) -> str:
    process = subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    if process.returncode != 0:
        summary = "\n".join(output.splitlines()[-20:])
        raise ValueError(f"command failed ({process.returncode}): {' '.join(command)}\n{summary}")
    return output


def _download(url: str, destination: Path, expected_sha256: str) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and sha256_file(destination) == expected_sha256:
        return expected_sha256
    partial = destination.with_name(f".{destination.name}.partial")
    curl = shutil.which("curl")
    if not curl:
        raise ValueError("curl is required for resumable Phase 3 downloads")
    _run(
        [
            curl,
            "--fail",
            "--location",
            "--retry",
            "5",
            "--retry-delay",
            "3",
            "--continue-at",
            "-",
            "--output",
            str(partial),
            url,
        ],
        timeout=14400,
    )
    actual = sha256_file(partial)
    if actual != expected_sha256:
        raise ValueError(
            f"SHA256 mismatch for {destination.name}: expected {expected_sha256}, found {actual}"
        )
    os.replace(partial, destination)
    return actual


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            target = (destination / member.filename).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe ZIP path: {member.filename}")
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"symbolic link in ZIP archive: {member.filename}")
        for member in bundle.infolist():
            target = Path(bundle.extract(member, destination))
            permissions = (member.external_attr >> 16) & 0o777
            if permissions and target.is_file():
                target.chmod(permissions)


def _restore_zip_permissions(archive: Path, home: Path, prefix: str) -> None:
    root = home.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if not member.filename.startswith(prefix):
                continue
            relative = member.filename.removeprefix(prefix)
            if not relative:
                continue
            target = (home / relative).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe ZIP permission path: {member.filename}")
            permissions = (member.external_attr >> 16) & 0o777
            if permissions and target.is_file():
                target.chmod(permissions)


def _codeql_binary(home: Path) -> Path:
    for candidate in (home / "codeql", home / "bin/codeql"):
        if candidate.is_file():
            candidate.chmod(candidate.stat().st_mode | 0o100)
            return candidate
    raise ValueError(f"CodeQL executable not found under {home}")


def _install_iris_codeql(repo_root: Path, pins: Mapping[str, Any]) -> dict[str, str]:
    artifact = cast(Mapping[str, Any], pins["codeql_artifact"])
    release = str(artifact["release"])
    archive = repo_root / ".cache/downloads" / f"iris-{release}.zip"
    digest = _download(str(artifact["url"]), archive, str(artifact["sha256"]))
    home = repo_root / ".cache/toolchains" / f"iris-{release}"
    if not home.is_dir():
        home.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{home.name}.", dir=home.parent))
        try:
            _safe_extract_zip(archive, temporary)
            candidates = [temporary / "codeql", temporary]
            extracted = next((item for item in candidates if (item / "codeql").is_file()), None)
            if extracted is None:
                raise ValueError("IRIS CodeQL ZIP does not contain a CodeQL home")
            os.replace(extracted, home)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    _restore_zip_permissions(archive, home, "codeql/")
    binary = _codeql_binary(home)
    reported = _run([str(binary), "version", "--format=terse"], timeout=60).splitlines()[0]
    set_env_value_if_empty(repo_root / ".env", "MAXVERA_IRIS_CODEQL_HOME", str(home))
    return {
        "name": "iris_codeql",
        "release": release,
        "commit": str(artifact["release_tag_commit"]),
        "archive_sha256": digest,
        "reported_version": reported,
        "home": str(home),
    }


def _checkout_llama(repo_root: Path, pins: Mapping[str, Any]) -> Path:
    source = repo_root / "third_party/llama.cpp"
    commit = str(pins["commit"])
    if not (source / ".git").is_dir():
        source.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--filter=blob:none", str(pins["repository"]), str(source)])
    _run(["git", "fetch", "--depth", "1", "origin", commit], cwd=source)
    _run(["git", "checkout", "--detach", commit], cwd=source)
    head = _run(["git", "rev-parse", "HEAD"], cwd=source).splitlines()[0]
    if head != commit:
        raise ValueError(f"llama.cpp checkout mismatch: expected {commit}, found {head}")
    return source


def _build_llama(repo_root: Path, pins: Mapping[str, Any]) -> dict[str, str]:
    source = _checkout_llama(repo_root, pins)
    release = str(pins["release"])
    install = repo_root / ".cache/toolchains" / f"llama.cpp-{release}"
    build = install / "build"
    built_binary = build / "bin/llama-server"
    if not built_binary.is_file():
        install.mkdir(parents=True, exist_ok=True)
        native = all(shutil.which(tool) for tool in ("cmake", "c++"))
        configure = [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DGGML_CUDA=OFF",
            "-DLLAMA_CURL=OFF",
            "-DLLAMA_BUILD_TESTS=OFF",
            "-DLLAMA_BUILD_EXAMPLES=ON",
        ]
        if native:
            _run(configure, timeout=1800)
            _run(["cmake", "--build", str(build), "--target", "llama-server", "-j", "2"])
        else:
            docker = shutil.which("docker")
            if not docker:
                raise ValueError("building pinned llama.cpp requires CMake/C++ or Docker")
            upstreams = _load_pins(repo_root / "configs/upstreams.yaml")
            container = cast(Mapping[str, Any], upstreams["container"])
            image = f"{container['image']}@{container['digest']}"
            uid = str(os.getuid())
            gid = str(os.getgid())
            script = (
                "apt-get update && "
                "apt-get install -y --no-install-recommends cmake g++ make && "
                "cmake -S /source -B /output/build -DCMAKE_BUILD_TYPE=Release "
                "-DGGML_CUDA=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF "
                "-DLLAMA_BUILD_EXAMPLES=ON && "
                "cmake --build /output/build --target llama-server -j 2 && "
                f"chown -R {uid}:{gid} /output"
            )
            _run(
                [
                    docker,
                    "run",
                    "--rm",
                    "--mount",
                    f"type=bind,src={source},dst=/source,readonly",
                    "--mount",
                    f"type=bind,src={install},dst=/output",
                    image,
                    "bash",
                    "-lc",
                    script,
                ],
                timeout=7200,
            )
    built_binary.chmod(built_binary.stat().st_mode | 0o100)
    wrapper = install / "llama-server"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'TOOL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"\n'
        'export LD_LIBRARY_PATH="$TOOL_DIR/build/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n'
        'exec "$TOOL_DIR/build/bin/llama-server" "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    reported = _run([str(wrapper), "--version"], timeout=60)
    commit = str(pins["commit"])
    if commit[:7] not in reported and release.removeprefix("v") not in reported:
        raise ValueError("llama-server does not report the pinned release or commit")
    set_env_value_if_empty(repo_root / ".env", "MAXVERA_LLAMA_SERVER_BIN", str(wrapper))
    return {
        "name": "llama_cpp",
        "release": release,
        "commit": commit,
        "reported_version": reported.splitlines()[0],
        "binary": str(wrapper),
    }


def _install_qwen(repo_root: Path, pins: Mapping[str, Any]) -> dict[str, str]:
    revision = str(pins["revision"])
    filename = str(pins["filename"])
    url = f"https://huggingface.co/{pins['repository']}/resolve/{revision}/{filename}?download=true"
    model = repo_root / ".cache/models" / filename
    digest = _download(url, model, str(pins["sha256"]))
    set_env_value_if_empty(repo_root / ".env", "MAXVERA_MODEL_PATH", str(model))
    return {
        "name": "qwen_model",
        "repository": str(pins["repository"]),
        "revision": revision,
        "filename": filename,
        "sha256": digest,
        "size_bytes": str(model.stat().st_size),
        "path": str(model),
    }


def install(repo_root: Path) -> Path:
    pins = _load_pins(repo_root / "configs/upstreams.yaml")
    tools = [
        _install_iris_codeql(repo_root, cast(Mapping[str, Any], pins["iris_reproduction"])),
        _build_llama(repo_root, cast(Mapping[str, Any], pins["llama_cpp"])),
        _install_qwen(repo_root, cast(Mapping[str, Any], pins["qwen"])),
    ]
    manifest = repo_root / "data/interim/build_info/phase3_toolchains.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {"schema_version": 1, "installed_at": utc_now(), "tools": tools},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = install(args.repo_root.resolve())
    except (OSError, ValueError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        print(f"ERROR: {error}")
        return 1
    print(f"Phase 3 dependencies installed and verified: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
