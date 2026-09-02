"""Prepare checksum-pinned CWE-Bench Java build tools and validate JDK homes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env, initialize_env_file, set_env_value_if_empty
from src.common.provenance import sha256_file, utc_now


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"invalid toolchain config: {path}")
    return cast(dict[str, Any], loaded)


def _hash(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_archive(path: Path, metadata: Mapping[str, Any]) -> None:
    for algorithm in ("sha256", "sha512"):
        expected = metadata.get(algorithm)
        if expected is not None and _hash(path, algorithm) != str(expected):
            raise ValueError(f"{algorithm.upper()} mismatch for {path.name}")


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    resolved = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            target = (destination / member.filename).resolve()
            if target != resolved and resolved not in target.parents:
                raise ValueError(f"unsafe ZIP path in {archive.name}: {member.filename}")
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"symbolic link in ZIP archive: {member.filename}")
            bundle.extract(member, destination)
            permissions = mode & 0o777
            if permissions and target.exists():
                target.chmod(permissions)


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if target != resolved and resolved not in target.parents:
                raise ValueError(f"unsafe TAR path in {archive.name}: {member.name}")
            if member.isdev():
                raise ValueError(f"device entry in TAR archive: {member.name}")
            if member.issym():
                link = (target.parent / member.linkname).resolve()
                if link != resolved and resolved not in link.parents:
                    raise ValueError(f"unsafe TAR link in {archive.name}: {member.name}")
            if member.islnk():
                link = (destination / member.linkname).resolve()
                if link != resolved and resolved not in link.parents:
                    raise ValueError(f"unsafe TAR link in {archive.name}: {member.name}")
        bundle.extractall(destination)


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "MaxVera/phase2"})
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            temporary.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _version_output(
    executable: Path,
    arguments: list[str],
    environment: Mapping[str, str] | None = None,
) -> str:
    process = subprocess.run(
        [str(executable), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(environment) if environment is not None else None,
    )
    output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    if process.returncode != 0:
        raise ValueError(f"version check failed for {executable}")
    informative = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and set(line.strip()) != {"-"}
    ]
    return informative[0] if informative else "UNKNOWN"


def _prepare_zip_family(
    family: str,
    entries: Mapping[str, Any],
    install_root: Path,
    download_root: Path,
    *,
    run_version_check: bool,
    version_environment: Mapping[str, str] | None,
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    executable_name = "mvn" if family == "maven" else "gradle"
    arguments = ["--version"]
    for version, untyped in entries.items():
        if not isinstance(untyped, Mapping):
            raise ValueError(f"invalid {family} metadata for {version}")
        metadata = cast(Mapping[str, Any], untyped)
        archive = download_root / str(metadata["archive"])
        if not archive.is_file():
            _download(str(metadata["url"]), archive)
        _validate_archive(archive, metadata)
        home = install_root / str(metadata["directory"])
        executable = home / "bin" / executable_name
        if not executable.is_file():
            _safe_extract_zip(archive, install_root)
        executable.chmod(executable.stat().st_mode | 0o100)
        records.append(
            {
                "family": family,
                "version": str(version),
                "home": str(home),
                "archive": archive.name,
                "archive_sha256": sha256_file(archive),
                "reported_version": (
                    _version_output(executable, arguments, version_environment)
                    if run_version_check
                    else "NOT_RUN_JAVA_REQUIRED"
                ),
            }
        )
    return records


def _validate_jdks(entries: Mapping[str, Any], machine: Mapping[str, str]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    missing: list[str] = []
    for version, untyped in entries.items():
        if not isinstance(untyped, Mapping):
            raise ValueError(f"invalid JDK metadata for {version}")
        metadata = cast(Mapping[str, Any], untyped)
        variable = str(metadata["env_home"])
        configured = machine.get(variable)
        if not configured:
            missing.append(variable)
            continue
        home = Path(configured).expanduser().resolve()
        executable = home / "bin" / "java"
        if not executable.is_file():
            raise ValueError(f"{variable} does not contain bin/java")
        report = _version_output(executable, ["-version"])
        expected = "1.7" if str(version) == "7u80" else ("1.8" if str(version) == "8u202" else "17")
        if expected not in report:
            raise ValueError(f"{variable} reports an unexpected Java version")
        records.append(
            {
                "family": "jdk",
                "version": str(version),
                "home": str(home),
                "reported_version": report,
                "source": str(metadata["acquisition"]),
                "vendor": str(metadata["vendor"]),
            }
        )
    if missing:
        raise ValueError("missing JDK configuration variables: " + ", ".join(sorted(missing)))
    return records


def _prepare_jdks(
    entries: Mapping[str, Any], install_root: Path, download_root: Path, env_path: Path
) -> None:
    for version, untyped in entries.items():
        if not isinstance(untyped, Mapping):
            raise ValueError(f"invalid JDK metadata for {version}")
        metadata = cast(Mapping[str, Any], untyped)
        archive = download_root / str(metadata["archive"])
        if not archive.is_file():
            _download(str(metadata["url"]), archive)
        _validate_archive(archive, metadata)
        home = install_root / str(metadata["directory"])
        if not (home / "bin" / "java").is_file():
            archive_type = str(metadata["archive_type"])
            if archive_type == "zip":
                _safe_extract_zip(archive, install_root)
            elif archive_type == "tar.gz":
                _safe_extract_tar(archive, install_root)
            else:
                raise ValueError(f"unsupported JDK archive type: {archive_type}")
        if not (home / "bin" / "java").is_file():
            raise ValueError(f"JDK {version} archive did not create expected home: {home.name}")
        for candidate in home.rglob("*"):
            if candidate.is_file() and "bin" in candidate.relative_to(home).parts:
                candidate.chmod(candidate.stat().st_mode | 0o100)
        set_env_value_if_empty(env_path, str(metadata["env_home"]), str(home.resolve()))


def prepare(
    repo_root: Path, config_path: Path, *, require_jdks: bool, install_jdks: bool = False
) -> Path:
    config = _load_config(config_path)
    install_root = repo_root / str(config["install_root"])
    download_root = install_root / "downloads"
    install_root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, str]] = []
    version_environment: dict[str, str] | None = None
    env_path = repo_root / ".env"
    if install_jdks:
        _prepare_jdks(cast(Mapping[str, Any], config["jdk"]), install_root, download_root, env_path)
    if require_jdks:
        initialize_env_file(env_path)
        machine = effective_env(env_path)
        jdk_records = _validate_jdks(cast(Mapping[str, Any], config["jdk"]), machine)
        records.extend(jdk_records)
        java_17 = next(record for record in jdk_records if record["version"] == "17")
        version_environment = dict(os.environ)
        version_environment["JAVA_HOME"] = java_17["home"]
        java_bin = str(Path(java_17["home"]) / "bin")
        version_environment["PATH"] = f"{java_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    records.extend(
        _prepare_zip_family(
            "maven",
            cast(Mapping[str, Any], config["maven"]),
            install_root,
            download_root,
            run_version_check=require_jdks,
            version_environment=version_environment,
        )
    )
    records.extend(
        _prepare_zip_family(
            "gradle",
            cast(Mapping[str, Any], config["gradle"]),
            install_root,
            download_root,
            run_version_check=require_jdks,
            version_environment=version_environment,
        )
    )
    defaults = config.get("default_env_homes", {})
    if not isinstance(defaults, Mapping):
        raise ValueError("default_env_homes must be a mapping")
    for variable, relative_home in defaults.items():
        set_env_value_if_empty(
            env_path, str(variable), str((install_root / str(relative_home)).resolve())
        )
    manifest = repo_root / "data" / "interim" / "build_info" / "toolchains.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "prepared_at": utc_now(),
        "config_sha256": sha256_file(config_path),
        "jdk_validation_required": require_jdks,
        "tools": records,
    }
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--config", type=Path, default=Path("configs/toolchains/cwe_bench_java.yaml")
    )
    parser.add_argument("--require-jdks", action="store_true")
    parser.add_argument("--install-jdks", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.repo_root.resolve()
    config = args.config if args.config.is_absolute() else root / args.config
    try:
        manifest = prepare(
            root,
            config,
            require_jdks=bool(args.require_jdks),
            install_jdks=bool(args.install_jdks),
        )
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as error:
        print(f"ERROR: {error}")
        return 1
    print(f"Toolchain manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
