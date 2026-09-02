"""Install the checksum-pinned main-study CodeQL bundle."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import set_env_value_if_empty
from src.common.provenance import sha256_file, utc_now


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
            temporary.open("wb") as handle,
        ):
            shutil.copyfileobj(response, handle)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe path in CodeQL archive: {member.name}")
            if member.isdev():
                raise ValueError(f"device entry in CodeQL archive: {member.name}")
            if member.issym() or member.islnk():
                link = (target.parent / member.linkname).resolve()
                if link != root and root not in link.parents:
                    raise ValueError(f"unsafe link in CodeQL archive: {member.name}")
        bundle.extractall(destination)


def install(repo_root: Path) -> Path:
    with (repo_root / "configs/upstreams.yaml").open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("invalid upstream config")
    pins = cast(dict[str, Any], loaded)["codeql_main"]
    if not isinstance(pins, dict):
        raise ValueError("invalid CodeQL pin")
    linux = pins["linux_x64"]
    if not isinstance(linux, dict):
        raise ValueError("invalid CodeQL Linux pin")
    version = str(pins["cli_version"])
    archive = repo_root / ".cache/downloads" / f"codeql-bundle-v{version}-linux64.tar.gz"
    if not archive.is_file():
        _download(str(linux["url"]), archive)
    expected = str(linux["sha256"])
    actual = sha256_file(archive)
    if actual != expected:
        raise ValueError(f"CodeQL archive SHA256 mismatch: expected {expected}, found {actual}")
    home = repo_root / ".cache/toolchains" / f"codeql-{version}"
    binary = home / "codeql"
    if not binary.is_file():
        temporary = Path(tempfile.mkdtemp(prefix=f".{home.name}.", dir=home.parent))
        try:
            _safe_extract(archive, temporary)
            extracted = temporary / "codeql"
            if not (extracted / "codeql").is_file():
                raise ValueError("CodeQL archive does not contain codeql/codeql")
            os.replace(extracted, home)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    process = subprocess.run(
        [str(binary), "version", "--format=terse"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    reported = process.stdout.strip()
    if process.returncode != 0 or not reported.startswith(version):
        raise ValueError(f"installed CodeQL reports unexpected version: {reported or 'UNKNOWN'}")
    set_env_value_if_empty(repo_root / ".env", "MAXVERA_CODEQL_HOME", str(home))
    manifest = repo_root / "data/interim/build_info/codeql_toolchain.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "installed_at": utc_now(),
                "version": version,
                "bundle_sha256": actual,
                "java_queries_pack": pins["java_queries_pack"],
                "java_library_pack": pins["java_library_pack"],
                "home": str(home),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return home


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        home = install(args.repo_root.resolve())
    except (OSError, ValueError, tarfile.TarError, urllib.error.URLError) as error:
        print(f"ERROR: {error}")
        return 1
    print(f"CodeQL installed and verified: {home}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
