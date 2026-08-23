#!/usr/bin/env python3
"""Fetch and verify the patched CodeQL archive pinned for Phase 0."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.request import Request, urlopen

CODEQL_ARCHIVE_URL = (
    "https://github.com/iris-sast/iris/releases/download/codeql-0.8.3-patched/codeql.zip"
)
CODEQL_ARCHIVE_SIZE = 807_846_025
CODEQL_ARCHIVE_SHA256 = "e61633fa05ee291ba01cdaa36bbe96acfe83ca3e6aa6b77b06406abb24cec094"
CODEQL_ARCHIVE_NAME = "iris-codeql-2.15.3-patched.zip"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = PROJECT_ROOT / "tools" / "downloads" / CODEQL_ARCHIVE_NAME
_CHUNK_SIZE = 1024 * 1024

OpenUrl = Callable[[Request, float], AbstractContextManager[BinaryIO]]


class ArchiveVerificationError(ValueError):
    """The fetched or existing release archive does not match the pin."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    destination: Path
    size_bytes: int
    sha256: str
    downloaded: bool
    replaced_invalid: bool


def _stdlib_open_url(request: Request, timeout_seconds: float) -> AbstractContextManager[BinaryIO]:
    # ``urlopen`` takes HTTP request body as its second positional argument;
    # timeout must therefore be passed by keyword.
    return urlopen(request, timeout=timeout_seconds)  # type: ignore[return-value]


def _digest_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while block := handle.read(_CHUNK_SIZE):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def verify_archive(
    path: str | Path,
    *,
    expected_size: int = CODEQL_ARCHIVE_SIZE,
    expected_sha256: str = CODEQL_ARCHIVE_SHA256,
) -> tuple[int, str]:
    """Return the verified size and digest, or raise with both observed values."""

    archive = Path(path)
    if not archive.is_file():
        raise ArchiveVerificationError(f"CodeQL archive is not a file: {archive}")
    size, digest = _digest_file(archive)
    expected_digest = expected_sha256.casefold()
    if size != expected_size or digest != expected_digest:
        raise ArchiveVerificationError(
            "CodeQL archive verification failed: "
            f"expected size={expected_size}, sha256={expected_digest}; "
            f"observed size={size}, sha256={digest}"
        )
    return size, digest


def fetch_archive(
    destination: str | Path = DEFAULT_OUTPUT,
    *,
    url: str = CODEQL_ARCHIVE_URL,
    expected_size: int = CODEQL_ARCHIVE_SIZE,
    expected_sha256: str = CODEQL_ARCHIVE_SHA256,
    timeout_seconds: float = 120.0,
    open_url: OpenUrl | None = None,
) -> FetchResult:
    """Download atomically; a verified destination is returned without network I/O."""

    if expected_size <= 0:
        raise ValueError("expected_size must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    expected_digest = expected_sha256.casefold()
    if len(expected_digest) != 64 or any(
        char not in "0123456789abcdef" for char in expected_digest
    ):
        raise ValueError("expected_sha256 must contain exactly 64 hexadecimal characters")

    output = Path(destination).resolve()
    invalid_existing = False
    if output.exists():
        if not output.is_file():
            raise FileExistsError(f"download destination is not a file: {output}")
        try:
            size, digest = verify_archive(
                output,
                expected_size=expected_size,
                expected_sha256=expected_digest,
            )
        except ArchiveVerificationError:
            invalid_existing = True
        else:
            return FetchResult(
                destination=output,
                size_bytes=size,
                sha256=digest,
                downloaded=False,
                replaced_invalid=False,
            )

    output.parent.mkdir(parents=True, exist_ok=True)
    request = Request(
        url,
        headers={
            "User-Agent": "MaxVera-Phase0-bootstrap/1.0",
            "Accept": "application/octet-stream",
        },
    )
    opener = open_url or _stdlib_open_url
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{output.name}.",
            suffix=".part",
            dir=output.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            digest = hashlib.sha256()
            size = 0
            with opener(request, timeout_seconds) as response:
                while block := response.read(_CHUNK_SIZE):
                    size += len(block)
                    if size > expected_size:
                        raise ArchiveVerificationError(
                            "CodeQL download exceeded pinned size: "
                            f"expected {expected_size}, observed at least {size}"
                        )
                    digest.update(block)
                    temporary.write(block)
            temporary.flush()
            os.fsync(temporary.fileno())

        observed_digest = digest.hexdigest()
        if size != expected_size or observed_digest != expected_digest:
            raise ArchiveVerificationError(
                "CodeQL download verification failed: "
                f"expected size={expected_size}, sha256={expected_digest}; "
                f"observed size={size}, sha256={observed_digest}"
            )
        os.replace(temporary_path, output)
        temporary_path = None
        return FetchResult(
            destination=output,
            size_bytes=size,
            sha256=observed_digest,
            downloaded=True,
            replaced_invalid=invalid_existing,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args()
    result = fetch_archive(args.output, timeout_seconds=args.timeout_seconds)
    action = "verified existing" if not result.downloaded else "downloaded and verified"
    if result.replaced_invalid:
        action += " (replaced invalid existing file)"
    print(f"CodeQL archive {action}: {result.destination}")
    print(f"size={result.size_bytes} sha256={result.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
