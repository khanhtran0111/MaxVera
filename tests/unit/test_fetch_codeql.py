from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
from pathlib import Path
from types import ModuleType
from urllib.request import Request

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "toolchain" / "fetch_codeql.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("maxvera_fetch_codeql_test", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fetch_codeql = _load_script()
CODEQL_ARCHIVE_NAME = fetch_codeql.CODEQL_ARCHIVE_NAME
CODEQL_ARCHIVE_SHA256 = fetch_codeql.CODEQL_ARCHIVE_SHA256
CODEQL_ARCHIVE_SIZE = fetch_codeql.CODEQL_ARCHIVE_SIZE
CODEQL_ARCHIVE_URL = fetch_codeql.CODEQL_ARCHIVE_URL
ArchiveVerificationError = fetch_codeql.ArchiveVerificationError
fetch_archive = fetch_codeql.fetch_archive
verify_archive = fetch_codeql.verify_archive


def _pin(content: bytes) -> tuple[int, str]:
    return len(content), hashlib.sha256(content).hexdigest()


def test_phase0_codeql_pin_is_exact() -> None:
    assert CODEQL_ARCHIVE_URL == (
        "https://github.com/iris-sast/iris/releases/download/codeql-0.8.3-patched/codeql.zip"
    )
    assert CODEQL_ARCHIVE_NAME == "iris-codeql-2.15.3-patched.zip"
    assert CODEQL_ARCHIVE_SIZE == 807_846_025
    assert CODEQL_ARCHIVE_SHA256 == (
        "e61633fa05ee291ba01cdaa36bbe96acfe83ca3e6aa6b77b06406abb24cec094"
    )


def test_verified_existing_archive_skips_network(tmp_path: Path) -> None:
    content = b"already verified"
    size, digest = _pin(content)
    destination = tmp_path / "codeql.zip"
    destination.write_bytes(content)

    def unexpected_network(_request: Request, _timeout: float) -> io.BytesIO:
        raise AssertionError("verified existing file must not perform network I/O")

    result = fetch_archive(
        destination,
        expected_size=size,
        expected_sha256=digest,
        open_url=unexpected_network,
    )

    assert not result.downloaded
    assert not result.replaced_invalid
    assert result.size_bytes == size
    assert result.sha256 == digest


def test_download_is_verified_and_installed_atomically(tmp_path: Path) -> None:
    content = b"pinned release bytes"
    size, digest = _pin(content)
    destination = tmp_path / "nested" / "codeql.zip"
    observed: list[tuple[str, float, str]] = []

    def response(request: Request, timeout: float) -> io.BytesIO:
        observed.append((request.full_url, timeout, request.get_header("User-agent") or ""))
        return io.BytesIO(content)

    result = fetch_archive(
        destination,
        url="https://example.test/pinned.zip",
        expected_size=size,
        expected_sha256=digest,
        timeout_seconds=7,
        open_url=response,
    )

    assert result.downloaded
    assert destination.read_bytes() == content
    assert observed == [("https://example.test/pinned.zip", 7, "MaxVera-Phase0-bootstrap/1.0")]
    assert not list(destination.parent.glob("*.part"))
    assert verify_archive(destination, expected_size=size, expected_sha256=digest) == (
        size,
        digest,
    )


def test_stdlib_opener_passes_timeout_by_keyword(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[tuple[Request, object, float]] = []

    def fake_urlopen(
        request: Request,
        data: object = None,
        *,
        timeout: float,
    ) -> io.BytesIO:
        observed.append((request, data, timeout))
        return io.BytesIO(b"")

    monkeypatch.setattr(fetch_codeql, "urlopen", fake_urlopen)
    request = Request("https://example.test/archive.zip")
    with fetch_codeql._stdlib_open_url(request, 9):
        pass

    assert observed == [(request, None, 9)]


def test_valid_download_replaces_only_an_invalid_existing_file(tmp_path: Path) -> None:
    content = b"correct"
    size, digest = _pin(content)
    destination = tmp_path / "codeql.zip"
    destination.write_bytes(b"partial")

    result = fetch_archive(
        destination,
        expected_size=size,
        expected_sha256=digest,
        open_url=lambda _request, _timeout: io.BytesIO(content),
    )

    assert result.downloaded
    assert result.replaced_invalid
    assert destination.read_bytes() == content


def test_failed_download_preserves_existing_file_and_removes_partial(tmp_path: Path) -> None:
    destination = tmp_path / "codeql.zip"
    destination.write_bytes(b"existing invalid evidence")
    expected = b"expected content"
    size, digest = _pin(expected)

    with pytest.raises(ArchiveVerificationError, match="verification failed"):
        fetch_archive(
            destination,
            expected_size=size,
            expected_sha256=digest,
            open_url=lambda _request, _timeout: io.BytesIO(b"wrong content---"),
        )

    assert destination.read_bytes() == b"existing invalid evidence"
    assert not list(tmp_path.glob("*.part"))
