#!/usr/bin/env python3
"""Fetch the pinned primary Qwen GGUF model and verify its SHA-256 digest."""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.request import Request, urlopen

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "models" / "qwen25_coder_3b_q4_k_m.yaml"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models"
_CHUNK_SIZE = 1024 * 1024

OpenUrl = Callable[[Request, float], AbstractContextManager[BinaryIO]]


class ModelVerificationError(ValueError):
    """The downloaded or cached GGUF file does not match its immutable pin."""


@dataclass(frozen=True, slots=True)
class ModelPin:
    model_id: str
    revision: str
    filename: str
    download_url: str
    sha256: str


@dataclass(frozen=True, slots=True)
class FetchResult:
    destination: Path
    size_bytes: int
    sha256: str
    downloaded: bool
    replaced_invalid: bool


def _required_text(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"model config field {key!r} must be a non-empty string")
    return value.strip()


def load_model_pin(path: str | Path = DEFAULT_CONFIG) -> ModelPin:
    """Load and validate only the immutable download identity from a model config."""

    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, Mapping):
        raise ValueError(f"expected a mapping in model config: {config_path}")
    pin = ModelPin(
        model_id=_required_text(document, "model_id"),
        revision=_required_text(document, "revision"),
        filename=_required_text(document, "filename"),
        download_url=_required_text(document, "download_url"),
        sha256=_required_text(document, "sha256").casefold(),
    )
    if len(pin.revision) != 40 or any(char not in "0123456789abcdef" for char in pin.revision):
        raise ValueError("model revision must be a full lowercase 40-hex commit")
    if Path(pin.filename).name != pin.filename or not pin.filename.casefold().endswith(".gguf"):
        raise ValueError("model filename must be a portable GGUF basename")
    if len(pin.sha256) != 64 or any(char not in "0123456789abcdef" for char in pin.sha256):
        raise ValueError("model sha256 must contain exactly 64 hexadecimal characters")
    if pin.revision not in pin.download_url or pin.filename not in pin.download_url:
        raise ValueError("download_url must embed the pinned revision and filename")
    return pin


def _stdlib_open_url(request: Request, timeout_seconds: float) -> AbstractContextManager[BinaryIO]:
    return urlopen(request, timeout=timeout_seconds)  # type: ignore[return-value]


def digest_file(path: str | Path) -> tuple[int, str]:
    model_path = Path(path)
    if not model_path.is_file():
        raise ModelVerificationError(f"GGUF model is not a file: {model_path}")
    digest = hashlib.sha256()
    size = 0
    with model_path.open("rb") as handle:
        while block := handle.read(_CHUNK_SIZE):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def verify_model(path: str | Path, *, expected_sha256: str) -> tuple[int, str]:
    """Return size and digest when the local GGUF matches the pinned digest."""

    size, observed = digest_file(path)
    expected = expected_sha256.casefold()
    if observed != expected:
        raise ModelVerificationError(
            f"GGUF verification failed: expected sha256={expected}; observed sha256={observed}"
        )
    return size, observed


def fetch_model(
    pin: ModelPin,
    destination: str | Path,
    *,
    timeout_seconds: float = 300.0,
    open_url: OpenUrl | None = None,
) -> FetchResult:
    """Download atomically, retaining an invalid cached file until verification succeeds."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    output = Path(destination).resolve()
    invalid_existing = False
    if output.exists():
        if not output.is_file():
            raise FileExistsError(f"model destination is not a file: {output}")
        try:
            size, digest = verify_model(output, expected_sha256=pin.sha256)
        except ModelVerificationError:
            invalid_existing = True
        else:
            return FetchResult(output, size, digest, downloaded=False, replaced_invalid=False)

    output.parent.mkdir(parents=True, exist_ok=True)
    request = Request(
        pin.download_url,
        headers={
            "User-Agent": "MaxVera-local-model-bootstrap/1.0",
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
                    digest.update(block)
                    temporary.write(block)
            temporary.flush()
            os.fsync(temporary.fileno())

        observed = digest.hexdigest()
        if observed != pin.sha256:
            raise ModelVerificationError(
                "GGUF download verification failed: "
                f"expected sha256={pin.sha256}; observed sha256={observed}"
            )
        os.replace(temporary_path, output)
        temporary_path = None
        return FetchResult(
            output, size, observed, downloaded=True, replaced_invalid=invalid_existing
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args()
    pin = load_model_pin(args.config)
    output = args.output or DEFAULT_MODEL_DIR / pin.filename
    result = fetch_model(pin, output, timeout_seconds=args.timeout_seconds)
    action = "verified existing" if not result.downloaded else "downloaded and verified"
    if result.replaced_invalid:
        action += " (replaced invalid cached file)"
    print(f"Qwen GGUF {action}: {result.destination}")
    print(f"model={pin.model_id}@{pin.revision}")
    print(f"size={result.size_bytes} sha256={result.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
