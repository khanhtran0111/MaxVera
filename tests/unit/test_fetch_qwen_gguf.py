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
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "toolchain" / "fetch_qwen_gguf.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("maxvera_fetch_qwen_test", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fetch_qwen = _load_script()
ModelPin = fetch_qwen.ModelPin
ModelVerificationError = fetch_qwen.ModelVerificationError
fetch_model = fetch_qwen.fetch_model
load_model_pin = fetch_qwen.load_model_pin
verify_model = fetch_qwen.verify_model


def _pin(content: bytes) -> tuple[int, str]:
    return len(content), hashlib.sha256(content).hexdigest()


def _model_pin(digest: str) -> object:
    revision = "a" * 40
    filename = "model-q4_k_m.gguf"
    return ModelPin(
        model_id="owner/model",
        revision=revision,
        filename=filename,
        download_url=f"https://example.test/{revision}/{filename}",
        sha256=digest,
    )


def test_primary_model_pin_is_exact() -> None:
    pin = load_model_pin()
    assert pin.model_id == "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF"
    assert pin.revision == "f74adce6aa16316c625447af059dbebe4983757c"
    assert pin.filename == "qwen2.5-coder-3b-instruct-q4_k_m.gguf"
    assert pin.sha256 == "724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7"
    assert pin.revision in pin.download_url


def test_verified_cached_model_skips_network(tmp_path: Path) -> None:
    content = b"verified gguf"
    size, digest = _pin(content)
    destination = tmp_path / "model.gguf"
    destination.write_bytes(content)

    def unexpected_network(_request: Request, _timeout: float) -> io.BytesIO:
        raise AssertionError("verified model must not perform network I/O")

    result = fetch_model(_model_pin(digest), destination, open_url=unexpected_network)
    assert not result.downloaded
    assert result.size_bytes == size
    assert result.sha256 == digest


def test_download_is_atomic_and_hash_verified(tmp_path: Path) -> None:
    content = b"pinned qwen gguf bytes"
    _, digest = _pin(content)
    destination = tmp_path / "models" / "model.gguf"
    result = fetch_model(
        _model_pin(digest),
        destination,
        open_url=lambda _request, _timeout: io.BytesIO(content),
    )
    assert result.downloaded
    assert destination.read_bytes() == content
    assert not list(destination.parent.glob("*.part"))
    assert verify_model(destination, expected_sha256=digest) == (len(content), digest)


def test_failed_download_preserves_invalid_cache(tmp_path: Path) -> None:
    destination = tmp_path / "model.gguf"
    destination.write_bytes(b"old invalid cache")
    _, expected_digest = _pin(b"expected")
    with pytest.raises(ModelVerificationError, match="download verification failed"):
        fetch_model(
            _model_pin(expected_digest),
            destination,
            open_url=lambda _request, _timeout: io.BytesIO(b"wrong"),
        )
    assert destination.read_bytes() == b"old invalid cache"
    assert not list(tmp_path.glob("*.part"))
