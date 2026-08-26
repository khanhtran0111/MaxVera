from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.common.provenance import (
    REDACTED,
    assert_secret_free,
    atomic_write_json,
    collect_manifest,
    redact_secrets,
    sanitize_git_remote,
    sha256_file,
    write_checksums,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    content = b"maxvera\x00provenance\n"
    artifact.write_bytes(content)
    assert sha256_file(artifact) == hashlib.sha256(content).hexdigest()


def test_recursive_secret_redaction() -> None:
    original = {
        "api_token": "never-serialize-this",
        "nested": {"password": "also-private", "model_sha256": "public-digest"},
        "items": [{"authorization": "Bearer hidden"}, "safe"],
    }
    redacted = redact_secrets(original)
    assert isinstance(redacted, dict)
    assert redacted["api_token"] == REDACTED
    assert redacted["nested"] == {"password": REDACTED, "model_sha256": "public-digest"}
    assert redacted["items"] == [{"authorization": REDACTED}, "safe"]


def test_assert_secret_free_names_leaked_variable_not_value() -> None:
    secret_environment = {"MAXVERA_API_TOKEN": "super-secret-value"}
    with pytest.raises(ValueError, match="MAXVERA_API_TOKEN") as error:
        assert_secret_free({"bad": "super-secret-value"}, secret_environment)
    assert "super-secret-value" not in str(error.value)


def test_git_remote_credentials_and_local_paths_are_removed() -> None:
    assert sanitize_git_remote("https://user:password@example.com/org/repo.git?token=x") == (
        "https://example.com/org/repo.git"
    )
    assert sanitize_git_remote("git@example.com:org/repo.git") == "example.com:org/repo.git"
    assert sanitize_git_remote("C:\\private\\repo") == "LOCAL_OR_REDACTED"


def test_manifest_has_required_provenance_and_no_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "phase-one-test-secret"
    monkeypatch.setenv("MAXVERA_API_TOKEN", secret)
    manifest = collect_manifest(REPO_ROOT, mode="development", run_id="unit-test")
    serialized = json.dumps(manifest)
    assert secret not in serialized
    assert manifest["schema_version"] == 1
    assert manifest["run"] == {
        "id": "unit-test",
        "mode": "development",
        "seed": 1234,
        "parent_run_id": None,
    }
    assert isinstance(manifest["git"], dict)
    assert isinstance(manifest["environment"], dict)
    assert manifest["artifacts"]["model_file_sha256"] == (
        "724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7"
    )


def test_extra_metadata_is_redacted() -> None:
    manifest = collect_manifest(
        REPO_ROOT,
        mode="pilot",
        extra={"access_token": "sensitive", "public": "visible"},
    )
    assert manifest["extra"] == {"access_token": REDACTED, "public": "visible"}


def test_atomic_json_and_checksum_index(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "nested" / "b.json"
    atomic_write_json(first, {"value": 1})
    atomic_write_json(second, {"value": 2})
    assert json.loads(first.read_text(encoding="utf-8")) == {"value": 1}

    checksums = tmp_path / "checksums.sha256"
    write_checksums([second, first], checksums, tmp_path)
    lines = checksums.read_text(encoding="utf-8").splitlines()
    assert lines[0].endswith("  a.json")
    assert lines[1].endswith("  nested/b.json")
