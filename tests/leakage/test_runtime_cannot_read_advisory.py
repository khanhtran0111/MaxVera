from __future__ import annotations

import json

import pytest

from openiris.data import LeakageError, RuntimeInstance


def test_runtime_cannot_read_advisory(separated_views) -> None:
    record = json.loads(separated_views.runtime_manifest.read_text(encoding="utf-8"))
    record["advisory"] = "GHSA-aaaa-bbbb-cccc"

    with pytest.raises(LeakageError, match="Forbidden runtime field"):
        RuntimeInstance.from_dict(record)


def test_runtime_manifest_has_no_advisory_value(separated_views) -> None:
    runtime_text = separated_views.runtime_manifest.read_text(encoding="utf-8")
    assert "ghsa-" not in runtime_text.casefold()
    assert "advisory" not in runtime_text.casefold()
