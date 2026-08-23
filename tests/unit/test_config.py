from __future__ import annotations

from openiris.config import config_sha256, deep_merge


def test_config_hash_is_independent_of_mapping_order() -> None:
    assert config_sha256({"b": 2, "a": 1}) == config_sha256({"a": 1, "b": 2})


def test_deep_merge_does_not_mutate_inputs() -> None:
    base = {"tool": {"version": "1", "timeout": 1}}
    override = {"tool": {"timeout": 2}}

    assert deep_merge(base, override) == {"tool": {"version": "1", "timeout": 2}}
    assert base["tool"]["timeout"] == 1
