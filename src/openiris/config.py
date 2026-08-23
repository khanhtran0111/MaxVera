"""Small, deterministic YAML configuration loader used by experiment scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when a configuration cannot be loaded safely."""


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML mapping and reject ambiguous/non-mapping documents."""

    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ConfigError(f"expected a YAML mapping in {config_path}")
    return value


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible data in the canonical form used for hashes."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def config_sha256(config: dict[str, Any]) -> str:
    """Return the stable SHA-256 of a resolved configuration mapping."""

    return hashlib.sha256(canonical_json(config).encode("utf-8")).hexdigest()


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge mappings without mutating either input."""

    result: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result
