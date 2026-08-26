"""Minimal, non-logging .env handling for machine-local configuration."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

REQUIRED_ENV_KEYS = (
    "MAXVERA_CODEQL_HOME",
    "MAXVERA_IRIS_CODEQL_HOME",
    "MAXVERA_LLAMA_SERVER_BIN",
    "MAXVERA_MODEL_PATH",
    "MAXVERA_JAVA_7_HOME",
    "MAXVERA_JAVA_8_HOME",
    "MAXVERA_JAVA_17_HOME",
    "MAXVERA_MAVEN_HOME",
    "MAXVERA_GRADLE_HOME",
)


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE lines without expanding or executing values."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def initialize_env_file(path: Path, keys: tuple[str, ...] = REQUIRED_ENV_KEYS) -> tuple[str, ...]:
    """Create/update .env by appending missing names, never replacing values."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = path.read_text(encoding="utf-8") if path.exists() else ""
    existing = parse_env_file(path)
    missing = tuple(key for key in keys if key not in existing)
    if not missing and path.exists():
        return ()

    sections: list[str] = []
    if existing_text:
        sections.append(existing_text.rstrip("\n"))
    else:
        sections.extend(
            [
                "# Machine-local values only. This file is intentionally ignored by Git.",
                "# Values are never copied into manifests or preflight reports.",
            ]
        )
    sections.extend(f"{key}=" for key in missing)
    content = "\n".join(sections) + "\n"

    descriptor, temporary_name = tempfile.mkstemp(prefix=".env.", dir=path.parent, text=True)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return missing


def effective_env(path: Path) -> dict[str, str]:
    """Return process environment overlaid on .env without mutating os.environ."""
    values = parse_env_file(path)
    for key in REQUIRED_ENV_KEYS:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values
