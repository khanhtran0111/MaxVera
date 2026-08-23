"""Hash helpers for source snapshots and generated artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_paths(root: str | Path, relative_paths: Iterable[str | Path]) -> str:
    """Hash path names and contents in a deterministic, platform-neutral order."""

    root_path = Path(root)
    normalized = sorted(Path(item).as_posix() for item in relative_paths)
    digest = hashlib.sha256()
    for relative in normalized:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(root_path / Path(relative))))
        digest.update(b"\0")
    return digest.hexdigest()
