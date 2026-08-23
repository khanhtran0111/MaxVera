from __future__ import annotations

from pathlib import Path

from openiris.utils.hashing import sha256_paths


def test_tree_hash_is_order_independent(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")

    forward = sha256_paths(tmp_path, ["a.txt", "b.txt"])
    reverse = sha256_paths(tmp_path, ["b.txt", "a.txt"])

    assert forward == reverse
