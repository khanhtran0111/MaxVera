from __future__ import annotations

import json
from pathlib import Path

import pytest

from openiris.data import LeakageError, RuntimeInstance, materialize_dataset_views


def test_runtime_cannot_read_fix_info(separated_views) -> None:
    record = json.loads(separated_views.runtime_manifest.read_text(encoding="utf-8"))
    record["fix_commit_ids"] = ["b" * 40]

    with pytest.raises(LeakageError, match="Forbidden runtime field"):
        RuntimeInstance.from_dict(record)


def test_runtime_and_ground_truth_cannot_share_or_nest_root(tmp_path: Path) -> None:
    # Importing the fixture's bundle is intentionally avoided; the guard runs
    # before bundle contents are inspected.
    from openiris.data import DatasetBundle

    bundle = DatasetBundle(tmp_path / "source", "legacy", (), {}, {})
    with pytest.raises(LeakageError, match="physically separate"):
        materialize_dataset_views(bundle, "fixture", tmp_path / "views", tmp_path / "views")
