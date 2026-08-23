"""Allow data entrypoints to run from a source checkout before installation."""

from __future__ import annotations

import sys
from pathlib import Path


def add_source_tree() -> None:
    source = Path(__file__).resolve().parents[2] / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
