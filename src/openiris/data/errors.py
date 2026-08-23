"""Errors raised by the OpenIRIS dataset boundary."""

from __future__ import annotations


class DatasetError(Exception):
    """Base class for dataset preparation failures."""


class DatasetFormatError(DatasetError, ValueError):
    """The upstream dataset does not satisfy the expected CSV contract."""


class DatasetIntegrityError(DatasetError):
    """A frozen snapshot no longer matches its recorded checksums."""


class LeakageError(DatasetError):
    """Evaluation-only information crossed into the runtime view."""
