"""Canonical repository paths for evaluator-side comparisons."""

from __future__ import annotations

import posixpath
import re
from os import PathLike
from urllib.parse import unquote, urlsplit

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:/")
_FILE_URI_WINDOWS_DRIVE = re.compile(r"^/[A-Za-z]:/")


def _as_text(value: str | PathLike[str]) -> str:
    return value if isinstance(value, str) else str(value)


def _decode_file_uri(value: str) -> str:
    """Turn a file URI into a path without relying on the host operating system."""

    if not value.lower().startswith("file:"):
        return unquote(value)

    parsed = urlsplit(value)
    path = unquote(parsed.path)
    if parsed.netloc and parsed.netloc.lower() != "localhost":
        path = f"//{parsed.netloc}{path}"
    if _FILE_URI_WINDOWS_DRIVE.match(path):
        path = path[1:]
    return path


def _canonical_path(value: str | PathLike[str]) -> str:
    path = _decode_file_uri(_as_text(value)).replace("\\", "/")
    if not path:
        return ""

    # posixpath works deterministically for both Windows and POSIX inputs.  It
    # also removes repeated separators and harmless ``.`` segments.
    path = posixpath.normpath(path)
    if path == ".":
        return ""
    if path.startswith("./"):
        path = path[2:]
    if _WINDOWS_DRIVE.match(path):
        path = path[0].upper() + path[1:]
    return path


def _is_windows_absolute(path: str) -> bool:
    return bool(_WINDOWS_DRIVE.match(path)) or path.startswith("//")


def _relative_to_root(path: str, root: str) -> str | None:
    """Return a lexical relative path when *path* is inside *root*."""

    if not path or not root:
        return None

    windows = _is_windows_absolute(path) or _is_windows_absolute(root)
    comparable_path = path.casefold() if windows else path
    comparable_root = root.rstrip("/").casefold() if windows else root.rstrip("/")
    if comparable_path == comparable_root:
        return ""

    prefix = comparable_root + "/"
    if comparable_path.startswith(prefix):
        return path[len(root.rstrip("/")) + 1 :]
    return None


def normalize_uri(
    uri: str | PathLike[str],
    repository_root: str | PathLike[str] | None = None,
) -> str:
    """Normalize a SARIF URI or benchmark path to a portable repository path.

    Backslashes and file URIs are normalized without consulting the host OS.
    When ``repository_root`` is provided, absolute locations below that root
    become repository-relative.  This lets a Windows-produced SARIF file be
    evaluated on POSIX (and vice versa).
    """

    path = _canonical_path(uri)
    if repository_root is None:
        return path

    root = _canonical_path(repository_root).rstrip("/")
    relative = _relative_to_root(path, root)
    return path if relative is None else relative
