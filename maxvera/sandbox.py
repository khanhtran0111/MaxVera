"""Linux Landlock read allowlist inherited by all research subprocesses.

Deny-by-default filesystem access, not a Python open() monkeypatch. Unavailable
kernels fail closed. The trusted parent selects only label-free input paths.
"""

from __future__ import annotations

import ctypes
import os
import platform
from pathlib import Path

SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446
EXECUTE, READ_FILE, READ_DIR = 1, 4, 8
READ_ACCESS = EXECUTE | READ_FILE | READ_DIR
# ABI >=3 handles refer/rename and truncate in addition to creation/removal/write.
WRITE_ACCESS = ((1 << 15) - 1) & ~READ_ACCESS
HANDLED = READ_ACCESS | WRITE_ACCESS


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


def landlock_available() -> bool:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.syscall(SYS_CREATE, 0, 0, 1) >= 3


def restrict_reads(paths: list[Path], *, write_paths: list[Path] | None = None) -> None:
    if not landlock_available():
        raise RuntimeError("research requires Linux Landlock; no unisolated fallback")
    libc = ctypes.CDLL(None, use_errno=True)
    ruleset = Ruleset(HANDLED)
    fd = libc.syscall(SYS_CREATE, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "Landlock ruleset creation failed")
    try:
        for path, writable in [(p, False) for p in paths] + [
            (p, True) for p in (write_paths or [])
        ]:
            if not path.exists():
                continue
            parent = os.open(path.resolve(), os.O_PATH | os.O_CLOEXEC)
            try:
                access = READ_ACCESS if path.is_dir() else EXECUTE | READ_FILE
                if writable:
                    access |= WRITE_ACCESS if path.is_dir() else (2 | (1 << 14))
                rule = PathRule(access, parent)
                if libc.syscall(SYS_ADD, fd, 1, ctypes.byref(rule), 0) < 0:
                    raise OSError(ctypes.get_errno(), "Landlock allowlist rule failed")
            finally:
                os.close(parent)
        if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), "no_new_privs failed")
        if libc.syscall(SYS_RESTRICT, fd, 0):
            raise OSError(ctypes.get_errno(), "Landlock restriction failed")
    finally:
        os.close(fd)
