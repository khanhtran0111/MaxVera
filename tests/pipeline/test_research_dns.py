"""DNS configuration follows a system symlink without opening its runtime directory."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest


def test_resolver_target_read_is_allowed_but_neighbor_is_protected(tmp_path):
    from maxvera.sandbox import landlock_available, resolver_runtime_paths

    if not landlock_available():
        pytest.skip("Landlock unavailable")
    etc = tmp_path / "etc"
    runtime = tmp_path / "run/systemd/resolve"
    etc.mkdir()
    runtime.mkdir(parents=True)
    target = runtime / "stub-resolv.conf"
    target.write_text("nameserver 127.0.0.53\n")
    secret = runtime / "unrelated-private-file"
    secret.write_text("private")
    resolver = etc / "resolv.conf"
    resolver.symlink_to(target)
    paths = resolver_runtime_paths(resolver)
    script = """
import json, sys
from pathlib import Path
from maxvera.sandbox import restrict_reads
restrict_reads([Path(p) for p in json.loads(sys.argv[1])])
assert Path(sys.argv[2]).read_text() == 'nameserver 127.0.0.53\\n'
try:
    Path(sys.argv[3]).read_text()
except PermissionError:
    print('resolver readable; neighbor denied')
else:
    raise AssertionError('resolver directory was broadly exposed')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            json.dumps([str(etc), *map(str, paths)]),
            str(resolver),
            str(secret),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "neighbor denied" in result.stdout
