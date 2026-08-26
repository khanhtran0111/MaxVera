"""Collect deterministic checksums and secret-safe run provenance manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeAlias, cast
from urllib.parse import urlsplit, urlunsplit

import yaml

JsonValue: TypeAlias = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None

MANIFEST_SCHEMA_VERSION = 1
REDACTED = "***REDACTED***"
_SENSITIVE_KEY = re.compile(
    r"(^|[_-])(access[_-]?key|api[_-]?key|authorization|client[_-]?secret|cookie|"
    r"credential|password|passwd|private[_-]?key|secret|token)($|[_-])",
    re.IGNORECASE,
)


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate SHA256 without loading the complete artifact into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def redact_secrets(value: Any, key: str | None = None) -> JsonValue:
    """Recursively redact values whose field names identify credentials."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_secrets(item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_secrets(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def sensitive_environment_values(environment: Mapping[str, str] | None = None) -> set[str]:
    """Return non-trivial secret-like values only for leak detection."""
    source = os.environ if environment is None else environment
    return {
        value
        for name, value in source.items()
        if _SENSITIVE_KEY.search(name) and len(value) >= 6
    }


def assert_secret_free(value: JsonValue, environment: Mapping[str, str] | None = None) -> None:
    """Reject serialized reports containing known secret environment values."""
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False)
    leaked_names = [
        name
        for name, candidate in (os.environ if environment is None else environment).items()
        if _SENSITIVE_KEY.search(name) and len(candidate) >= 6 and candidate in serialized
    ]
    if leaked_names:
        names = ", ".join(sorted(leaked_names))
        raise ValueError(f"report contains values from sensitive variables: {names}")


def _run_version(command: list[str], cwd: Path | None = None) -> str | None:
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    return output.splitlines()[0].strip() if output else None


def _git_value(repo_root: Path, arguments: list[str]) -> str | None:
    if shutil.which("git") is None:
        return None
    return _run_version(["git", *arguments], cwd=repo_root)


def sanitize_git_remote(remote: str | None) -> str:
    """Remove credentials and machine-local paths from a Git remote."""
    if not remote:
        return "UNAVAILABLE"
    if "://" in remote:
        parsed = urlsplit(remote)
        hostname = parsed.hostname
        if not hostname:
            return "LOCAL_OR_REDACTED"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path, "", ""))
    if re.match(r"^[^/@:]+@[^:]+:", remote):
        return re.sub(r"^[^/@:]+@", "", remote)
    if re.match(r"^[A-Za-z]:[\\/]", remote) or remote.startswith(("/", "./", "../")):
        return "LOCAL_OR_REDACTED"
    return remote


def collect_git(repo_root: Path) -> dict[str, JsonValue]:
    """Collect source revision and dirty state without mutating the repository."""
    status = _git_value(repo_root, ["status", "--porcelain=v1", "--untracked-files=normal"])
    return {
        "commit": _git_value(repo_root, ["rev-parse", "HEAD"]) or "UNAVAILABLE",
        "branch": _git_value(repo_root, ["branch", "--show-current"]) or "DETACHED_OR_UNAVAILABLE",
        "dirty": bool(status),
        "origin": sanitize_git_remote(_git_value(repo_root, ["remote", "get-url", "origin"])),
    }


def total_ram_bytes() -> int | None:
    """Return physical memory using platform-native read-only interfaces."""
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    if sys.platform == "darwin":
        value = _run_version(["sysctl", "-n", "hw.memsize"])
        return int(value) if value and value.isdigit() else None
    if os.name == "nt":
        value = _run_version(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ]
        )
        return int(value) if value and value.isdigit() else None
    return None


def collect_gpu() -> list[dict[str, JsonValue]]:
    """Collect non-sensitive NVIDIA model/memory/driver facts when available."""
    if shutil.which("nvidia-smi") is None:
        return []
    try:
        process = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    devices: list[dict[str, JsonValue]] = []
    for line in process.stdout.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) == 3:
            memory = int(fields[1]) if fields[1].isdigit() else None
            devices.append({"name": fields[0], "memory_mib": memory, "driver": fields[2]})
    return devices


def collect_environment(repo_root: Path) -> dict[str, JsonValue]:
    """Collect reproducibility facts; environment variables are never included."""
    disk = shutil.disk_usage(repo_root)
    cpu_name = platform.processor().strip() or platform.machine()
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cpu": cpu_name,
        "logical_cpu_count": os.cpu_count(),
        "ram_bytes": total_ram_bytes(),
        "disk": {"total_bytes": disk.total, "free_bytes": disk.free},
        "gpu": cast(list[JsonValue], collect_gpu()),
        "tools": {
            "git": _run_version(["git", "--version"]),
            "uv": _run_version(["uv", "--version"]),
            "java": _run_version(["java", "-version"]),
            "maven": _run_version(["mvn", "--version"]),
            "gradle": _run_version(["gradle", "--version"]),
            "codeql": _run_version(["codeql", "version", "--format=terse"]),
            "llama_cpp": _run_version(["llama-server", "--version"]),
        },
    }


def load_upstream_pins(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "configs" / "upstreams.yaml"
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"invalid upstream configuration: {path}")
    return cast(dict[str, Any], loaded)


def collect_manifest(
    repo_root: Path,
    *,
    mode: str,
    run_id: str | None = None,
    dataset_sha256: str = "NOT_BOUND_PHASE_2",
    parent_run_id: str | None = None,
    seed: int = 1234,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, JsonValue]:
    """Build a run manifest with all Phase 1 provenance fields."""
    pins = load_upstream_pins(repo_root)
    qwen = cast(dict[str, Any], pins["qwen"])
    codeql = cast(dict[str, Any], pins["codeql_main"])
    source_path = Path(__file__).resolve()
    manifest: dict[str, JsonValue] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "project": "MaxVera",
        "collected_at": utc_now(),
        "run": {
            "id": run_id,
            "mode": mode,
            "seed": seed,
            "parent_run_id": parent_run_id,
        },
        "git": collect_git(repo_root),
        "artifacts": {
            "dataset_sha256": dataset_sha256,
            "model_id": str(qwen["repository"]),
            "model_revision": str(qwen["revision"]),
            "model_file_sha256": str(qwen["sha256"]),
        },
        "toolchain": {
            "codeql_version": str(codeql["cli_version"]),
            "codeql_query_pack": str(codeql["java_queries_pack"]),
            "llama_cpp_commit": str(cast(dict[str, Any], pins["llama_cpp"])["commit"]),
            "python_version": str(cast(dict[str, Any], pins["python"])["version"]),
        },
        "environment": collect_environment(repo_root),
        "collector": {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "source_sha256": sha256_file(source_path),
        },
    }
    if extra:
        manifest["extra"] = redact_secrets(extra)
    redacted = cast(dict[str, JsonValue], redact_secrets(manifest))
    assert_secret_free(redacted)
    return redacted


def atomic_write_json(path: Path, value: JsonValue) -> None:
    """Write canonical JSON by atomic rename in the destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def write_checksums(paths: Sequence[Path], output: Path, root: Path) -> None:
    """Write stable GNU-style SHA256 records for files below root."""
    resolved_root = root.resolve()
    lines: list[str] = []
    for path in sorted((item.resolve() for item in paths), key=lambda item: item.as_posix()):
        relative = path.relative_to(resolved_root).as_posix()
        lines.append(f"{sha256_file(path)}  {relative}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", required=True, choices=("development", "smoke", "pilot", "full"))
    parser.add_argument("--run-id")
    parser.add_argument("--parent-run-id")
    parser.add_argument("--dataset-sha256", default="NOT_BOUND_PHASE_2")
    parser.add_argument("--seed", type=int, default=1234)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.repo_root.resolve()
    manifest = collect_manifest(
        root,
        mode=args.mode,
        run_id=args.run_id,
        dataset_sha256=args.dataset_sha256,
        parent_run_id=args.parent_run_id,
        seed=args.seed,
    )
    atomic_write_json(args.output.resolve(), manifest)
    print(f"Wrote secret-safe manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
