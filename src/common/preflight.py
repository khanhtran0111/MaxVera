"""Secret-safe Phase 1 and full-analysis environment preflight."""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast

from src.common.envfile import REQUIRED_ENV_KEYS, effective_env, initialize_env_file
from src.common.provenance import (
    JsonValue,
    assert_secret_free,
    atomic_write_json,
    collect_environment,
    load_upstream_pins,
    sha256_file,
    utc_now,
)

Status = Literal["PASS", "WARN", "FAIL"]
Profile = Literal["phase1", "phase4", "full", "local"]


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    required: bool
    detail: str
    version: str | None = None


def _execute(
    command: list[str],
    timeout: int = 15,
    environment: dict[str, str] | None = None,
) -> tuple[int, str]:
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    return process.returncode, output


def _executable(
    names: tuple[str, ...],
    configured: str | None = None,
    *,
    allow_path: bool = True,
) -> str | None:
    candidates: list[Path] = []
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.is_file():
            candidates.append(configured_path)
        else:
            for name in names:
                candidates.extend((configured_path / "bin" / name, configured_path / name))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    if allow_path:
        for name in names:
            found = shutil.which(name)
            if found:
                return found
    return None


def _tool_check(
    name: str,
    names: tuple[str, ...],
    version_args: list[str],
    *,
    required: bool,
    configured: str | None = None,
    expected_pattern: str | None = None,
    require_configured: bool = False,
    environment: dict[str, str] | None = None,
) -> Check:
    if require_configured and not configured:
        configured_status: Status = "FAIL" if required else "WARN"
        return Check(name, configured_status, required, "not configured")
    executable = _executable(names, configured, allow_path=not require_configured)
    if executable is None:
        missing_status: Status = "FAIL" if required else "WARN"
        return Check(name, missing_status, required, "not found or not configured")
    return_code, output = _execute([executable, *version_args], environment=environment)
    first_line = output.splitlines()[0].strip() if output else None
    if return_code != 0:
        command_status: Status = "FAIL" if required else "WARN"
        return Check(name, command_status, required, "version command failed")
    if expected_pattern and not re.search(expected_pattern, output, re.IGNORECASE):
        version_status: Status = "FAIL" if required else "WARN"
        return Check(name, version_status, required, "unexpected version", first_line)
    return Check(name, "PASS", required, "available", first_line)


def _resource_checks(repo_root: Path, *, required: bool) -> list[Check]:
    environment = collect_environment(repo_root)
    ram_value = environment.get("ram_bytes")
    ram_bytes = ram_value if isinstance(ram_value, int) else None
    disk_value = environment.get("disk")
    disk = disk_value if isinstance(disk_value, dict) else {}
    free_value = disk.get("free_bytes")
    free_bytes = free_value if isinstance(free_value, int) else None
    minimum_ram = 24 * 1024**3
    minimum_disk = 25 * 1024**3
    checks: list[Check] = []
    if ram_bytes is None:
        checks.append(Check("ram", "FAIL" if required else "WARN", required, "could not measure"))
    else:
        checks.append(
            Check(
                "ram",
                "PASS" if ram_bytes >= minimum_ram else ("FAIL" if required else "WARN"),
                required,
                f"{ram_bytes / 1024**3:.1f} GiB total; minimum 24 GiB",
            )
        )
    if free_bytes is None:
        checks.append(Check("disk", "FAIL" if required else "WARN", required, "could not measure"))
    else:
        checks.append(
            Check(
                "disk",
                "PASS" if free_bytes >= minimum_disk else ("FAIL" if required else "WARN"),
                required,
                f"{free_bytes / 1024**3:.1f} GiB free; minimum 25 GiB",
            )
        )
    return checks


def _python_check(required: bool = True) -> Check:
    version = platform.python_version()
    compatible = sys.version_info[:3] == (3, 10, 16)
    status: Status = "PASS" if compatible else ("FAIL" if required else "WARN")
    detail = "canonical Python 3.10.16" if compatible else "requires pinned Python 3.10.16"
    return Check("python", status, required, detail, version)


def _file_check(
    name: str,
    configured: str | None,
    *,
    required: bool,
    expected_sha256: str | None = None,
) -> Check:
    if not configured:
        return Check(name, "FAIL" if required else "WARN", required, "not configured")
    path = Path(configured).expanduser()
    if not path.is_file():
        return Check(name, "FAIL" if required else "WARN", required, "configured file is missing")
    if expected_sha256:
        actual = sha256_file(path)
        if actual != expected_sha256:
            return Check(name, "FAIL" if required else "WARN", required, "SHA256 mismatch")
    return Check(name, "PASS", required, "file exists and checksum matches")


def _openrouter_checks(machine: dict[str, str], *, required: bool) -> list[Check]:
    api_key = machine.get("OPENROUTER_API_KEY", "")
    base_url = machine.get("MAXVERA_OPENROUTER_BASE_URL", "")
    provider = machine.get("MAXVERA_OPENROUTER_PROVIDER", "")
    missing_status: Status = "FAIL" if required else "WARN"
    return [
        Check(
            "openrouter_api_key",
            "PASS" if api_key else missing_status,
            required,
            "configured" if api_key else "not configured",
        ),
        Check(
            "openrouter_base_url",
            "PASS" if base_url == "https://openrouter.ai/api/v1" else missing_status,
            required,
            "canonical HTTPS endpoint"
            if base_url == "https://openrouter.ai/api/v1"
            else "must be https://openrouter.ai/api/v1",
        ),
        Check(
            "openrouter_provider",
            "PASS" if provider else missing_status,
            required,
            "provider route pinned" if provider else "not configured",
        ),
    ]


def run_preflight(repo_root: Path, profile: Profile, env_path: Path) -> dict[str, JsonValue]:
    """Run checks and return a report that never includes .env values or paths."""
    initialize_env_file(env_path)
    machine = effective_env(env_path)
    full = profile == "full"
    phase4 = profile == "phase4"
    local = profile == "local"
    checks: list[Check] = [
        _python_check(),
        _tool_check("git", ("git", "git.exe"), ["--version"], required=True),
        _tool_check("bash", ("bash", "bash.exe"), ["--version"], required=True),
        _tool_check(
            "uv",
            ("uv", "uv.exe"),
            ["--version"],
            required=True,
            expected_pattern=r"uv 0\.11\.32",
        ),
    ]
    checks.extend(_resource_checks(repo_root, required=not local))

    analysis_required = full or phase4
    build_tool_environment: dict[str, str] | None = None
    java_17_home = machine.get("MAXVERA_JAVA_17_HOME")
    if java_17_home:
        build_tool_environment = dict(os.environ)
        build_tool_environment["JAVA_HOME"] = java_17_home
        build_tool_environment["PATH"] = (
            f"{Path(java_17_home) / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
        )
    checks.extend(
        [
            _tool_check(
                "java_7",
                ("java", "java.exe"),
                ["-version"],
                required=analysis_required,
                configured=machine.get("MAXVERA_JAVA_7_HOME"),
                expected_pattern=r'version "1\.7',
                require_configured=True,
            ),
            _tool_check(
                "java_8",
                ("java", "java.exe"),
                ["-version"],
                required=analysis_required,
                configured=machine.get("MAXVERA_JAVA_8_HOME"),
                expected_pattern=r'version "1\.8',
                require_configured=True,
            ),
            _tool_check(
                "java_17",
                ("java", "java.exe"),
                ["-version"],
                required=analysis_required,
                configured=machine.get("MAXVERA_JAVA_17_HOME"),
                expected_pattern=r'version "17',
                require_configured=True,
            ),
            _tool_check(
                "maven",
                ("mvn", "mvn.cmd", "mvn.exe"),
                ["--version"],
                required=analysis_required,
                configured=machine.get("MAXVERA_MAVEN_HOME"),
                require_configured=True,
                environment=build_tool_environment,
            ),
            _tool_check(
                "gradle",
                ("gradle", "gradle.bat", "gradle.exe"),
                ["--version"],
                required=analysis_required,
                configured=machine.get("MAXVERA_GRADLE_HOME"),
                require_configured=True,
                environment=build_tool_environment,
            ),
            _tool_check(
                "codeql_main",
                ("codeql", "codeql.exe"),
                ["version", "--format=terse"],
                required=analysis_required,
                configured=machine.get("MAXVERA_CODEQL_HOME"),
                expected_pattern=r"^2\.26\.2",
                require_configured=True,
            ),
            _tool_check(
                "codeql_iris_patched",
                ("codeql", "codeql.exe"),
                ["version", "--format=terse"],
                required=analysis_required,
                configured=machine.get("MAXVERA_IRIS_CODEQL_HOME"),
                require_configured=True,
            ),
        ]
    )
    if not phase4:
        checks.append(
            _tool_check(
                "llama_cpp",
                ("llama-server", "llama-server.exe"),
                ["--version"],
                required=full,
                configured=machine.get("MAXVERA_LLAMA_SERVER_BIN"),
                require_configured=True,
            )
        )
        pins = load_upstream_pins(repo_root)
        qwen = cast(dict[str, Any], pins["qwen"])
        checks.append(
            _file_check(
                "qwen_model",
                machine.get("MAXVERA_MODEL_PATH"),
                required=full,
                expected_sha256=str(qwen["sha256"]) if full else None,
            )
        )
    checks.extend(_openrouter_checks(machine, required=phase4))
    if not phase4:
        gpu = collect_environment(repo_root).get("gpu")
        checks.append(
            Check(
                "nvidia_gpu",
                "PASS" if isinstance(gpu, list) and gpu else "WARN",
                False,
                (
                    "available for optional offload"
                    if isinstance(gpu, list) and gpu
                    else "not available; CPU is canonical"
                ),
            )
        )

    missing_env_names = sorted(
        key for key in REQUIRED_ENV_KEYS if not machine.get(key)
    )
    failures = sum(check.status == "FAIL" for check in checks)
    warnings = sum(check.status == "WARN" for check in checks)
    report: dict[str, JsonValue] = {
        "schema_version": 1,
        "project": "MaxVera",
        "profile": profile,
        "collected_at": utc_now(),
        "status": "PASS" if failures == 0 else "FAIL",
        "summary": {"failures": failures, "warnings": warnings, "checks": len(checks)},
        "missing_environment_variable_names": cast(list[JsonValue], missing_env_names),
        "checks": [cast(dict[str, JsonValue], asdict(check)) for check in checks],
        "environment": collect_environment(repo_root),
        "privacy": {
            "environment_values_recorded": False,
            "configured_paths_recorded": False,
            "secret_scan_passed": True,
        },
    }
    assert_secret_free(report, {**os.environ, **machine})
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=("phase1", "phase4", "full", "local"), default="phase1"
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    root = args.repo_root.resolve()
    env_file = args.env_file.resolve() if args.env_file else root / ".env"
    output = (
        args.output.resolve()
        if args.output
        else root / ".cache" / "preflight" / "environment.json"
    )
    report = run_preflight(root, cast(Profile, args.profile), env_file)
    atomic_write_json(output, report)
    checks = cast(list[dict[str, JsonValue]], report["checks"])
    for check in checks:
        print(f"[{check['status']}] {check['name']}: {check['detail']}")
    missing = cast(list[str], report["missing_environment_variable_names"])
    if missing:
        print("Unconfigured variable names: " + ", ".join(missing))
    summary = cast(dict[str, JsonValue], report["summary"])
    print(
        f"Preflight {report['status']}: {summary['checks']} checks, "
        f"{summary['failures']} failures, {summary['warnings']} warnings. Report: {output}"
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
