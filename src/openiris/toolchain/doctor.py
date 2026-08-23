"""Audit the host against the Phase 0 toolchain contract."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from openiris.config import load_yaml


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    expected: str | None
    observed: str | None
    detail: str | None = None


def _run(command: list[str], timeout: int = 15) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
    )
    return completed.returncode, output


def _command_check(
    name: str,
    args: list[str],
    expected: str | None = None,
    *,
    executable_name: str | None = None,
) -> Check:
    executable = shutil.which(executable_name or name)
    if executable is None:
        return Check(name, "MISSING", expected, None, "not found on PATH")
    code, output = _run([executable, *args])
    first_line = output.splitlines()[0] if output else ""
    status = "OK" if code == 0 else "ERROR"
    if expected and expected not in output:
        status = "MISMATCH"
    return Check(name, status, expected, first_line or executable)


def _explicit_executable_check(name: str, path: Path, args: list[str], expected: str) -> Check:
    if not path.is_file():
        return Check(name, "MISSING", expected, None, str(path))
    code, output = _run([str(path), *args], timeout=30)
    first_line = output.splitlines()[0] if output else ""
    status = "OK" if code == 0 and expected in output else "MISMATCH"
    return Check(name, status, expected, first_line or str(path))


def _docker_command_check(name: str, image: str, args: list[str], expected: str) -> Check:
    if shutil.which("docker") is None:
        return Check(name, "MISSING", expected, None, "docker not found on PATH")
    code, output = _run(["docker", "run", "--rm", image, *args], timeout=60)
    first_line = output.splitlines()[0] if output else ""
    status = "OK" if code == 0 and expected in output else "MISMATCH"
    return Check(name, status, expected, first_line or None, image)


def _docker_gpu_check(name: str, image: str) -> Check:
    if shutil.which("docker") is None:
        return Check(name, "MISSING", "CUDA available in container", None, "docker not found")
    code, output = _run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--gpus",
            "all",
            image,
            "python",
            "-c",
            (
                "import torch; print('cuda=' + str(torch.cuda.is_available()).lower()); "
                "raise SystemExit(0 if torch.cuda.is_available() else 1)"
            ),
        ],
        timeout=60,
    )
    first_line = output.splitlines()[0] if output else ""
    status = "OK" if code == 0 and "cuda=true" in output else "UNAVAILABLE"
    return Check(name, status, "cuda=true", first_line or None, image)


def _git_checkout_check(name: str, path: Path, expected: str) -> Check:
    if not (path / ".git").exists():
        return Check(name, "MISSING", expected, None, str(path))
    code, output = _run(["git", "-C", str(path), "rev-parse", "HEAD"])
    observed = output.splitlines()[0] if output else None
    status = "OK" if code == 0 and observed == expected else "MISMATCH"
    return Check(name, status, expected, observed, str(path))


def audit(config_path: str | Path, workspace: str | Path | None = None) -> dict[str, Any]:
    workspace_path = Path(workspace or Path.cwd()).resolve()
    config = load_yaml(config_path)
    checks: list[Check] = []

    checks.append(_command_check("git", ["--version"]))
    checks.append(_command_check("python", ["--version"]))
    checks.append(_command_check("uv", ["--version"]))
    checks.append(_command_check("javac", ["-version"]))
    checks.append(_command_check("maven", ["--version"], executable_name="mvn"))
    checks.append(_command_check("gradle", ["--version"]))
    checks.append(_command_check("docker-client", ["--version"], executable_name="docker"))

    docker_code, docker_output = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    checks.append(
        Check(
            "docker-daemon",
            "OK" if docker_code == 0 and docker_output.strip() else "UNAVAILABLE",
            "running (optional)",
            docker_output.splitlines()[0] if docker_output else None,
        )
    )

    docker_config = config.get("docker", {})
    for check_name, config_key in (
        ("phase0-container-image", "phase0_image"),
        ("codeql-container-image", "codeql_image"),
        ("iris-container-image", "iris_image"),
    ):
        image_name = str(docker_config.get(config_key, ""))
        image_code, image_output = _run(
            ["docker", "image", "inspect", image_name, "--format", "{{.Id}}"]
        )
        checks.append(
            Check(
                check_name,
                "OK" if image_code == 0 and image_output.strip() else "MISSING",
                image_name,
                image_output.splitlines()[0] if image_output else None,
            )
        )

    codeql_config = config["codeql"]
    codeql_path = workspace_path / Path(str(codeql_config["executable"]))
    checks.append(
        _explicit_executable_check(
            "codeql-host",
            codeql_path,
            ["version", "--format=terse"],
            str(codeql_config["cli_version_observed"]),
        )
    )
    codeql_image = str(docker_config.get("codeql_image", ""))
    checks.append(
        _docker_command_check(
            "codeql-container-cli",
            codeql_image,
            [str(codeql_config["linux_executable"]), "version", "--format=terse"],
            str(codeql_config["cli_version_observed"]),
        )
    )
    checks.append(
        _docker_gpu_check(
            "iris-container-gpu-runtime",
            str(docker_config.get("iris_image", "")),
        )
    )

    iris_config = config["iris"]
    checks.append(
        _git_checkout_check(
            "iris-v1-checkout",
            workspace_path / Path(str(iris_config["source_path"])),
            str(iris_config["git_commit"]),
        )
    )
    dataset_config = load_yaml(workspace_path / "configs/datasets/legacy_paper.yaml")
    checks.append(
        _git_checkout_check(
            "legacy-dataset-checkout",
            workspace_path / Path(str(dataset_config["source_path"])),
            str(dataset_config["git_commit"]),
        )
    )

    statuses = {check.name: check.status for check in checks}
    common_required = {
        "git",
        "python",
        "uv",
        "iris-v1-checkout",
        "legacy-dataset-checkout",
    }
    if config.get("execution_mode") == "docker":
        smoke_required = common_required | {
            "docker-client",
            "docker-daemon",
            "phase0-container-image",
            "codeql-container-image",
            "codeql-container-cli",
            "iris-container-image",
            "iris-container-gpu-runtime",
        }
    else:
        smoke_required = common_required | {"codeql-host"}
    full_required = smoke_required | {"javac", "maven", "gradle"}
    ready_smoke = all(statuses.get(name) == "OK" for name in smoke_required)
    ready_full = all(statuses.get(name) == "OK" for name in full_required)
    return {
        "schema_version": 1,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "cwd": str(workspace_path),
        },
        "environment_flags": {
            "openai_api_key_present": bool(os.environ.get("OPENAI_API_KEY")),
            "google_api_key_present": bool(os.environ.get("GOOGLE_API_KEY")),
            "nvidia_smi_present": shutil.which("nvidia-smi") is not None,
        },
        "checks": [asdict(check) for check in checks],
        "execution_mode": config.get("execution_mode", "native"),
        "ready_smoke": ready_smoke,
        "ready_full_matrix": ready_full,
        "ready": ready_smoke,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/toolchain/phase0.yaml")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    result = audit(args.config, args.workspace)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 1 if args.strict and not result["ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
