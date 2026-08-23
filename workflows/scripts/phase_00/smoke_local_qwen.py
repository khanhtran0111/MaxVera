#!/usr/bin/env python3
"""Run one pinned Qwen GGUF request through a local llama.cpp CUDA server."""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "models" / "qwen25_coder_3b_q4_k_m.yaml"


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a mapping in {path}")
    return value


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _request_json(url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    with urlopen(request, timeout=60) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object from {url}")
    return value


def _wait_until_ready(url: str, process: subprocess.Popen[str], timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "server did not answer"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"llama-server exited during model load with {process.returncode}")
        try:
            health = _request_json(url)
            if health.get("status") in {"ok", "ready"}:
                return
            last_error = json.dumps(health, sort_keys=True)
        except HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except (TimeoutError, URLError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise TimeoutError(f"llama-server was not ready after {timeout_seconds}s: {last_error}")


def _gpu_snapshot() -> dict[str, Any]:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return {"available": False, "error": "nvidia-smi not found"}
    process = subprocess.run(
        [
            executable,
            "--query-gpu=name,memory.total,memory.used,driver_version",
            "--format=csv,noheader,nounits",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    return {
        "available": process.returncode == 0,
        "returncode": process.returncode,
        "rows": [line.strip() for line in process.stdout.splitlines() if line.strip()],
        "error": process.stderr.strip() or None,
    }


def _version(executable: str) -> str:
    process = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    value = (process.stdout + "\n" + process.stderr).strip()
    if process.returncode != 0:
        raise RuntimeError(f"could not identify llama-server version: {value}")
    return value


def run_smoke(
    *,
    config_path: Path,
    model_path: Path,
    output_path: Path,
    llama_server: str,
    startup_timeout_seconds: float,
) -> dict[str, Any]:
    config = _load_config(config_path)
    expected_release = str(config["llama_cpp"]["release"])
    expected_commit = str(config["llama_cpp"]["git_commit"])
    version = _version(llama_server)
    version_tokens = {expected_release, expected_release.removeprefix("b"), expected_commit[:7]}
    if not any(token in version for token in version_tokens):
        raise RuntimeError(
            "llama-server version is not pinned "
            f"{expected_release}/{expected_commit[:7]}: {version}"
        )
    if not model_path.is_file():
        raise FileNotFoundError(model_path)
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite smoke result: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = output_path.with_suffix(".server.log")
    port = _available_port()
    argv = [
        llama_server,
        "--model",
        str(model_path.resolve()),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--ctx-size",
        str(config["context_size"]),
        "--batch-size",
        str(config["batch_size"]),
        "--n-gpu-layers",
        "99",
        "--flash-attn",
        "off",
        "--seed",
        str(config["seed"]),
        "--temp",
        str(config["temperature"]),
    ]
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    started = time.monotonic()
    gpu_before = _gpu_snapshot()
    response: dict[str, Any] | None = None
    error: str | None = None
    returncode: int | None = None
    with log_path.open("x", encoding="utf-8", newline="\n") as log:
        process = subprocess.Popen(
            argv,
            cwd=PROJECT_ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            _wait_until_ready(f"http://127.0.0.1:{port}/health", process, startup_timeout_seconds)
            gpu_loaded = _gpu_snapshot()
            response = _request_json(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                {
                    "model": str(config["model_id"]),
                    "temperature": config["temperature"],
                    "seed": config["seed"],
                    "max_tokens": 64,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return concise JSON only.",
                        },
                        {
                            "role": "user",
                            "content": (
                                'Return {"runtime":"ok"} if you can read this Java snippet: '
                                "class Demo { String value(String x) { return x; } }"
                            ),
                        },
                    ],
                },
            )
            choices = response.get("choices")
            if not isinstance(choices, list) or not choices:
                raise RuntimeError("local model returned no choices")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            process.terminate()
            try:
                returncode = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                returncode = process.wait(timeout=20)
            runtime = time.monotonic() - started
            log.flush()

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    result = {
        "schema_version": 1,
        "status": "COMPLETE" if response is not None and error is None else "FAILED",
        "started_at": started_at,
        "runtime_seconds": round(runtime, 3),
        "model": {
            "model_id": config["model_id"],
            "revision": config["revision"],
            "filename": config["filename"],
            "sha256": config["sha256"],
            "quantization": config["quantization"],
        },
        "runtime": {
            "llama_cpp_version": version,
            "command": argv,
            "server_exit_code_after_terminate": returncode,
            "cuda_log_detected": "CUDA" in log_text,
            "gpu_before": gpu_before,
            "gpu_loaded": gpu_loaded if "gpu_loaded" in locals() else None,
        },
        "response": response,
        "error": error,
        "artifacts": [str(output_path.resolve()), str(log_path.resolve())],
    }
    with output_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llama-server", default="llama-server")
    parser.add_argument("--startup-timeout-seconds", type=float, default=600.0)
    args = parser.parse_args()
    executable = shutil.which(args.llama_server) or args.llama_server
    result = run_smoke(
        config_path=args.config.resolve(),
        model_path=args.model.resolve(),
        output_path=args.output.resolve(),
        llama_server=executable,
        startup_timeout_seconds=args.startup_timeout_seconds,
    )
    print(json.dumps({"status": result["status"], "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
