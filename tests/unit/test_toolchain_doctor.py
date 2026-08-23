from __future__ import annotations

from typing import Any

from openiris.toolchain import doctor


def test_docker_gpu_check_requests_gpu_and_requires_cuda(monkeypatch: Any) -> None:
    observed: list[str] = []

    monkeypatch.setattr(doctor.shutil, "which", lambda _: "docker")

    def fake_run(command: list[str], timeout: int = 15) -> tuple[int, str]:
        del timeout
        observed.extend(command)
        return 0, "cuda=true"

    monkeypatch.setattr(doctor, "_run", fake_run)

    check = doctor._docker_gpu_check("gpu", "phase0-iris")

    assert check.status == "OK"
    assert check.observed == "cuda=true"
    assert observed[:7] == ["docker", "run", "--rm", "--pull=never", "--gpus", "all", "phase0-iris"]


def test_docker_gpu_check_rejects_cpu_only_container(monkeypatch: Any) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda _: "docker")
    monkeypatch.setattr(doctor, "_run", lambda *args, **kwargs: (1, "cuda=false"))

    check = doctor._docker_gpu_check("gpu", "phase0-iris")

    assert check.status == "UNAVAILABLE"
    assert check.observed == "cuda=false"
