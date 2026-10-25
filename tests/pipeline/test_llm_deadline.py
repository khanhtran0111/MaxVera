"""An absolute case deadline bounds paid calls without changing replay identity."""

import json
import signal
import time
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest

from maxvera.llm import JournaledClient
from src.llm.providers.openrouter import OpenRouterSettings


def settings():
    return OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "deadline-secret",
        "openai/gpt-oss-20b",
        "fixture",
        64,
        0,
        1,
        1234,
        "low",
        1800,
        0,
    )


def response_body():
    return json.dumps(
        {
            "model": "openai/gpt-oss-20b",
            "provider": "fixture",
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {"cost": 0.001},
        }
    ).encode()


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self):
        return response_body()


def test_transport_timeout_is_clamped_to_remaining_case_budget(tmp_path, monkeypatch):
    observed = []

    def remote(request, timeout):
        observed.append(timeout)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", remote)
    client = JournaledClient(settings(), tmp_path, {"timeout_case_s": 1})
    assert client.complete([{"role": "user", "content": "fixture"}]) == "{}"
    assert 0 < observed[0] <= 1


def test_case_deadline_is_shared_across_distinct_requests(tmp_path, monkeypatch):
    clock, calls = [100.0], []

    def remote(client, messages, **kwargs):
        calls.append(messages)
        clock[0] += 0.6
        client._append_log({"usage": {"cost": 0.001}, "finish_reason": "stop"})
        return "{}"

    monkeypatch.setattr("maxvera.llm.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    client = JournaledClient(settings(), tmp_path, {"timeout_case_s": 1})
    assert client.complete([{"role": "user", "content": "first"}]) == "{}"
    with pytest.raises(RuntimeError, match=r"time budget|deadline"):
        client.complete([{"role": "user", "content": "second"}])
    with pytest.raises(RuntimeError, match=r"time budget|deadline"):
        client.complete([{"role": "user", "content": "third"}])
    assert len(calls) == 2
    states = [json.loads(p.read_text())["status"] for p in tmp_path.glob("requests/*/request.json")]
    assert states.count("SUCCESS") == 1


def test_response_read_is_interrupted_and_uncertain_request_is_not_repeated(tmp_path, monkeypatch):
    calls = []

    class SlowResponse(Response):
        def read(self):
            time.sleep(1)
            return response_body()

    def remote(request, timeout):
        calls.append(timeout)
        return SlowResponse()

    monkeypatch.setattr("urllib.request.urlopen", remote)
    prompt = [{"role": "user", "content": "slow response"}]
    client = JournaledClient(settings(), tmp_path, {}, deadline=time.monotonic() + 0.05)
    started = time.monotonic()
    with pytest.raises(RuntimeError, match=r"uncertain|deadline|time budget"):
        client.complete(prompt)
    assert time.monotonic() - started < 0.5
    state = json.loads(next(tmp_path.glob("requests/*/request.json")).read_text())
    assert state["status"] == "UNCERTAIN"
    with pytest.raises(RuntimeError, match="uncertain"):
        JournaledClient(settings(), tmp_path, {}).complete(prompt)
    assert len(calls) == 1


def test_transport_deadline_does_not_change_paid_cache_identity(tmp_path):
    prompt = [{"role": "user", "content": "same paid request"}]
    a = JournaledClient(settings(), tmp_path / "a", {}, deadline=time.monotonic() + 5)
    b = JournaledClient(settings(), tmp_path / "b", {}, deadline=time.monotonic() + 30)
    assert a.key(prompt, True, 64) == b.key(prompt, True, 64)


def test_expired_deadline_never_creates_pending_charge(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("expired work must not contact the provider")

    monkeypatch.setattr("urllib.request.urlopen", unexpected)
    client = JournaledClient(settings(), tmp_path, {}, deadline=time.monotonic() - 1)
    with pytest.raises(RuntimeError, match=r"time budget|deadline"):
        client.complete([{"role": "user", "content": "expired"}])
    assert not list(Path(tmp_path).glob("requests/*/request.json"))


def test_rate_limit_backoff_respects_time_spent_on_prior_attempt(tmp_path, monkeypatch):
    from src.llm.providers.openrouter import OpenRouterError

    clock, calls, delays = [100.0], [], []

    def remote(client, messages, **kwargs):
        calls.append(messages)
        clock[0] += 0.6
        raise OpenRouterError("explicit rejection", http_status=429, retryable=True)

    monkeypatch.setattr("maxvera.llm.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("maxvera.llm.time.sleep", delays.append)
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    configured = replace(settings(), max_retries=1, rate_limit_backoff_seconds=0.6)
    client = JournaledClient(configured, tmp_path, {"timeout_case_s": 1})
    with pytest.raises(RuntimeError, match="time budget"):
        client.complete([{"role": "user", "content": "rejected"}])
    assert len(calls) == 1 and delays == []
    state = json.loads(next(tmp_path.glob("requests/*/request.json")).read_text())
    assert state["status"] == "RATE_LIMITED"


def test_transport_restores_later_process_alarm(tmp_path, monkeypatch):
    def remote(request, timeout):
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", remote)
    original_handler = signal.getsignal(signal.SIGALRM)
    original_timer = signal.getitimer(signal.ITIMER_REAL)
    try:
        signal.setitimer(signal.ITIMER_REAL, 2)
        client = JournaledClient(settings(), tmp_path, {}, deadline=time.monotonic() + 1)
        assert client.complete([{"role": "user", "content": "fixture"}]) == "{}"
        assert signal.getsignal(signal.SIGALRM) == original_handler
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 1 < remaining <= 2 and interval == 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original_handler)
        if original_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, *original_timer)


def test_error_response_body_cannot_block_past_deadline(tmp_path, monkeypatch):
    calls = []

    class SlowError:
        def read(self):
            time.sleep(1)
            return b"{}"

        def close(self):
            pass

    def remote(request, timeout):
        calls.append(timeout)
        raise urllib.error.HTTPError("https://fixture", 429, "rejected", {}, SlowError())

    monkeypatch.setattr("urllib.request.urlopen", remote)
    client = JournaledClient(settings(), tmp_path, {}, deadline=time.monotonic() + 0.05)
    started = time.monotonic()
    with pytest.raises(RuntimeError):
        client.complete([{"role": "user", "content": "rejected"}])
    assert time.monotonic() - started < 0.5 and len(calls) == 1
    attempt = json.loads(next(tmp_path.glob("requests/*/attempt-1.json")).read_text())
    assert attempt["status"] == "RATE_LIMITED" and attempt["cost_usd"] == 0
