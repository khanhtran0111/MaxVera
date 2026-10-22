from __future__ import annotations

import json
import urllib.error
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings


def _settings() -> OpenRouterSettings:
    return OpenRouterSettings(
        base_url="https://openrouter.ai/api/v1",
        api_key="unit-test-secret",
        model="openai/gpt-oss-20b",
        provider="akashml",
        max_tokens=2048,
        temperature=0.0,
        top_p=1.0,
        seed=1234,
        reasoning_effort="low",
        timeout_seconds=10,
        max_retries=0,
    )


@pytest.mark.parametrize("interval", [15, 90])
def test_request_pacing_is_shared_across_clients_and_retries(
    monkeypatch: pytest.MonkeyPatch,
    interval: int,
) -> None:
    clock = [100.0]
    sleeps = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("src.llm.providers.openrouter.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("src.llm.providers.openrouter.time.sleep", sleep)
    monkeypatch.setattr(OpenRouterClient, "_last_request_started", None)
    first = OpenRouterClient(_settings(), request_interval_seconds=interval)
    first._pace_request()
    first._pace_request()
    second = OpenRouterClient(_settings(), request_interval_seconds=interval)
    second._pace_request()
    assert sleeps == [interval, interval]
    assert first._payload([], expect_json=True) == second._payload([], expect_json=True)


def test_payload_pins_model_provider_privacy_and_no_fallback() -> None:
    client = OpenRouterClient(_settings())
    payload = client._payload([{"role": "user", "content": "return JSON"}], expect_json=True)
    assert payload["model"] == "openai/gpt-oss-20b"
    assert payload["provider"] == {
        "only": ["akashml"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "zdr": True,
        "data_collection": "deny",
    }
    assert payload["reasoning"] == {"effort": "low", "exclude": True}
    assert payload["response_format"] == {"type": "json_object"}


def test_90_second_pacing_also_applies_to_http_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    starts: list[float] = []

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    def failed_request(*_args: object, **_kwargs: object) -> None:
        starts.append(clock[0])
        raise urllib.error.HTTPError("https://example.invalid", 429, "provider error", {}, None)

    monkeypatch.setattr("src.llm.providers.openrouter.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("src.llm.providers.openrouter.time.sleep", sleep)
    monkeypatch.setattr("urllib.request.urlopen", failed_request)
    monkeypatch.setattr(OpenRouterClient, "_last_request_started", None)
    from src.llm.providers.openrouter import OpenRouterError

    with pytest.raises(OpenRouterError):
        OpenRouterClient(replace(_settings(), max_retries=2), request_interval_seconds=90).complete(
            [{"role": "user", "content": "fixture"}]
        )
    assert starts == [100, 190, 280]


def test_payload_uses_strict_structured_outputs_when_schema_is_supplied() -> None:
    schema = {
        "type": "object",
        "properties": {"hypotheses": {"type": "array"}},
        "required": ["hypotheses"],
        "additionalProperties": False,
    }
    payload = OpenRouterClient(_settings())._payload(
        [{"role": "user", "content": "return JSON"}],
        expect_json=True,
        response_schema=schema,
    )
    assert payload["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "phase5_hypotheses",
            "strict": True,
            "schema": schema,
        },
    }


def test_completion_logs_provenance_without_key_or_prompt(monkeypatch: Any, tmp_path: Path) -> None:
    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "id": "gen-test",
                    "model": "openai/gpt-oss-20b",
                    "provider": "AkashML",
                    "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 1, "cost": 0.0},
                }
            ).encode()

    def fake_urlopen(_request: object, timeout: int) -> Response:
        assert timeout == 10
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    call_log = tmp_path / "llm-calls.jsonl"
    client = OpenRouterClient(_settings(), call_log)
    assert client.complete([{"role": "user", "content": "private-prompt-marker"}]) == "OK"
    logged = call_log.read_text(encoding="utf-8")
    assert "unit-test-secret" not in logged
    assert "private-prompt-marker" not in logged
    record = json.loads(logged)
    assert record["requested_model"] == "openai/gpt-oss-20b"
    assert record["provider_route"] == "akashml"
    assert record["provider"] == "AkashML"
    assert record["request_id"] == "gen-test"


def test_settings_reject_provider_route_drift(tmp_path: Path) -> None:
    config = tmp_path / "model.yaml"
    config.write_text(
        "\n".join(
            (
                "model_id: openai/gpt-oss-20b",
                "provider_route: akashml",
                "max_output_tokens: 2048",
                "temperature: 0.0",
                "top_p: 1.0",
                "seed: 1234",
                "reasoning_effort: low",
                "timeout_seconds: 10",
                "max_retries: 0",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "\n".join(
            (
                "OPENROUTER_API_KEY=unit-test-secret",
                "MAXVERA_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1",
                "MAXVERA_OPENROUTER_PROVIDER=groq",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must match the pinned route akashml"):
        OpenRouterSettings.load(tmp_path, config)


def test_rate_limit_retry_uses_retry_after_or_bounded_backoff() -> None:
    with_header = urllib.error.HTTPError(
        "https://example.invalid",
        429,
        "rate limited",
        {"Retry-After": "17"},
        None,
    )
    without_header = urllib.error.HTTPError(
        "https://example.invalid", 429, "rate limited", {}, None
    )
    assert OpenRouterClient._retry_delay(1, with_header) == 17.0
    assert OpenRouterClient._retry_delay(1, without_header) == 5.0
    assert OpenRouterClient._retry_delay(5, without_header) == 60.0


def test_retry_after_is_not_shortened_to_sixty_seconds() -> None:
    error = urllib.error.HTTPError(
        "https://example.invalid", 429, "rate limited", {"Retry-After": "900"}, None
    )
    assert OpenRouterClient._retry_delay(1, error) == 900


@pytest.mark.parametrize("status,retryable", [(429, True), (503, True), (401, False)])
def test_exhausted_http_error_retains_retry_classification(
    monkeypatch: Any, status: int, retryable: bool
) -> None:
    from src.llm.providers.openrouter import OpenRouterError

    def failed_request(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError("https://example.invalid", status, "provider error", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", failed_request)
    with pytest.raises(OpenRouterError) as captured:
        OpenRouterClient(_settings()).complete([{"role": "user", "content": "fixture"}])
    assert captured.value.retryable is retryable
    assert captured.value.http_status == status
    assert "unit-test-secret" not in str(captured.value)


@pytest.mark.parametrize("failure", ["broken_json", "wrong_model", "wrong_provider"])
def test_unreadable_response_and_route_drift_are_not_automatically_retried(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    from src.llm.providers.openrouter import OpenRouterError

    valid = {
        "model": "openai/gpt-oss-20b",
        "provider": "AkashML",
        "choices": [{"message": {"content": "OK"}}],
    }
    first = {**valid}
    if failure == "wrong_model":
        first["model"] = "unexpected-model"
    elif failure == "wrong_provider":
        first["provider"] = "unexpected-provider"
    bodies = [
        b"<html>temporary gateway response</html>"
        if failure == "broken_json"
        else json.dumps(first).encode(),
        json.dumps(valid).encode(),
    ]
    starts: list[float] = []
    clock = [100.0]

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self) -> bytes:
            return bodies.pop(0)

    def urlopen(*_args: Any, **_kwargs: Any) -> Response:
        starts.append(clock[0])
        return Response()

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr("src.llm.providers.openrouter.time.sleep", sleep)
    monkeypatch.setattr("src.llm.providers.openrouter.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(OpenRouterClient, "_last_request_started", None)
    client = OpenRouterClient(
        replace(_settings(), max_retries=2), tmp_path / "calls.jsonl", request_interval_seconds=90
    )
    with pytest.raises(OpenRouterError) as captured:
        client.complete([])
    assert not captured.value.retryable
    assert starts == [100]
    logs = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
    assert logs[0]["http_status"] == 200
    assert logs[0]["status"] == "INVALID_RESPONSE"


def test_unparseable_transport_outcome_is_not_automatically_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.llm.providers.openrouter import OpenRouterError

    def invalid_envelope(*_args: Any, **_kwargs: Any) -> None:
        raise json.JSONDecodeError("invalid gateway response", "", 0)

    monkeypatch.setattr("urllib.request.urlopen", invalid_envelope)
    with pytest.raises(OpenRouterError) as captured:
        OpenRouterClient(_settings()).complete([])
    assert not captured.value.retryable
