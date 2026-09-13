from __future__ import annotations

import json
import urllib.error
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


def test_payload_pins_model_provider_privacy_and_no_fallback() -> None:
    client = OpenRouterClient(_settings())
    payload = client._payload(
        [{"role": "user", "content": "return JSON"}], expect_json=True
    )
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
                    "choices": [
                        {"message": {"content": "OK"}, "finish_reason": "stop"}
                    ],
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
