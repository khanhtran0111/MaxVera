from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings


def _settings() -> OpenRouterSettings:
    return OpenRouterSettings(
        base_url="https://openrouter.ai/api/v1",
        api_key="unit-test-secret",
        model="openai/gpt-oss-20b",
        provider="groq",
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
        "only": ["groq"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "zdr": True,
        "data_collection": "deny",
    }
    assert payload["reasoning"] == {"effort": "low", "exclude": True}
    assert payload["response_format"] == {"type": "json_object"}


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
                    "provider": "Groq",
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
    assert record["provider_route"] == "groq"
    assert record["request_id"] == "gen-test"
