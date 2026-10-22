"""Exercise the fast profile's real journal scheduling without remote calls."""

import json
from contextlib import suppress
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def fast_settings(monkeypatch):
    from src.llm.providers.openrouter import OpenRouterSettings

    root = Path(__file__).resolve().parents[2]
    profile = root / "configs/models/gpt_oss_20b_openrouter_fast.yaml"
    config = yaml.safe_load(profile.read_text())
    monkeypatch.setattr(
        "src.llm.providers.openrouter.effective_env",
        lambda _: {
            "MAXVERA_OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1",
            "OPENROUTER_API_KEY": "fixture-key",
            "MAXVERA_OPENROUTER_PROVIDER": config["provider_route"],
        },
    )
    return OpenRouterSettings.load(root, profile)


def test_fast_profile_does_not_idle_after_success_and_replays_cache(
    tmp_path, monkeypatch, fast_settings
):
    from maxvera.llm import JournaledClient

    clock, delays, payloads = [100.0], [], []

    def sleep(delay):
        delays.append(delay)
        clock[0] += delay

    def remote(client, messages, **kwargs):
        payloads.append(client._payload(messages, expect_json=False))
        clock[0] += 1
        client._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
        return "[]"

    monkeypatch.setattr("maxvera.llm.time.time", lambda: clock[0])
    monkeypatch.setattr("maxvera.llm.time.sleep", sleep)
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    for text in ["first", "second", "first"]:
        result = JournaledClient(fast_settings, tmp_path, {}).complete(
            [{"role": "user", "content": text}], validate_json=True, expected_kind="array"
        )
        assert result == "[]"
    assert clock[0] == 102
    assert delays == []
    assert len(payloads) == 2
    for payload in payloads:
        assert payload["model"] == "openai/gpt-oss-20b"
        assert payload["temperature"] == 0
        assert payload["top_p"] == 1
        assert payload["max_tokens"] == 2048
        assert payload["provider"]["allow_fallbacks"] is False


def test_fast_profile_honors_retry_after_without_a_minute_floor(
    tmp_path, monkeypatch, fast_settings
):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterError

    calls, delays = [], []

    def remote(client, messages, **kwargs):
        calls.append(messages)
        if len(calls) == 1:
            raise OpenRouterError("429", http_status=429, retryable=True, retry_after_seconds=3)
        client._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
        return "[]"

    monkeypatch.setattr("maxvera.llm.time.sleep", delays.append)
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    client = JournaledClient(fast_settings, tmp_path, {})
    assert client.complete([{"role": "user", "content": "same prompt"}]) == "[]"
    assert delays == [3]
    assert calls[0] == calls[1]
    attempts = [json.loads(p.read_text()) for p in tmp_path.glob("requests/*/attempt-*.json")]
    assert len(attempts) == 2
    rejected = next(a for a in attempts if a["status"] == "RATE_LIMITED")
    assert rejected["cost_usd"] == 0
    assert rejected["input_reservation"] == rejected["output_reservation"] == 0


@pytest.mark.parametrize("wrapper", ["```json\n{}\n```", "```\n{}\n```"])
def test_json_code_fence_does_not_trigger_a_second_paid_generation(
    tmp_path, monkeypatch, wrapper, fast_settings
):
    from maxvera.llm import JournaledClient

    response = wrapper.format('[{"type":"source"}]')
    calls = []

    def remote(client, messages, **kwargs):
        calls.append(messages)
        client._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
        return response

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    client = JournaledClient(fast_settings, tmp_path, {"max_calls_per_case": 1})
    prompt = [{"role": "user", "content": "original prompt"}]
    for _ in range(2):
        assert client.complete(prompt, validate_json=True, expected_kind="array") == response
    assert len(calls) == 1


@pytest.mark.parametrize(
    "raw",
    [
        'before\n```json\n[]\n```',
        '```json\n[]\n```\nafter',
        '```json\n[]\n```\n```json\n[]\n```',
        '```json\n[{"type":"sink","type":"source"}]\n```',
        '```json\n[{"value":NaN}]\n```',
    ],
)
def test_code_fence_handling_retains_strict_validation(raw):
    from maxvera.llm import _validate_output

    with pytest.raises(ValueError):
        _validate_output(raw, "array")


@pytest.mark.parametrize("failure", ["preflight_budget", "rate_limit", "unknown_charge"])
def test_worker_does_not_publish_success_when_upstream_swallows_transport_error(
    tmp_path, monkeypatch, fast_settings, failure
):
    from dataclasses import replace

    from maxvera.iris_worker import run_stage
    from maxvera.llm import IrisProvider
    from src.llm.providers.openrouter import OpenRouterError

    monkeypatch.setattr(IrisProvider, "settings", replace(fast_settings, max_retries=0))
    monkeypatch.setattr(IrisProvider, "_failure", None, raising=False)
    monkeypatch.setattr(
        IrisProvider,
        "request",
        {
            "stage": "context_filter",
            "journal": str(tmp_path),
            "budgets": {"max_output_tokens_per_case": 1} if failure == "preflight_budget" else {},
        },
    )

    calls = []

    def remote(client, messages, **kwargs):
        calls.append(messages)
        if len(calls) > 1:
            client._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
            return "{}"
        if failure == "rate_limit":
            raise OpenRouterError("429", http_status=429, retryable=True)
        raise OSError("connection lost")

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)

    class Upstream:
        def query_gpt_for_posthoc_filtering(self):
            # Pinned upstream catches these errors and produces partial SARIF.
            for text in ["first path", "later path"]:
                with suppress(Exception):
                    IrisProvider().predict([[{"role": "user", "content": text}]], batch_size=1)

    with pytest.raises(RuntimeError, match="LLM stage failed"):
        run_stage(Upstream(), "context_filter")
    assert len(calls) == (0 if failure == "preflight_budget" else 1)
