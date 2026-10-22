"""Budgets and durable model journaling without any external requests."""

import json
from dataclasses import replace

import pytest

from src.llm.providers.openrouter import OpenRouterSettings


def settings():
    return OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "test-secret",
        "openai/gpt-oss-20b",
        "fixture-provider",
        64,
        0,
        1,
        1234,
        "low",
        5,
        0,
    )


def test_completed_request_is_replayed_without_double_charge(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    def remote(self, messages, **kwargs):
        self._append_log(
            {
                "status": "SUCCESS",
                "request_id": "response-1",
                "usage": {"prompt_tokens": 10, "completion_tokens": 7, "cost": 0.001},
                "finish_reason": "stop",
            }
        )
        return '{"label":"source"}'

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    a = JournaledClient(settings(), tmp_path, {"max_calls_per_case": 1})
    assert (
        a.complete([{"role": "user", "content": "class X {}"}], expect_json=True)
        == '{"label":"source"}'
    )
    b = JournaledClient(settings(), tmp_path, {"max_calls_per_case": 1})
    assert (
        b.complete([{"role": "user", "content": "class X {}"}], expect_json=True)
        == '{"label":"source"}'
    )
    with pytest.raises(RuntimeError, match="budget"):
        b.complete([{"role": "user", "content": "different"}])
    assert len(list((tmp_path / "requests").glob("*/request.json"))) == 1


def test_pending_remote_request_blocks_resume(tmp_path):
    from maxvera.llm import JournaledClient

    c = JournaledClient(settings(), tmp_path, {})
    key = c.key([{"role": "user", "content": "x"}], False, 64)
    folder = tmp_path / "requests" / key
    folder.mkdir(parents=True)
    (folder / "request.json").write_text('{"status":"PENDING"}')
    with pytest.raises(RuntimeError, match="uncertain"):
        c.complete([{"role": "user", "content": "x"}])


def test_json_retry_does_not_invent_labels_or_change_prompt(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    prompts = []

    def remote(self, messages, **kwargs):
        prompts.append(messages)
        self._append_log(
            {
                "status": "SUCCESS",
                "usage": {"prompt_tokens": 10, "completion_tokens": 7, "cost": 0.001},
                "finish_reason": "stop",
            }
        )
        return "broken JSON" if len(prompts) == 1 else '[{"type":"sink"}]'

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    c = JournaledClient(replace(settings(), max_retries=1), tmp_path, {"max_calls_per_case": 2})
    assert c.complete([{"role": "user", "content": "x"}], expect_json=True) == '[{"type":"sink"}]'
    assert prompts[0] == prompts[1]


def test_explicit_rate_limit_retries_same_prompt_and_releases_token_reservation(
    tmp_path, monkeypatch
):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterError

    prompts, delays = [], []

    def remote(self, messages, **kwargs):
        prompts.append(messages)
        if len(prompts) == 1:
            raise OpenRouterError(
                "rate limited", http_status=429, retryable=True, retry_after_seconds=12
            )
        self._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
        return "[]"

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    monkeypatch.setattr("maxvera.llm.time.sleep", delays.append)
    client = JournaledClient(
        replace(settings(), max_retries=1),
        tmp_path,
        {"max_calls_per_case": 2, "max_input_tokens_per_case": 1500},
    )
    assert client.complete([{"role": "user", "content": "original"}]) == "[]"
    assert prompts[0] == prompts[1]
    assert delays == [12]
    rejected = next(tmp_path.glob("requests/*/attempt-1.json"))
    record = json.loads(rejected.read_text())
    assert record["status"] == "RATE_LIMITED"
    assert record["cost_usd"] == 0
    assert record["input_reservation"] == record["output_reservation"] == 0


def test_rate_limit_retries_remain_subject_to_total_call_budget(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterError

    calls = []

    def remote(self, messages, **kwargs):
        calls.append(messages)
        raise OpenRouterError("rate limited", http_status=429, retryable=True)

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    monkeypatch.setattr("maxvera.llm.time.sleep", lambda seconds: None)
    client = JournaledClient(
        replace(settings(), max_retries=5), tmp_path, {"max_calls_per_case": 1}
    )
    with pytest.raises(RuntimeError, match="call budget"):
        client.complete([{"role": "user", "content": "original"}])
    assert len(calls) == 1


@pytest.mark.parametrize("http_status", [None, 503])
def test_uncertain_remote_failure_is_never_automatically_retried(
    tmp_path, monkeypatch, http_status
):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterError

    calls = []

    def remote(self, messages, **kwargs):
        calls.append(messages)
        raise OpenRouterError("connection lost", http_status=http_status, retryable=True)

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    client = JournaledClient(replace(settings(), max_retries=5), tmp_path, {})
    for _ in range(2):
        with pytest.raises(RuntimeError, match="uncertain"):
            client.complete([{"role": "user", "content": "original"}])
    assert len(calls) == 1


def test_spacing_is_measured_after_response_and_survives_client_restart(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    clock, calls, delays = [100.0], [], []

    def sleep(seconds):
        delays.append(seconds)
        clock[0] += seconds

    def remote(self, messages, **kwargs):
        calls.append(clock[0])
        clock[0] += 40
        self._append_log({"status": "SUCCESS", "usage": {"cost": 0}})
        return "[]"

    monkeypatch.setattr("maxvera.llm.time.time", lambda: clock[0])
    monkeypatch.setattr("maxvera.llm.time.sleep", sleep)
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    paced = replace(settings(), request_interval_seconds=30)
    first = [{"role": "user", "content": "first"}]
    assert JournaledClient(paced, tmp_path, {}).complete(first) == "[]"
    assert JournaledClient(paced, tmp_path, {}).complete(first) == "[]"
    assert delays == []  # Cached responses do not wait or make a request.
    clock[0] += 5
    JournaledClient(paced, tmp_path, {}).complete([{"role": "user", "content": "next"}])
    assert calls == [100, 170]
    assert delays == [25]


def test_rate_limit_backoff_uses_configured_minimum_and_honors_long_retry_after(
    tmp_path, monkeypatch
):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterError

    delays, calls = [], []

    def remote(self, messages, **kwargs):
        calls.append(messages)
        if len(calls) < 3:
            raise OpenRouterError(
                "rate limited",
                http_status=429,
                retryable=True,
                retry_after_seconds=900 if len(calls) == 2 else 1,
            )
        self._append_log({"status": "SUCCESS", "usage": {"cost": 0}})
        return "[]"

    monkeypatch.setattr("maxvera.llm.time.sleep", delays.append)
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    paced = replace(
        settings(), max_retries=2, rate_limit_backoff_seconds=60, rate_limit_max_backoff_seconds=600
    )
    assert JournaledClient(paced, tmp_path, {}).complete([{"role": "user", "content": "x"}]) == "[]"
    assert delays == [60, 900]
    assert calls[0] == calls[1] == calls[2]


def test_spacing_cannot_exceed_time_budget_or_mark_unsent_request_uncertain(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    monkeypatch.setattr("maxvera.llm.time.time", lambda: 100)
    (tmp_path / "request_clock.json").write_text('{"last_finished_at": 100}')

    def remote(*args, **kwargs):
        pytest.fail("request must not be sent beyond time budget")

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    paced = replace(settings(), request_interval_seconds=30)
    with pytest.raises(RuntimeError, match="time budget"):
        JournaledClient(paced, tmp_path, {"timeout_case_s": 10}).complete(
            [{"role": "user", "content": "x"}]
        )
    assert not list(tmp_path.glob("requests/*/request.json"))


@pytest.mark.parametrize(
    ("budgets", "reason"),
    [
        ({"max_calls_per_case": 1}, "call"),
        ({"max_input_tokens_per_case": 1500}, "input"),
        ({"max_output_tokens_per_case": 64}, "output"),
    ],
)
def test_iris_rejects_unaffordable_batch_before_any_remote_request(
    tmp_path, monkeypatch, budgets, reason
):
    from maxvera.llm import IrisProvider

    def remote(*args, **kwargs):
        pytest.fail("an unaffordable batch must never send its first paid request")

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    monkeypatch.setattr(IrisProvider, "settings", settings())
    monkeypatch.setattr(
        IrisProvider,
        "request",
        {"journal": str(tmp_path), "budgets": budgets, "stage": "llm_specs"},
    )
    with pytest.raises(RuntimeError, match=f"batch.*{reason}.*budget"):
        IrisProvider().predict(
            [[{"role": "user", "content": "first"}], [{"role": "user", "content": "second"}]],
            batch_size=1,
        )
    assert not list(tmp_path.glob("requests/*/attempt-*.json"))


def test_batch_preflight_counts_prior_attempts_and_reservations(tmp_path):
    from maxvera.llm import JournaledClient

    old = tmp_path / "requests/old"
    old.mkdir(parents=True)
    (old / "attempt-1.json").write_text(
        json.dumps(
            {
                "status": "RATE_LIMITED",
                "input_reservation": 0,
                "output_reservation": 0,
                "cost_usd": 0,
            }
        )
    )
    (old / "attempt-2.json").write_text(
        json.dumps(
            {
                "status": "RECEIVED",
                "input_reservation": 1200,
                "output_reservation": 64,
                "cost_usd": 0.001,
            }
        )
    )
    prompts = [[{"role": "user", "content": "new"}]]
    for budget, reason in [
        ({"max_calls_per_case": 2}, "call"),
        ({"max_input_tokens_per_case": 2000}, "input"),
        ({"max_output_tokens_per_case": 100}, "output"),
    ]:
        client = JournaledClient(settings(), tmp_path, budget)
        with pytest.raises(RuntimeError, match=f"batch.*{reason}.*budget"):
            client.preflight(prompts)


def test_batch_preflight_deduplicates_and_preserves_cached_replay(tmp_path, monkeypatch):
    from maxvera.llm import JournaledClient

    def remote(client, messages, **kwargs):
        client._append_log({"status": "SUCCESS", "usage": {"cost": 0.001}})
        return "[]"

    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    client = JournaledClient(settings(), tmp_path, {"max_calls_per_case": 2})
    cached = [{"role": "user", "content": "cached"}]
    fresh = [{"role": "user", "content": "fresh"}]
    assert client.complete(cached) == "[]"
    plan = client.preflight([cached, fresh, fresh])
    assert plan["uncached_requests"] == 1
    assert plan["prior_attempts"] == 1
    assert plan["minimum_output_reservation"] == 64
    assert [client.complete(p) for p in [cached, fresh, fresh]] == ["[]", "[]", "[]"]
    assert len(list(tmp_path.glob("requests/*/attempt-*.json"))) == 2


@pytest.mark.parametrize("status", ["PENDING", "UNCERTAIN", "INVALID_JSON"])
def test_batch_preflight_rejects_unreplayable_journal_before_any_send(tmp_path, status):
    from maxvera.llm import JournaledClient

    client = JournaledClient(settings(), tmp_path, {})
    prompt = [{"role": "user", "content": "old"}]
    folder = tmp_path / "requests" / client.key(prompt, False, 64)
    folder.mkdir(parents=True)
    (folder / "request.json").write_text(json.dumps({"status": status}))
    with pytest.raises(RuntimeError, match=r"uncertain|adjudication"):
        client.preflight([[{"role": "user", "content": "fresh"}], prompt])


def test_batch_preflight_checks_cached_response_integrity(tmp_path):
    from maxvera.llm import JournaledClient

    client = JournaledClient(settings(), tmp_path, {})
    prompt = [{"role": "user", "content": "cached"}]
    folder = tmp_path / "requests" / client.key(prompt, False, 64)
    folder.mkdir(parents=True)
    (folder / "request.json").write_text(
        json.dumps(
            {
                "status": "SUCCESS",
                "response_hash": "original-checksum",
            }
        )
    )
    (folder / "response.txt").write_text("tampered")
    with pytest.raises(RuntimeError, match="checksum"):
        client.preflight([[{"role": "user", "content": "fresh"}], prompt])


def test_reproduction_config_can_admit_observed_dspace_batch_with_retry_headroom(tmp_path):
    from pathlib import Path

    from maxvera.contracts import PipelineConfig
    from maxvera.llm import JournaledClient

    config = PipelineConfig.load(Path("configs/pipelines/reproduce.yaml"))
    # Observed DSpace: 3,336 APIs / 30 = 112 distinct prompts. Reserve
    # six attempts/prompt at 8,000 bytes each, including template allowance.
    client = JournaledClient(
        replace(settings(), max_tokens=2048), tmp_path, config.resolved()["budgets"]
    )
    prompts = [[{"role": "user", "content": f"{i}:" + "a" * 6900}] for i in range(672)]
    plan = client.preflight(prompts)
    assert plan["uncached_requests"] == 672
    assert config.budgets.max_cost_usd_per_case == 1.0
