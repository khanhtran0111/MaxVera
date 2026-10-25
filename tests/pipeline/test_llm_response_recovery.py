"""Exercise real transport plus journal against received and uncertain HTTP failures."""

from __future__ import annotations

import json
import math
import stat
import urllib.error
from dataclasses import replace

import pytest

from maxvera.llm import JournaledClient
from src.llm.providers.openrouter import OpenRouterClient, OpenRouterError, OpenRouterSettings


def settings(**changes):
    base = OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "response-test-secret",
        "openai/gpt-oss-20b",
        "fixture-provider",
        128,
        0,
        1,
        1234,
        "low",
        5,
        0,
    )
    return replace(base, **changes)


def envelope(content="[]", *, cost=0.002, finish="stop", **extra):
    return {
        "id": "gen-fixture",
        "model": "openai/gpt-oss-20b",
        "provider": "Fixture Provider",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish,
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 7,
            "total_tokens": 17,
            "cost": cost,
            "completion_tokens_details": {"reasoning_tokens": 2},
        },
        **extra,
    }


@pytest.fixture
def wire(monkeypatch):
    sent, sleeps = [], []

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return self.body

    def install(*responses):
        queue = list(responses)

        def urlopen(request, timeout):
            assert 0 < timeout <= 5  # A case deadline may be shorter than the profile timeout.
            sent.append(json.loads(request.data))
            if not queue:
                pytest.fail("unexpected additional paid attempt")
            body = queue.pop(0)
            if isinstance(body, BaseException):
                raise body
            return Response(body if isinstance(body, bytes) else json.dumps(body).encode())

        monkeypatch.setattr("urllib.request.urlopen", urlopen)
        return sent

    monkeypatch.setattr("src.llm.providers.openrouter.time.sleep", sleeps.append)
    return install


def test_text_blocks_are_concatenated_without_inventing_separators(wire):
    wire(
        envelope(
            [
                {"type": "text", "text": "["},
                {"type": "text", "text": '{"type":"sink"}'},
                {"type": "text", "text": "]"},
            ]
        )
    )
    assert OpenRouterClient(settings()).complete([]) == '[{"type":"sink"}]'


@pytest.mark.parametrize("content", [None, "", " \n\t", []])
def test_empty_received_response_retains_metadata_and_private_evidence(tmp_path, wire, content):
    from src.llm.providers.openrouter import OpenRouterResponseError

    wire(envelope(content))
    log = tmp_path / "calls.jsonl"
    evidence = tmp_path / "private"
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(), log, response_directory=evidence).complete([])
    error = caught.value
    assert error.failure_kind == "EMPTY_CONTENT"
    assert error.retryable
    assert error.http_status == 200
    assert error.response_metadata["request_id"] == "gen-fixture"
    assert error.response_metadata["usage"]["cost"] == 0.002
    record = json.loads(log.read_text())
    assert record["failure_kind"] == "EMPTY_CONTENT"
    assert record["http_status"] == 200
    assert record["usage"]["completion_tokens_details"]["reasoning_tokens"] == 2
    files = list(evidence.glob("*.body"))
    assert len(files) == 1
    assert json.loads(files[0].read_text())["choices"][0]["message"]["content"] == content
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o700
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "content",
    [
        True,
        123,
        {},
        [{"type": "image_url", "image_url": "x"}],
        [{"type": "text", "text": 123}],
        ["[]"],
        [{"type": "text", "text": "[]"}, {"type": "image_url"}],
    ],
)
def test_unsupported_content_is_not_coerced_or_silently_discarded(wire, content):
    from src.llm.providers.openrouter import OpenRouterResponseError

    sent = wire(envelope(content))
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(max_retries=2)).complete([])
    assert caught.value.failure_kind == "UNSUPPORTED_CONTENT"
    assert not caught.value.retryable
    assert len(sent) == 1


@pytest.mark.parametrize("finish", ["length", "error", "content_filter", "tool_calls", "unknown"])
def test_finish_reason_cannot_turn_partial_json_into_success(wire, finish):
    from src.llm.providers.openrouter import OpenRouterResponseError

    wire(envelope("[]", finish=finish))
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings()).complete([])
    assert caught.value.response_metadata["finish_reason"] == finish
    assert caught.value.failure_kind != "EMPTY_CONTENT"


@pytest.mark.parametrize("field,value", [("refusal", "denied"), ("tool_calls", [{"id": "tool-1"}])])
def test_refusal_or_tool_call_is_rejected_even_with_valid_json_content(wire, field, value):
    from src.llm.providers.openrouter import OpenRouterResponseError

    body = envelope()
    body["choices"][0]["message"][field] = value
    sent = wire(body)
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(max_retries=2)).complete([])
    assert not caught.value.retryable
    assert len(sent) == 1


@pytest.mark.parametrize("location", ["top", "choice"])
def test_http_200_error_envelope_retains_generation_identity(wire, tmp_path, location):
    from src.llm.providers.openrouter import OpenRouterResponseError

    body = envelope()
    error = {
        "code": 502,
        "message": "provider disconnected",
        "metadata": {"error_type": "provider_unavailable"},
    }
    if location == "top":
        body["error"] = error
        body.pop("choices")
    else:
        body["choices"][0]["error"] = error
    wire(body)
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(), tmp_path / "calls.jsonl").complete([])
    assert caught.value.failure_kind == "PROVIDER_ERROR"
    assert caught.value.http_status == 200
    assert caught.value.retryable
    assert caught.value.response_metadata["request_id"] == "gen-fixture"
    assert caught.value.response_metadata["provider_error_code"] == 502


@pytest.mark.parametrize("field,value", [("model", "wrong-model"), ("provider", "wrong-provider")])
def test_route_drift_on_empty_response_is_permanent_and_accounted(tmp_path, wire, field, value):
    sent = wire(envelope(None, **{field: value}))
    client = JournaledClient(settings(max_retries=3), tmp_path, {})
    with pytest.raises(RuntimeError, match="ROUTE_MISMATCH"):
        client.complete([])
    assert len(sent) == 1
    request = json.loads(next(tmp_path.glob("requests/*/request.json")).read_text())
    assert request["status"] == "INVALID_RESPONSE"
    attempt = json.loads(next(tmp_path.glob("requests/*/attempt-1.json")).read_text())
    assert attempt["cost_usd"] == 0.002


def test_charged_empty_response_retries_identical_request_and_replays_success(tmp_path, wire):
    sent = wire(envelope(None), envelope('[{"type":"sink"}]', cost=0.003))
    client = JournaledClient(settings(max_retries=1), tmp_path, {})
    messages = [{"role": "user", "content": "unchanged prompt"}]
    assert (
        client.complete(messages, validate_json=True, expected_kind="array") == '[{"type":"sink"}]'
    )
    assert (
        client.complete(messages, validate_json=True, expected_kind="array") == '[{"type":"sink"}]'
    )
    assert len(sent) == 2
    assert sent[0] == sent[1]
    attempts = [
        json.loads(p.read_text()) for p in sorted(tmp_path.glob("requests/*/attempt-*.json"))
    ]
    assert [a["cost_usd"] for a in attempts] == [0.002, 0.003]
    assert attempts[0]["status"] == "INVALID_RESPONSE"
    assert len(list(tmp_path.glob("requests/*/provider-attempt-*/*.body"))) == 2


@pytest.mark.parametrize("cost", [None, -0.01, "0.01", True, math.nan, math.inf])
@pytest.mark.parametrize("content", [None, "[]"])
def test_missing_or_invalid_cost_blocks_retry_replay_and_later_requests(
    tmp_path, wire, cost, content
):
    sent = wire(envelope(content, cost=cost))
    client = JournaledClient(settings(max_retries=3), tmp_path, {})
    for messages in ([], [], [{"role": "user", "content": "next"}]):
        with pytest.raises(RuntimeError, match=r"unknown|uncertain"):
            client.complete(messages)
    assert len(sent) == 1
    record = json.loads(next(tmp_path.glob("requests/*/request.json")).read_text())
    assert record["status"] == "UNCERTAIN"
    assert record["request_id"] == "gen-fixture"


def test_received_error_cost_is_checked_before_any_retry_or_replay(tmp_path, wire):
    sent = wire(envelope(None, cost=0.02))
    client = JournaledClient(settings(max_retries=3), tmp_path, {"max_cost_usd_per_case": 0.01})
    for messages in ([], [], [{"role": "user", "content": "next"}]):
        with pytest.raises(RuntimeError, match="budget"):
            client.complete(messages)
    assert len(sent) == 1
    assert (tmp_path / "budget_stop.json").exists()


def test_repeated_empty_responses_stop_at_retry_limit_and_cannot_restart(tmp_path, wire):
    sent = wire(envelope(None), envelope(None))
    client = JournaledClient(settings(max_retries=1), tmp_path, {})
    for _ in range(2):
        with pytest.raises(RuntimeError, match=r"EMPTY_CONTENT|adjudication"):
            client.complete([])
    assert len(sent) == 2
    assert len(list(tmp_path.glob("requests/*/attempt-*.json"))) == 2


@pytest.mark.parametrize(
    "budgets,reason",
    [
        ({"max_calls_per_case": 1}, "call budget"),
        ({"max_input_tokens_per_case": 1500}, "input-token"),
        ({"max_output_tokens_per_case": 128}, "output-token"),
        ({"max_cost_usd_per_case": 0.002}, "cost budget"),
    ],
)
def test_received_error_retries_obey_all_case_ceilings(tmp_path, wire, budgets, reason):
    sent = wire(envelope(None))
    with pytest.raises(RuntimeError, match=reason):
        JournaledClient(settings(max_retries=5), tmp_path, budgets).complete([])
    assert len(sent) == 1


def test_http_200_body_rate_limit_does_not_release_a_real_charge(tmp_path, wire):
    body = envelope(None, cost=0.003, error={"code": 429, "message": "provider rejected late"})
    sent = wire(body, envelope(cost=0.001))
    client = JournaledClient(settings(max_retries=1), tmp_path, {})
    assert client.complete([]) == "[]"
    attempts = [
        json.loads(p.read_text()) for p in sorted(tmp_path.glob("requests/*/attempt-*.json"))
    ]
    assert [a["cost_usd"] for a in attempts] == [0.003, 0.001]
    assert attempts[0]["input_reservation"] > 0
    assert attempts[0]["output_reservation"] == 128
    assert len(sent) == 2


@pytest.mark.parametrize("raw", [b"<html>gateway</html>", b"\xff\xfe"])
def test_unparseable_http_body_is_retained_but_charge_remains_uncertain(tmp_path, wire, raw):
    sent = wire(raw)
    client = JournaledClient(settings(max_retries=3), tmp_path, {})
    with pytest.raises(RuntimeError, match="uncertain"):
        client.complete([])
    assert len(sent) == 1
    evidence = list(tmp_path.glob("requests/*/provider-attempt-*/*.body"))
    assert len(evidence) == 1
    assert evidence[0].read_bytes() == raw


def test_evidence_and_provenance_never_write_api_key(tmp_path, wire):
    body = envelope(None, extra_echo="Bearer response-test-secret")
    wire(body)
    log = tmp_path / "calls.jsonl"
    with pytest.raises(OpenRouterError):
        OpenRouterClient(settings(), log, response_directory=tmp_path / "evidence").complete([])
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert "response-test-secret" not in p.read_text()


@pytest.mark.parametrize("retry_after", ["nan", "inf", "-inf", "not-a-number"])
def test_nonfinite_or_invalid_retry_after_cannot_create_unbounded_sleep(retry_after):
    error = urllib.error.HTTPError(
        "https://example.invalid", 429, "rate limited", {"Retry-After": retry_after}, None
    )
    assert OpenRouterClient._retry_delay(1, error) == 5


@pytest.mark.parametrize(
    "mutation",
    [
        "choices_missing",
        "choices_wrong_type",
        "empty_choices",
        "non_object_choice",
        "multiple_choices",
        "message_wrong_type",
        "finish_list",
        "finish_object",
        "provider_list",
    ],
)
def test_malformed_shapes_are_classified_without_losing_received_usage(tmp_path, wire, mutation):
    from src.llm.providers.openrouter import OpenRouterResponseError

    body = envelope()
    if mutation == "choices_missing":
        body.pop("choices")
    elif mutation == "choices_wrong_type":
        body["choices"] = {}
    elif mutation == "empty_choices":
        body["choices"] = []
    elif mutation == "non_object_choice":
        body["choices"] = [None]
    elif mutation == "multiple_choices":
        body["choices"] *= 2
    elif mutation == "message_wrong_type":
        body["choices"][0]["message"] = []
    elif mutation == "finish_list":
        body["choices"][0]["finish_reason"] = ["stop"]
    elif mutation == "finish_object":
        body["choices"][0]["finish_reason"] = {"name": "stop"}
    elif mutation == "provider_list":
        body["provider"] = ["fixture-provider"]
    sent = wire(body)
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(max_retries=2), tmp_path / "calls.jsonl").complete([])
    assert caught.value.response_metadata["usage"]["cost"] == 0.002
    assert not caught.value.retryable
    assert len(sent) == 1


@pytest.mark.parametrize(
    "content",
    ["[NaN]", "[Infinity]", "[1e999]", "[1]", "[null]", '[{"type":"source","type":"sink"}]'],
)
def test_iris_rejects_ambiguous_or_non_object_label_json_before_cache(tmp_path, wire, content):
    sent = wire(envelope(content), envelope('[{"type":"sink"}]'))
    client = JournaledClient(settings(max_retries=1), tmp_path, {})
    assert client.complete([], validate_json=True, expected_kind="array") == '[{"type":"sink"}]'
    assert len(sent) == 2
    assert sent[0] == sent[1]


def test_response_backoff_cannot_exceed_case_time_budget(tmp_path, wire):
    sent = wire(envelope(None))
    with pytest.raises(RuntimeError, match="time budget"):
        JournaledClient(settings(max_retries=2), tmp_path, {"timeout_case_s": 1}).complete([])
    assert len(sent) == 1


def test_local_evidence_write_failure_never_repeats_a_paid_request(tmp_path, wire):
    from src.llm.providers.openrouter import OpenRouterResponseError

    target = tmp_path / "not-a-directory"
    target.write_text("existing data")
    sent = wire(envelope())
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(max_retries=2), response_directory=target).complete([])
    assert caught.value.failure_kind == "EVIDENCE_WRITE_FAILED"
    assert caught.value.response_metadata["usage"]["cost"] == 0.002
    assert len(sent) == 1
    assert target.read_text() == "existing data"


def test_provenance_does_not_promote_unknown_usage_fields_or_response_text(tmp_path, wire):
    body = envelope("private-response-marker")
    body["usage"]["extra_prompt"] = "private-response-marker"
    body["usage"]["completion_tokens_details"]["extra_prompt"] = "private-response-marker"
    wire(body)
    log = tmp_path / "calls.jsonl"
    assert OpenRouterClient(settings(), log).complete([]) == "private-response-marker"
    assert "private-response-marker" not in log.read_text()


def test_echoed_key_in_generation_id_does_not_leak_to_journal(tmp_path, wire):
    wire(envelope(None, id="response-test-secret"))
    with pytest.raises(RuntimeError, match="EMPTY_CONTENT"):
        JournaledClient(settings(), tmp_path, {}).complete([])
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert b"response-test-secret" not in p.read_bytes()


def test_raw_client_never_resends_unparseable_received_response(wire):
    sent = wire(b"<html>unknown billing</html>")
    with pytest.raises(OpenRouterError) as caught:
        OpenRouterClient(settings(max_retries=2)).complete([])
    assert not caught.value.retryable
    assert len(sent) == 1


def test_transient_provenance_write_error_cannot_duplicate_paid_completion(
    tmp_path, wire, monkeypatch
):
    from src.llm.providers.openrouter import OpenRouterResponseError

    sent = wire(envelope())
    append = OpenRouterClient._append_log
    writes = []

    def transient_failure(client, record):
        writes.append(record)
        if len(writes) == 1:
            raise OSError("temporary provenance write failure")
        append(client, record)

    monkeypatch.setattr(OpenRouterClient, "_append_log", transient_failure)
    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterClient(settings(max_retries=2), tmp_path / "calls.jsonl").complete([])
    assert caught.value.response_metadata["usage"]["cost"] == 0.002
    assert not caught.value.retryable
    assert len(sent) == 1


@pytest.mark.parametrize(
    "metadata_field",
    ["id", "provider", "model", "system_fingerprint", "error_code", "error_type", "finish_reason"],
)
def test_nested_metadata_is_never_promoted_to_public_provenance(tmp_path, wire, metadata_field):
    body = envelope(None)
    private = {"raw": "private-response-marker"}
    if metadata_field == "error_code":
        body["error"] = {"code": private}
    elif metadata_field == "error_type":
        body["error"] = {"code": 502, "metadata": {"error_type": private}}
    elif metadata_field == "finish_reason":
        body["choices"][0]["finish_reason"] = private
    else:
        body[metadata_field] = private
    wire(body)
    log = tmp_path / "calls.jsonl"
    with pytest.raises(OpenRouterError):
        OpenRouterClient(settings(), log).complete([])
    assert "private-response-marker" not in log.read_text()


def test_existing_21_pending_journal_is_not_bypassed_after_response_repair(tmp_path, wire):
    # Captured from the previous implementation with settings() and empty messages.
    old_key = "b6de0ad85104b0e1f3e45d6bdd094f683b5f3e9af5f53cfc73e88d82cd279a94"
    folder = tmp_path / "requests" / old_key
    folder.mkdir(parents=True)
    (folder / "request.json").write_text(json.dumps({"status": "PENDING", "key": old_key}))
    (folder / "attempt-1.json").write_text(
        json.dumps(
            {
                "status": "RECEIVED",
                "cost_usd": 0.002,
                "input_reservation": 1026,
                "output_reservation": 128,
            }
        )
    )
    sent = wire(envelope())
    with pytest.raises(RuntimeError, match="uncertain"):
        JournaledClient(settings(), tmp_path, {}).complete([])
    assert sent == []


def test_old_successful_cache_is_revalidated_without_sending_paid_request(tmp_path, wire):
    from maxvera.contracts import digest

    client = JournaledClient(settings(), tmp_path, {})
    cached = [{"role": "user", "content": "old cached prompt"}]
    folder = tmp_path / "requests" / client.key(cached, False, 128, True, "array")
    folder.mkdir(parents=True)
    raw = '[{"type":"source","type":"sink"}]'
    (folder / "response.txt").write_text(raw)
    (folder / "request.json").write_text(
        json.dumps({"status": "SUCCESS", "response_hash": digest(raw)})
    )
    sent = wire(envelope())
    with pytest.raises(RuntimeError, match=r"cached.*validation"):
        client.complete(cached, validate_json=True, expected_kind="array")
    with pytest.raises(RuntimeError, match=r"cached.*validation"):
        client.preflight(
            [[{"role": "user", "content": "new prompt"}], cached],
            validate_json=True,
            expected_kind="array",
        )
    assert sent == []
