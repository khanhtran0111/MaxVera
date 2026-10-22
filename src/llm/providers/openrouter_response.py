"""Classify received completion envelopes without discarding billing evidence."""

from __future__ import annotations

import json
import math
from typing import Any


class ResponseFailure(ValueError):
    def __init__(self, kind: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable


def known_cost(value: Any) -> bool:
    """A billable amount must be a finite, nonnegative number, never a bool."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value >= 0
        and (not isinstance(value, float) or math.isfinite(value))
    )


def response_metadata(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"usage": {}, "content_type": "missing"}
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices else None
    choice = choice if isinstance(choice, dict) else {}
    message = choice.get("message")
    message = message if isinstance(message, dict) else {}
    usage = body.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    # Usage is provenance, not a place to copy arbitrary provider response text.
    safe_usage: dict[str, Any] = {}
    for name in ("prompt_tokens", "completion_tokens", "total_tokens", "cost", "is_byok"):
        value = usage.get(name)
        if name == "is_byok":
            if isinstance(value, bool):
                safe_usage[name] = value
        elif name in usage:
            safe_usage[name] = value if known_cost(value) else None
    for name, fields in {
        "completion_tokens_details": {"reasoning_tokens", "image_tokens", "audio_tokens"},
        "prompt_tokens_details": {
            "cached_tokens",
            "cache_write_tokens",
            "audio_tokens",
            "video_tokens",
        },
        "cost_details": {
            "upstream_inference_cost",
            "upstream_inference_prompt_cost",
            "upstream_inference_completions_cost",
        },
    }.items():
        details = usage.get(name)
        if isinstance(details, dict):
            safe_usage[name] = {
                k: v if known_cost(v) else None for k, v in details.items() if k in fields
            }
    error = body.get("error") or choice.get("error")
    error = error if isinstance(error, dict) else {}
    error_metadata = error.get("metadata")
    error_metadata = error_metadata if isinstance(error_metadata, dict) else {}

    def text(value: Any) -> str | None:
        return value if isinstance(value, str) and len(value) <= 256 else None

    error_code = error.get("code")
    return {
        "request_id": text(body.get("id")),
        "returned_model": text(body.get("model")),
        "provider": text(body.get("provider")),
        "system_fingerprint": text(body.get("system_fingerprint")),
        "usage": safe_usage,
        "finish_reason": text(choice.get("finish_reason")),
        "native_finish_reason": text(choice.get("native_finish_reason")),
        "content_type": type(message.get("content")).__name__,
        "provider_error_code": error_code if type(error_code) is int else None,
        "provider_error_type": text(error_metadata.get("error_type")),
    }


def _slug(value: Any) -> str:
    return "".join(c for c in str(value).casefold() if c.isalnum())


def completion_text(body: Any, *, model: str, provider: str) -> str:
    if not isinstance(body, dict):
        raise ResponseFailure("MALFORMED_RESPONSE", "response is not an object")
    # Reject route drift before considering a retryable empty/error response.
    if body.get("model") is not None and body["model"] != model:
        raise ResponseFailure("ROUTE_MISMATCH", "returned model mismatch")
    if body.get("provider") is not None and (
        not isinstance(body["provider"], str) or _slug(body["provider"]) != _slug(provider)
    ):
        raise ResponseFailure("ROUTE_MISMATCH", "returned provider mismatch")
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices else None
    choice = choice if isinstance(choice, dict) else {}
    error = body.get("error") or choice.get("error")
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        raise ResponseFailure(
            "PROVIDER_ERROR",
            "provider reported an error inside the HTTP response",
            retryable=type(code) is int and code in {408, 409, 429, 500, 502, 503, 504},
        )
    if body.get("model") != model or _slug(body.get("provider")) != _slug(provider):
        raise ResponseFailure("ROUTE_MISMATCH", "response is missing the pinned model/provider")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ResponseFailure(
            "MALFORMED_RESPONSE", "response must have exactly one completion choice"
        )
    message = choice.get("message")
    if not isinstance(message, dict):
        raise ResponseFailure("MALFORMED_RESPONSE", "completion choice has no message")
    finish = choice.get("finish_reason")
    if message.get("refusal") or finish == "content_filter":
        raise ResponseFailure("REFUSAL", "provider refused or filtered the completion")
    if message.get("tool_calls") or message.get("function_call") or finish == "tool_calls":
        raise ResponseFailure("UNEXPECTED_TOOL_CALL", "text-only completion returned a tool call")
    if finish == "error":
        raise ResponseFailure(
            "PROVIDER_ERROR", "provider ended completion with an error", retryable=True
        )
    if finish == "length":
        raise ResponseFailure(
            "TRUNCATED_RESPONSE", "completion exhausted its output cap", retryable=True
        )
    if finish is not None and (not isinstance(finish, str) or finish != "stop"):
        raise ResponseFailure(
            "UNSUPPORTED_FINISH_REASON", "completion has an unsupported finish reason"
        )
    content = message.get("content")
    # Compatibility for providers returning ordered text parts: never drop a
    # non-text part or invent separators/labels while combining text fragments.
    if isinstance(content, list):
        if any(
            not isinstance(p, dict) or p.get("type") != "text" or not isinstance(p.get("text"), str)
            for p in content
        ):
            raise ResponseFailure(
                "UNSUPPORTED_CONTENT", "completion contains unsupported content parts"
            )
        content = "".join(p["text"] for p in content)
    if content is None or (isinstance(content, str) and not content.strip()):
        raise ResponseFailure("EMPTY_CONTENT", "completion contains no usable text", retryable=True)
    if not isinstance(content, str):
        raise ResponseFailure("UNSUPPORTED_CONTENT", "completion content is not text or text parts")
    return content


def strict_json(text: str) -> Any:
    """Reject duplicate keys and non-finite numbers before upstream consumes JSON."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except RecursionError:
        raise ValueError("response JSON exceeds parser nesting limit") from None
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON number")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value
