"""Minimal OpenRouter client for the canonical GPT-OSS 20B research route."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env
from src.llm.providers.openrouter_response import (
    ResponseFailure,
    completion_text,
    known_cost,
    response_metadata,
)

CANONICAL_BASE_URL = "https://openrouter.ai/api/v1"
CANONICAL_MODEL = "openai/gpt-oss-20b"


def _provider_slug(value: object) -> str:
    return "".join(character for character in str(value).casefold() if character.isalnum())


class OpenRouterError(RuntimeError):
    """A bounded, secret-safe OpenRouter request failure."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
        retry_after_seconds: float = 0,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.http_status = http_status
        self.retry_after_seconds = retry_after_seconds


class OpenRouterResponseError(OpenRouterError):
    """An HTTP response was received; preserve its identity and actual usage."""

    def __init__(self, failure: ResponseFailure, metadata: dict[str, Any]):
        super().__init__(
            f"OpenRouter {failure.kind}: {failure}",
            retryable=failure.retryable and known_cost(metadata.get("usage", {}).get("cost")),
            http_status=200,
        )
        self.failure_kind = failure.kind
        self.response_metadata = metadata


@dataclass(frozen=True)
class OpenRouterSettings:
    base_url: str
    api_key: str
    model: str
    provider: str
    max_tokens: int
    temperature: float
    top_p: float
    seed: int
    reasoning_effort: str
    timeout_seconds: int
    max_retries: int
    request_interval_seconds: float = 0
    rate_limit_backoff_seconds: float = 5
    rate_limit_max_backoff_seconds: float = 60

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.max_retries < 0:
            raise ValueError("request timeout must be positive and retries nonnegative")
        pacing = (
            self.request_interval_seconds,
            self.rate_limit_backoff_seconds,
            self.rate_limit_max_backoff_seconds,
        )
        if not all(math.isfinite(value) for value in pacing):
            raise ValueError("request pacing must be finite")
        if self.request_interval_seconds < 0 or self.rate_limit_backoff_seconds <= 0:
            raise ValueError("request interval must be nonnegative and backoff positive")
        if self.rate_limit_max_backoff_seconds < self.rate_limit_backoff_seconds:
            raise ValueError("maximum backoff must be at least the initial backoff")

    @classmethod
    def load(
        cls,
        repo_root: Path,
        config_path: Path | None = None,
    ) -> OpenRouterSettings:
        config_path = config_path or repo_root / "configs/models/gpt_oss_20b_openrouter.yaml"
        if not config_path.is_absolute():
            config_path = repo_root / config_path
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"invalid model configuration: {config_path}")
        config = cast(dict[str, Any], loaded)
        env = effective_env(repo_root / ".env")
        base_url = env.get("MAXVERA_OPENROUTER_BASE_URL", "").rstrip("/")
        api_key = env.get("OPENROUTER_API_KEY", "")
        provider = env.get("MAXVERA_OPENROUTER_PROVIDER", "")
        if base_url != CANONICAL_BASE_URL:
            raise ValueError(f"MAXVERA_OPENROUTER_BASE_URL must be {CANONICAL_BASE_URL}")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is missing from .env")
        if not provider:
            raise ValueError("MAXVERA_OPENROUTER_PROVIDER is missing from .env")
        configured_provider = str(config.get("provider_route", ""))
        if not configured_provider:
            raise ValueError(f"provider_route is missing from {config_path}")
        if provider != configured_provider:
            raise ValueError(
                f"MAXVERA_OPENROUTER_PROVIDER must match the pinned route {configured_provider}"
            )
        if config.get("model_id") != CANONICAL_MODEL:
            raise ValueError(f"model_id must be {CANONICAL_MODEL}")
        return cls(
            base_url=base_url,
            api_key=api_key,
            model=CANONICAL_MODEL,
            provider=provider,
            max_tokens=int(config["max_output_tokens"]),
            temperature=float(config["temperature"]),
            top_p=float(config["top_p"]),
            seed=int(config["seed"]),
            reasoning_effort=str(config["reasoning_effort"]),
            timeout_seconds=int(config["timeout_seconds"]),
            max_retries=int(config["max_retries"]),
            request_interval_seconds=float(config.get("request_interval_seconds", 0)),
            rate_limit_backoff_seconds=float(config.get("rate_limit_backoff_seconds", 5)),
            rate_limit_max_backoff_seconds=float(config.get("rate_limit_max_backoff_seconds", 60)),
        )


class OpenRouterClient:
    """Synchronous one-request-at-a-time client with provenance-only logging."""

    _last_request_started: float | None = None

    def __init__(
        self,
        settings: OpenRouterSettings,
        call_log: Path | None = None,
        log_context: Mapping[str, Any] | None = None,
        *,
        request_interval_seconds: float = 0,
        response_directory: Path | None = None,
    ):
        if not 0 <= request_interval_seconds <= 90:
            raise ValueError("request interval must be between 0 and 90 seconds")
        self.settings = settings
        self.call_log = call_log
        self.log_context = dict(log_context or {})
        self.call_number = 0
        self.request_interval_seconds = request_interval_seconds
        self.response_directory = response_directory

    def _pace_request(self) -> None:
        previous = OpenRouterClient._last_request_started
        if previous is not None:
            remaining = self.request_interval_seconds - (time.monotonic() - previous)
            if remaining > 0:
                time.sleep(remaining)
        OpenRouterClient._last_request_started = time.monotonic()

    def _payload(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        expect_json: bool,
        max_tokens: int | None = None,
        response_schema: Mapping[str, Any] | None = None,
        response_schema_name: str = "phase5_hypotheses",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": list(messages),
            "temperature": self.settings.temperature,
            "top_p": self.settings.top_p,
            "seed": self.settings.seed,
            "max_tokens": min(max_tokens or self.settings.max_tokens, self.settings.max_tokens),
            "reasoning": {"effort": self.settings.reasoning_effort, "exclude": True},
            "provider": {
                "only": [self.settings.provider],
                "allow_fallbacks": False,
                "require_parameters": True,
                "zdr": True,
                "data_collection": "deny",
            },
        }
        if response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema_name,
                    "strict": True,
                    "schema": dict(response_schema),
                },
            }
        elif expect_json:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _append_log(self, record: Mapping[str, Any]) -> None:
        if self.call_log is None:
            return
        self.call_log.parent.mkdir(parents=True, exist_ok=True)
        with self.call_log.open("a", encoding="utf-8", newline="\n") as handle:
            merged = {**self.log_context, **dict(record)}
            serialized = json.dumps(merged, sort_keys=True, ensure_ascii=False)
            handle.write(serialized.replace(self.settings.api_key, "[REDACTED]") + "\n")

    def _save_response(self, raw: bytes, attempt: int) -> None:
        if self.response_directory is None:
            return
        self.response_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.response_directory, 0o700)
        path = self.response_directory / f"response-{self.call_number}-{attempt}.body"
        # Exact wire body except any echoed credential; private audit evidence
        # stays out of public provenance and never includes request headers.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw.replace(self.settings.api_key.encode(), b"[REDACTED]"))

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            loaded = json.loads(error.read().decode("utf-8", errors="replace"))
            error_record = loaded.get("error", {}) if isinstance(loaded, dict) else {}
            message = error_record.get("message") if isinstance(error_record, dict) else None
            metadata = error_record.get("metadata") if isinstance(error_record, dict) else None
            provider = metadata.get("provider_name") if isinstance(metadata, dict) else None
            raw = metadata.get("raw") if isinstance(metadata, dict) else None
            parts = [str(value) for value in (message, provider, raw) if value]
            return " | ".join(parts)[:500] if parts else f"HTTP {error.code}"
        except (OSError, ValueError, AttributeError):
            return f"HTTP {error.code}"

    @staticmethod
    def _retry_delay(attempt: int, error: urllib.error.HTTPError | None = None) -> float:
        if error is not None:
            retry_after = error.headers.get("Retry-After")
            if retry_after:
                try:
                    delay = float(retry_after)
                    if math.isfinite(delay):
                        return max(1.0, delay)
                except ValueError:
                    pass
            if error.code == 429:
                return float(min(5 * 2 ** (attempt - 1), 60))
        return float(min(2 ** (attempt - 1), 8))

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        expect_json: bool = False,
        max_tokens: int | None = None,
        response_schema: Mapping[str, Any] | None = None,
        response_schema_name: str = "phase5_hypotheses",
    ) -> str:
        payload = self._payload(
            messages,
            expect_json=expect_json,
            max_tokens=max_tokens,
            response_schema=response_schema,
            response_schema_name=response_schema_name,
        )
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        prompt_sha256 = hashlib.sha256(encoded).hexdigest()
        started = time.monotonic()
        last_error = "no response"
        retryable = False
        http_status = None
        self.call_number += 1
        for attempt in range(1, self.settings.max_retries + 2):
            received_http_status = None
            metadata: dict[str, Any] = {"usage": {}}
            self._pace_request()
            retry_delay = self._retry_delay(attempt)
            request = urllib.request.Request(
                f"{self.settings.base_url}/chat/completions",
                data=encoded,
                headers={
                    "Authorization": f"Bearer {self.settings.api_key}",
                    "Content-Type": "application/json",
                    "X-OpenRouter-Title": "MaxVera vulnerability research",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=self.settings.timeout_seconds
                ) as response:
                    received_http_status = 200
                    raw_body = response.read()
                parse_error = None
                try:
                    loaded = json.loads(raw_body.decode("utf-8"))
                except (ValueError, UnicodeError) as decoding_error:
                    loaded = None
                    parse_error = decoding_error
                metadata = response_metadata(loaded)
                # Metadata also reaches the durable journal through exceptions.
                metadata = json.loads(
                    json.dumps(metadata).replace(self.settings.api_key, "[REDACTED]")
                )
                record = {
                    "schema_version": 1,
                    "call": self.call_number,
                    "requested_model": self.settings.model,
                    "provider_route": self.settings.provider,
                    "prompt_sha256": prompt_sha256,
                    "attempt": attempt,
                    "http_status": 200,
                    "seconds": round(time.monotonic() - started, 3),
                    "max_output_tokens": payload["max_tokens"],
                    "reasoning_effort": self.settings.reasoning_effort,
                    "response_format_type": payload.get("response_format", {}).get("type"),
                    **metadata,
                }
                try:
                    self._save_response(raw_body, attempt)
                except OSError as writing_error:
                    failure = ResponseFailure(
                        "EVIDENCE_WRITE_FAILED", "received response could not be persisted"
                    )
                    self._append_log(
                        {
                            **record,
                            "status": "INVALID_RESPONSE",
                            "failure_kind": failure.kind,
                            "retryable": False,
                        }
                    )
                    raise OpenRouterResponseError(failure, metadata) from writing_error
                if parse_error:
                    failure = ResponseFailure(
                        "MALFORMED_RESPONSE", "completion envelope is not valid UTF-8 JSON"
                    )
                    self._append_log(
                        {
                            **record,
                            "status": "INVALID_RESPONSE",
                            "failure_kind": failure.kind,
                            "retryable": False,
                        }
                    )
                    raise OpenRouterResponseError(failure, metadata) from parse_error
                try:
                    content = completion_text(
                        loaded,
                        model=self.settings.model,
                        provider=self.settings.provider,
                    )
                except ResponseFailure as failure:
                    received_error = OpenRouterResponseError(failure, metadata)
                    # Only received, accounted failures can use transport retries.
                    # The journal disables these and enforces its own ceilings.
                    can_retry = failure.retryable and known_cost(metadata["usage"].get("cost"))
                    self._append_log(
                        {
                            **record,
                            "status": "INVALID_RESPONSE",
                            "failure_kind": failure.kind,
                            "retryable": can_retry,
                        }
                    )
                    if can_retry and attempt <= self.settings.max_retries:
                        time.sleep(retry_delay)
                        continue
                    raise received_error from failure
                self._append_log({**record, "status": "SUCCESS"})
                # Successful text also enters response caches and research findings.
                # Apply the same exact-key policy as private wire evidence before
                # any caller can persist or publish an echoed authorization key.
                return content.replace(self.settings.api_key, "[REDACTED]")
            except OpenRouterResponseError:
                raise
            except urllib.error.HTTPError as error:
                last_error = self._error_detail(error).replace(self.settings.api_key, "[REDACTED]")
                http_status = error.code
                retryable = error.code in {408, 409, 429, 500, 502, 503, 504}
                retry_delay = self._retry_delay(attempt, error)
                self._append_log(
                    {
                        "schema_version": 1,
                        "status": "RETRY"
                        if error.code in {408, 409, 429, 500, 502, 503, 504}
                        and attempt <= self.settings.max_retries
                        else "FAILED",
                        "call": self.call_number,
                        "requested_model": self.settings.model,
                        "provider_route": self.settings.provider,
                        "prompt_sha256": prompt_sha256,
                        "attempt": attempt,
                        "http_status": error.code,
                        "seconds": round(time.monotonic() - started, 3),
                        "error_type": "HTTPError",
                        "error": last_error,
                        "retry_delay_seconds": retry_delay,
                    }
                )
                if error.code not in {408, 409, 429, 500, 502, 503, 504}:
                    break
            except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
                last_error = str(error)[:500].replace(self.settings.api_key, "[REDACTED]")
                http_status = received_http_status
                # An unreadable response, network interruption or local write
                # failure does not prove that the provider accepted no charge.
                retryable = False
                if received_http_status == 200:
                    persistence_failure = ResponseFailure(
                        "RESPONSE_PERSISTENCE_FAILED",
                        "received response could not be read or recorded durably",
                    )
                    # The typed exception retains evidence if logging also fails.
                    with suppress(OSError):
                        self._append_log(
                            {
                                "status": "INVALID_RESPONSE",
                                "failure_kind": persistence_failure.kind,
                                "http_status": 200,
                                "retryable": False,
                                **metadata,
                            }
                        )
                    raise OpenRouterResponseError(persistence_failure, metadata) from error
                self._append_log(
                    {
                        "schema_version": 1,
                        "status": "RETRY"
                        if retryable and attempt <= self.settings.max_retries
                        else "FAILED",
                        "call": self.call_number,
                        "requested_model": self.settings.model,
                        "provider_route": self.settings.provider,
                        "prompt_sha256": prompt_sha256,
                        "attempt": attempt,
                        "http_status": received_http_status,
                        "seconds": round(time.monotonic() - started, 3),
                        "error_type": type(error).__name__,
                        "retry_delay_seconds": retry_delay,
                    }
                )
                if not retryable:
                    break
            if attempt <= self.settings.max_retries:
                time.sleep(retry_delay)
        raise OpenRouterError(
            f"OpenRouter request failed after {attempt} attempt(s): {last_error}",
            retryable=retryable,
            http_status=http_status,
            retry_after_seconds=retry_delay,
        )


def validate_connection(repo_root: Path, config_path: Path | None = None) -> dict[str, Any]:
    settings = OpenRouterSettings.load(repo_root, config_path)
    client = OpenRouterClient(settings)
    content = client.complete(
        [{"role": "user", "content": "Return exactly the word OK."}],
        max_tokens=128,
    )
    if not content.strip():
        raise OpenRouterError("OpenRouter validation returned empty content")
    return {
        "model": settings.model,
        "provider_route": settings.provider,
        "response_nonempty": bool(content.strip()),
        "routing": {
            "allow_fallbacks": False,
            "require_parameters": True,
            "zdr": True,
            "data_collection": "deny",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--model-config",
        type=Path,
        default=Path("configs/models/gpt_oss_20b_openrouter.yaml"),
    )
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    if not args.validate:
        parser.error("--validate is required")
    try:
        result = validate_connection(args.repo_root.resolve(), args.model_config)
    except (OSError, ValueError, OpenRouterError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
