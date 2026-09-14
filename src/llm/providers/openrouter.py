"""Minimal OpenRouter client for the canonical GPT-OSS 20B research route."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.envfile import effective_env

CANONICAL_BASE_URL = "https://openrouter.ai/api/v1"
CANONICAL_MODEL = "openai/gpt-oss-20b"


def _provider_slug(value: object) -> str:
    return "".join(character for character in str(value).casefold() if character.isalnum())


class OpenRouterError(RuntimeError):
    """A bounded, secret-safe OpenRouter request failure."""


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
        )


class OpenRouterClient:
    """Synchronous one-request-at-a-time client with provenance-only logging."""

    def __init__(
        self,
        settings: OpenRouterSettings,
        call_log: Path | None = None,
        log_context: Mapping[str, Any] | None = None,
    ):
        self.settings = settings
        self.call_log = call_log
        self.log_context = dict(log_context or {})
        self.call_number = 0

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
            handle.write(json.dumps(merged, sort_keys=True, ensure_ascii=False) + "\n")

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            loaded = json.loads(error.read().decode("utf-8", errors="replace"))
            message = loaded.get("error", {}).get("message") if isinstance(loaded, dict) else None
            return str(message)[:500] if message else f"HTTP {error.code}"
        except (OSError, ValueError, AttributeError):
            return f"HTTP {error.code}"

    @staticmethod
    def _retry_delay(attempt: int, error: urllib.error.HTTPError | None = None) -> float:
        if error is not None:
            retry_after = error.headers.get("Retry-After")
            if retry_after:
                try:
                    return min(60.0, max(1.0, float(retry_after)))
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
        self.call_number += 1
        for attempt in range(1, self.settings.max_retries + 2):
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
                    loaded = json.loads(response.read().decode("utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("OpenRouter response is not an object")
                choices = loaded.get("choices")
                if not isinstance(choices, list) or not choices:
                    raise ValueError("OpenRouter response has no choices")
                choice = choices[0]
                if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
                    raise ValueError("OpenRouter response choice has no message")
                content = choice["message"].get("content")
                if not isinstance(content, str):
                    raise ValueError("OpenRouter response content is not text")
                returned_model = loaded.get("model")
                if returned_model != self.settings.model:
                    raise ValueError(
                        "returned model mismatch: expected "
                        f"{self.settings.model}, got {returned_model}"
                    )
                returned_provider = loaded.get("provider")
                if _provider_slug(returned_provider) != _provider_slug(self.settings.provider):
                    raise ValueError(
                        "returned provider mismatch: expected "
                        f"{self.settings.provider}, got {returned_provider}"
                    )
                self._append_log(
                    {
                        "schema_version": 1,
                        "status": "SUCCESS",
                        "call": self.call_number,
                        "request_id": loaded.get("id"),
                        "requested_model": self.settings.model,
                        "returned_model": returned_model,
                        "provider": returned_provider,
                        "provider_route": self.settings.provider,
                        "system_fingerprint": loaded.get("system_fingerprint"),
                        "prompt_sha256": prompt_sha256,
                        "attempt": attempt,
                        "http_status": 200,
                        "seconds": round(time.monotonic() - started, 3),
                        "usage": loaded.get("usage", {}),
                        "finish_reason": choice.get("finish_reason"),
                        "max_output_tokens": payload["max_tokens"],
                        "reasoning_effort": self.settings.reasoning_effort,
                        "response_format_type": payload.get("response_format", {}).get("type"),
                    }
                )
                return content
            except urllib.error.HTTPError as error:
                last_error = self._error_detail(error)
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
                        "retry_delay_seconds": retry_delay,
                    }
                )
                if error.code not in {408, 409, 429, 500, 502, 503, 504}:
                    break
            except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
                last_error = str(error)[:500]
                self._append_log(
                    {
                        "schema_version": 1,
                        "status": "RETRY" if attempt <= self.settings.max_retries else "FAILED",
                        "call": self.call_number,
                        "requested_model": self.settings.model,
                        "provider_route": self.settings.provider,
                        "prompt_sha256": prompt_sha256,
                        "attempt": attempt,
                        "http_status": None,
                        "seconds": round(time.monotonic() - started, 3),
                        "error_type": type(error).__name__,
                        "retry_delay_seconds": retry_delay,
                    }
                )
            if attempt <= self.settings.max_retries:
                time.sleep(retry_delay)
        raise OpenRouterError(f"OpenRouter request failed after {attempt} attempt(s): {last_error}")


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
