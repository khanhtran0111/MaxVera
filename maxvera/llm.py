"""Model-substitution transport with per-case budgets and durable request journals."""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path

from maxvera.contracts import Budgets, digest
from src.llm.providers.openrouter import (
    OpenRouterClient,
    OpenRouterError,
    OpenRouterResponseError,
    OpenRouterSettings,
)
from src.llm.providers.openrouter_response import known_cost, strict_json
from src.reproduction.common import atomic_json, read_jsonl


def _validate_output(raw, expected_kind):
    # A single Markdown fence is presentation, not another model answer. Keep
    # the original response for upstream parsing, hashes and billing evidence.
    text = raw.strip()
    lines = text.splitlines()
    if len(lines) >= 3 and lines[0].casefold() in {"```json", "```"} and lines[-1] == "```":
        text = "\n".join(lines[1:-1])
    parsed = strict_json(text)
    if expected_kind == "array" and (
        not isinstance(parsed, list) or any(not isinstance(entry, dict) for entry in parsed)
    ):
        raise ValueError("IRIS labels require a top-level array of objects")
    if expected_kind == "object" and not isinstance(parsed, dict):
        raise ValueError("IRIS context assessment requires a top-level object")


def _validate_cache(raw, expect_json, validate_json, expected_kind):
    if expect_json or validate_json:
        try:
            _validate_output(raw, expected_kind)
        except ValueError as error:
            raise RuntimeError("cached model response failed current JSON validation") from error


class JournaledClient:
    def __init__(
        self,
        settings: OpenRouterSettings,
        directory: Path,
        budgets: dict,
        *,
        scope: str = "reproduce-only",
    ):
        self.settings, self.directory, self.scope = settings, directory, scope
        self.budgets = {**dataclasses.asdict(Budgets()), **budgets}
        self.directory.mkdir(parents=True, exist_ok=True)
        self.log = directory / "llm_calls.jsonl"

    def _wait_for_request_slot(self, started: float) -> None:
        interval = self.settings.request_interval_seconds
        if not interval:
            return
        clock = self.directory / "request_clock.json"
        last_finished = json.loads(clock.read_text())["last_finished_at"] if clock.exists() else 0
        delay = max(0, last_finished + interval - time.time())
        if time.monotonic() - started + delay > self.budgets["timeout_case_s"]:
            raise RuntimeError("LLM time budget exhausted during request spacing")
        if delay:
            time.sleep(delay)
        if time.monotonic() - started > self.budgets["timeout_case_s"]:
            raise RuntimeError("LLM time budget exhausted during request spacing")

    def key(self, messages, expect_json, max_tokens, validate_json=False, expected_kind=None):
        settings = dataclasses.asdict(self.settings)
        settings.pop("api_key")
        return digest(
            {
                "messages": messages,
                "expect_json": expect_json,
                "validation_policy": {
                    "json": validate_json or expect_json,
                    "kind": expected_kind,
                    # Keep billing identity stable so previous PENDING/UNCERTAIN
                    # entries cannot be bypassed when output validation improves.
                    "version": "2.1",
                },
                "max_tokens": max_tokens,
                "settings": settings,
                "schema_version": "2.0",
                "scope": self.scope,
            }
        )

    def preflight(
        self,
        prompts,
        *,
        expect_json=False,
        max_tokens=None,
        validate_json=False,
        expected_kind=None,
    ):
        """Reject batches whose minimum uncached work cannot fit before paying.

        Retries and later stages still use the per-request hard ceilings. This
        check proves minimum capacity, not provider availability or final cost.
        """
        if (self.directory / "budget_stop.json").exists():
            raise RuntimeError("case budget stop is durable; inspect journal before adjudication")
        cap = min(max_tokens or self.settings.max_tokens, self.settings.max_tokens)
        uncached = {}
        for messages in prompts:
            key = self.key(messages, expect_json, cap, validate_json, expected_kind)
            folder = self.directory / "requests" / key
            journal = folder / "request.json"
            if journal.exists():
                state = json.loads(journal.read_text())
                if state["status"] == "SUCCESS":
                    if digest((folder / "response.txt").read_text()) != state["response_hash"]:
                        raise RuntimeError("cached model response checksum mismatch")
                    _validate_cache(
                        (folder / "response.txt").read_text(),
                        expect_json,
                        validate_json,
                        expected_kind,
                    )
                    continue
                if state["status"] in {"PENDING", "UNCERTAIN"}:
                    raise RuntimeError("remote charge uncertain; inspect journal before retry")
                raise RuntimeError(
                    "failed request requires a new run or explicit journal adjudication"
                )
            uncached[key] = len(json.dumps(messages, ensure_ascii=False).encode()) + 1024
        records = [
            json.loads(p.read_text()) for p in self.directory.glob("requests/*/attempt-*.json")
        ]
        count = len(uncached)
        plan = {
            "uncached_requests": count,
            "prior_attempts": len(records),
            "minimum_input_reservation": sum(uncached.values()),
            "minimum_output_reservation": count * cap,
        }
        requirements = (
            ("call", len(records) + count, "max_calls_per_case"),
            (
                "input-token",
                sum(r["input_reservation"] for r in records) + plan["minimum_input_reservation"],
                "max_input_tokens_per_case",
            ),
            (
                "output-token",
                sum(r["output_reservation"] for r in records) + plan["minimum_output_reservation"],
                "max_output_tokens_per_case",
            ),
        )
        for name, needed, ceiling in requirements:
            if count and needed > self.budgets[ceiling]:
                raise RuntimeError(
                    f"LLM batch {name} budget insufficient: needs at least {needed}, "
                    f"configured {self.budgets[ceiling]}; no batch requests sent"
                )
        # Persist the decision without reserving attempts or changing replay keys.
        with (self.directory / "batch_preflight.jsonl").open("a") as log:
            log.write(json.dumps(plan, sort_keys=True) + "\n")
        return plan

    def complete(
        self,
        messages,
        *,
        expect_json=False,
        max_tokens=None,
        validate_json=False,
        expected_kind=None,
    ):
        cap = min(max_tokens or self.settings.max_tokens, self.settings.max_tokens)
        stop = self.directory / "budget_stop.json"
        if stop.exists():
            raise RuntimeError("case budget stop is durable; inspect journal before adjudication")
        key = self.key(messages, expect_json, cap, validate_json, expected_kind)
        folder = self.directory / "requests" / key
        journal = folder / "request.json"
        if journal.exists():
            state = json.loads(journal.read_text())
            if state["status"] == "SUCCESS":
                raw = (folder / "response.txt").read_text()
                if digest(raw) != state["response_hash"]:
                    raise RuntimeError("cached model response checksum mismatch")
                _validate_cache(raw, expect_json, validate_json, expected_kind)
                return raw
            if state["status"] in {"PENDING", "UNCERTAIN"}:
                raise RuntimeError("remote charge uncertain; inspect journal before retry")
            raise RuntimeError("failed request requires a new run or explicit journal adjudication")
        folder.mkdir(parents=True)
        # UTF-8 bytes conservatively bound token count; include message/template allowance.
        input_reservation = len(json.dumps(messages, ensure_ascii=False).encode()) + 1024
        started = time.monotonic()
        for attempt in range(self.settings.max_retries + 1):
            records = [
                json.loads(p.read_text()) for p in self.directory.glob("requests/*/attempt-*.json")
            ]
            if len(records) >= self.budgets["max_calls_per_case"]:
                raise RuntimeError("LLM call budget exhausted")
            if (
                sum(r["input_reservation"] for r in records) + input_reservation
                > self.budgets["max_input_tokens_per_case"]
            ):
                raise RuntimeError("LLM input-token budget exhausted")
            if (
                sum(r["output_reservation"] for r in records) + cap
                > self.budgets["max_output_tokens_per_case"]
            ):
                raise RuntimeError("LLM output-token budget exhausted")
            if records and any(not known_cost(r.get("cost_usd")) for r in records):
                raise RuntimeError("LLM cost unknown; cannot guarantee case cost budget")
            if (
                sum(r.get("cost_usd", 0) or 0 for r in records)
                >= self.budgets["max_cost_usd_per_case"]
            ):
                raise RuntimeError("LLM cost budget exhausted")
            if time.monotonic() - started > self.budgets["timeout_case_s"]:
                raise RuntimeError("LLM time budget exhausted")
            # Wait before creating PENDING: no request has been sent during pacing.
            self._wait_for_request_slot(started)
            pending = {
                "status": "PENDING",
                "input_reservation": input_reservation,
                "output_reservation": cap,
                "cost_usd": None,
                "attempt": attempt + 1,
            }
            attempt_file = folder / f"attempt-{attempt + 1}.json"
            atomic_json(attempt_file, pending)
            atomic_json(journal, {"status": "PENDING", "key": key})
            # Persist exact prompt privately for audit; never authorization headers/settings key.
            atomic_json(folder / "prompt.json", {"messages": messages, "schema_version": "2.0"})
            client = OpenRouterClient(
                dataclasses.replace(self.settings, max_retries=0),
                self.log,
                response_directory=folder / f"provider-attempt-{attempt + 1}",
            )
            response_error = None
            raw = None
            try:
                try:
                    raw = client.complete(messages, expect_json=expect_json, max_tokens=cap)
                finally:
                    # Durable completion-based spacing also survives worker/stage restarts.
                    atomic_json(
                        self.directory / "request_clock.json", {"last_finished_at": time.time()}
                    )
            except OpenRouterResponseError as e:
                # HTTP 200 may still contain empty output or a provider failure.
                # Account for it before deciding whether a bounded retry is safe.
                response_error = e
            except Exception as e:
                if isinstance(e, OpenRouterError) and e.http_status == 429:
                    # An explicit rejection did not accept a completion. Count the
                    # attempt, release its token reservation, and retry the same prompt.
                    atomic_json(
                        attempt_file,
                        {
                            **pending,
                            "status": "RATE_LIMITED",
                            "http_status": 429,
                            "input_reservation": 0,
                            "output_reservation": 0,
                            "cost_usd": 0,
                        },
                    )
                    atomic_json(journal, {"status": "RATE_LIMITED", "key": key})
                    if attempt < self.settings.max_retries:
                        delay = max(
                            e.retry_after_seconds,
                            min(
                                self.settings.rate_limit_max_backoff_seconds,
                                self.settings.rate_limit_backoff_seconds * 2**attempt,
                            ),
                        )
                        if time.monotonic() - started + delay > self.budgets["timeout_case_s"]:
                            raise RuntimeError("LLM time budget exhausted during backoff") from e
                        time.sleep(delay)
                        continue
                    raise RuntimeError("provider rate limit persisted after bounded retry") from e
                atomic_json(journal, {"status": "UNCERTAIN", "key": key})
                raise RuntimeError("remote charge uncertain; inspect journal before retry") from e
            calls = read_jsonl(self.log)
            metadata = (
                response_error.response_metadata if response_error else (calls[-1] if calls else {})
            )
            usage = metadata.get("usage", {})
            usage = usage if isinstance(usage, dict) else {}
            cost = usage.get("cost")
            atomic_json(
                attempt_file,
                {
                    **pending,
                    "status": "INVALID_RESPONSE" if response_error else "RECEIVED",
                    "usage": usage,
                    "cost_usd": cost if known_cost(cost) else None,
                    "request_id": metadata.get("request_id"),
                    "finish_reason": metadata.get("finish_reason"),
                    "failure_kind": response_error.failure_kind if response_error else None,
                },
            )
            if raw is not None:
                (folder / f"response-{attempt + 1}.txt").write_text(raw)
            if not known_cost(cost):
                atomic_json(
                    journal,
                    {
                        "status": "UNCERTAIN",
                        "key": key,
                        "reason": "received response cost unknown or invalid",
                        "request_id": metadata.get("request_id"),
                        "failure_kind": response_error.failure_kind if response_error else None,
                    },
                )
                raise RuntimeError(
                    "LLM response cost unknown; remote charge uncertain; "
                    "inspect journal before retry"
                )
            if (
                sum(r.get("cost_usd", 0) or 0 for r in records) + cost
                > self.budgets["max_cost_usd_per_case"]
            ):
                atomic_json(journal, {"status": "BUDGET_EXCEEDED", "key": key})
                atomic_json(stop, {"status": "BUDGET_EXCEEDED", "request_key": key})
                raise RuntimeError("actual provider cost exceeded case budget; stopping")
            if response_error:
                atomic_json(
                    journal,
                    {
                        "status": "INVALID_RESPONSE",
                        "key": key,
                        "failure_kind": response_error.failure_kind,
                        "request_id": metadata.get("request_id"),
                    },
                )
                if response_error.retryable and attempt < self.settings.max_retries:
                    delay = min(
                        self.settings.rate_limit_max_backoff_seconds,
                        self.settings.rate_limit_backoff_seconds * 2**attempt,
                    )
                    if time.monotonic() - started + delay > self.budgets["timeout_case_s"]:
                        raise RuntimeError(
                            "LLM time budget exhausted during response backoff"
                        ) from response_error
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    f"LLM response {response_error.failure_kind}; "
                    "bounded retry exhausted or permanent failure; "
                    "inspect private response evidence"
                ) from response_error
            try:
                if calls and calls[-1].get("finish_reason") == "length":
                    raise ValueError("truncated response")
                if expect_json or validate_json:
                    _validate_output(raw, expected_kind)
            except ValueError:
                atomic_json(journal, {"status": "INVALID_JSON", "key": key})
                if attempt < self.settings.max_retries:
                    continue  # Same prompt, no invented answer or semantic repair.
                raise RuntimeError("invalid/truncated JSON after bounded retry") from None
            (folder / "response.txt").write_text(raw)
            atomic_json(
                journal,
                {
                    "status": "SUCCESS",
                    "response_hash": digest(raw),
                    "request_key": key,
                    "scope": self.scope,
                },
            )
            return raw
        raise RuntimeError("request budget exhausted")


class IrisProvider:
    """Preserve upstream prompt/batch semantics while replacing only model transport."""

    request = None
    settings = None
    _failure = None
    _failure_request = None

    @classmethod
    def configure(cls, request):
        cls.request = request
        cls._failure = None
        cls._failure_request = None
        cls.settings = OpenRouterSettings.load(Path(request["root"]), Path(request["model_config"]))

    @classmethod
    def raise_if_failed(cls):
        if (
            cls.request is not None
            and cls._failure_request is cls.request
            and cls._failure is not None
        ):
            raise RuntimeError(
                "LLM stage failed; inspect request journal before retry"
            ) from cls._failure

    def __init__(self, model_name="gpt-oss-20b-openrouter", logger=None, **kwargs):
        if self.request is None or self.settings is None:
            raise RuntimeError("IRIS provider not configured")
        self.model_name, self.logger, self.logprobs = model_name, logger, None
        self.client = JournaledClient(
            self.settings, Path(self.request["journal"]), self.request["budgets"]
        )
        self.max_tokens = min(
            int(kwargs.get("max_new_tokens", self.settings.max_tokens)), self.settings.max_tokens
        )

    def predict(self, prompt, expect_json=False, batch_size=0, no_progress_bar=False):
        type(self).raise_if_failed()
        try:
            return self._predict(prompt, expect_json, batch_size, no_progress_bar)
        except Exception as error:
            type(self)._failure = error
            type(self)._failure_request = self.request
            raise

    def _predict(self, prompt, expect_json=False, batch_size=0, no_progress_bar=False):
        expected_kind = "array" if self.request["stage"] == "llm_specs" else "object"

        def one(messages):
            return self.client.complete(
                messages,
                expect_json=expect_json,
                max_tokens=self.max_tokens,
                validate_json=True,
                expected_kind=expected_kind,
            )

        if batch_size > 0:
            self.client.preflight(
                prompt,
                expect_json=expect_json,
                max_tokens=self.max_tokens,
                validate_json=True,
                expected_kind=expected_kind,
            )
            return [one(messages) for messages in prompt]
        return one(prompt)
