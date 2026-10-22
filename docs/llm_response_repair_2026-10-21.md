# LLM response handling repair — 2026-10-21

Status: implemented and verified for the transport/journal scope. This report records the repair before the later user-authorized [full reproduction launch](reproduction_full_2026-10-21.md). The repair itself did not restart a pipeline. No completed full result or guarantee of120 successful builds is claimed.

## Cause and evidence

The stopped r4 DSpace case reached 57 successful API prompt journals, then failed with `OpenRouter response content is not text`. Previously, the transport validated content before retaining generation ID, usage or finish reason. The journal consequently received a generic exception and could only mark the request uncertain. Its historical raw response was never retained, so whether it was transient empty output, output exhaustion or another payload shape remains unknown.

A separate authorized diagnostic replayed the exact failed prompt without modifying the old run. It returned HTTP 200, valid text, finish reason `stop`, 1,979 completion tokens and cost USD 0.00022066. This establishes that the prompt is not deterministically rejected, not the exact subtype of the historical failure.

Official contracts checked:

- [OpenRouter errors and debugging](https://openrouter.ai/docs/api_reference/errors-and-debugging): HTTP 200 can still carry generation errors; no-content results can be charged. Length-finished empty content may exhaust the token cap on reasoning.
- [Chat completion API](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion): completion message, finish reason and usage envelopes.

## Implementation

`src/llm/providers/openrouter_response.py` separates envelope metadata extraction, completion classification and strict output JSON parsing. Received-response metadata is captured before content validation. Public provenance uses bounded scalar metadata and whitelisted usage fields; private raw HTTP bodies are retained separately with mode 0600 in directories with mode 0700. Known credential echoes are redacted. Provider content remains private and is never converted into invented model labels.

`src/llm/providers/openrouter.py` raises `OpenRouterResponseError` with generation/billing evidence rather than throwing it away. It accepts text and ordered text-only content blocks, preserving exact fragment concatenation. It rejects mixed/unsupported blocks, route drift, refusals, unexpected tool calls, malformed shapes, provider errors and truncated output. Transient empty/provider/truncated completions may retry only when actual cost is known, within the configured retry count. JSON/UTF-8/network/provenance-write failures with unresolved billing no longer trigger generic automatic resends, including for raw-client consumers outside the journal. Evidence-write failures retain known usage in typed exceptions and do not resend a paid request.

`maxvera/llm.py` accounts for received unusable completions before deciding to retry. Every retry retains the prompt, model, route and sampling settings, counts toward call/input/output reservations, respects pacing/backoff/time/cost limits, and preserves each response's charge. Missing, negative, boolean, string, NaN or infinite costs stop as `UNCERTAIN`; even valid-looking output with unknown cost cannot become a successful cache entry. Actual overspend creates the existing durable budget stop. The dollar ceiling remains a post-response application stop, not a provider prepaid guarantee.

Existing request identity version 2.1 is preserved to honor old PENDING/UNCERTAIN journals, including a crash after received usage was written but before the request transitioned to SUCCESS. Cached output is checksum-verified and revalidated against current JSON rules before replay or batch preflight. Old scientific run manifests and journals were not rewritten.

Model JSON rejects duplicate keys, NaN/Infinity (including exponent overflow), excessive parser nesting and non-object members of IRIS label arrays. Context output still follows upstream IRIS field semantics; this repair does not redesign its assessment or label algorithms.

No model/provider/output-cap/runtime configuration was changed by this repair. Output remains capped at the configured 2,048 tokens. Repeated truncation, permanent provider/refusal/schema errors or unknown billing can still stop a run rather than report false success.

## Verification

80 HTTP-boundary/journal regression cases were added in `tests/pipeline/test_llm_response_recovery.py`. They exercise real transport and journal behavior with only the remote wire replaced: empty/null/whitespace/text blocks, unsupported mixtures, malformed shape/types, HTTP 200 body/choice errors, finish reasons, refusals/tools, route drift, cost boundaries and invalid costs, retry/reservation/time ceilings, raw JSON/UTF-8, cache identity/replay, old pending crash boundaries, private file permissions, credential echoes, metadata promotion, duplicate JSON keys and non-finite values. Existing raw-client JSON-retry tests were updated to the intentional stop-on-unknown-billing policy.

Independent review reproduced three Important findings: duplicate raw-client retries on unknown billing/local write failure, bypass of old pending identity, and nested metadata leaking into provenance. Each received a failing regression before its fix. No findings were left unaddressed. An additional 72 malformed-envelope field mutations produced classified failures or valid output without unexpected exceptions.

Final default validation:

- `pytest -q`: **381 passed, 2 opt-in CodeQL integration fixtures skipped**, 18.63 seconds.
- `ruff check .`: all checks passed.
- `mypy`: no issues in 126 configured source files.

Detailed test/lint/type logs and pre-change snapshots/diffs are under `logs/llm_response_repair_20261021/`.

## Authorized live checks

These are isolated diagnostics, not a smoke/benchmark run. Credentials came from the existing environment loader; none were printed. The two successful diagnostics also verified cached replay without another API request.

| Diagnostic | Actual outcome | Attempts | Reported cost USD |
| --- | --- | ---: | ---: |
| Original failed DSpace prompt, pre-repair raw diagnostic | HTTP 200, text, `stop` | 1 | 0.00022066 |
| Same DSpace API prompt through repaired JournaledClient | Success; cache replay made no request | 1 | 0.00016286 |
| Historical Spark context prompt through repaired JournaledClient | Success; cache replay made no request | 1 | 0.00004182 |
| Intentional max_tokens=1 diagnostic | Received `length`; classified TRUNCATED_RESPONSE; recorded charge; stopped | 1 | 0.00000166 |

Total reported cost: **USD 0.00042700**. The forced truncation is an expected diagnostic failure, not a scientific result or a claim that the historical null-content subtype was reproduced. Full live evidence and request IDs are in `live_repaired_summary.json` and private per-attempt HTTP bodies.

## Next execution decision

The original transport/journal defect has targeted regression coverage, full default-suite coverage and live API evidence. Repeating the long two-case smoke solely to validate this response-handling repair is not required by the available evidence; a production reproduction still exercises distinct build, CodeQL, dependency, storage and provider risks. It must use a new run ID because implementation fingerprints changed.

At repair completion, the user requested confirmation before moving on to reproduction; no pipeline was started as part of the repair. The user subsequently authorized the [new full run](reproduction_full_2026-10-21.md). Previously recorded execution limits remain: 118 other project builds were not exercised by the stopped smoke, full disk use is not proven, and four obsolete Spring EBR metadata coordinates were quarantined because an authoritative available source was not obtained. These are separate from the repaired response transport.
