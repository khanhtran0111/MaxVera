"""Authenticated, low-cost OpenRouter preflight for a run.

Checks: authentication (/key), model endpoint list, pinned provider availability and
supported parameters, ZDR eligibility, and one real chat completion through the exact
production client (provider routing, decoding parameters, accounting). Writes
<run_dir>/manifests/api_preflight.json. Never prints or stores the API key.

Exit codes: 0 ok, 77 configuration error (do not run experiments).
"""
import argparse
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(__file__))
from common import IRIS_SRC, IRIS_DIR, dump_json, now_iso  # noqa: E402

sys.path.insert(0, IRIS_DIR)
from src.models.openrouter_client import (  # noqa: E402
    OpenRouterClient, OpenRouterError, load_api_key, load_config, EXIT_CONFIG_ERROR)

REQUIRED_PARAMS = ["temperature", "top_p", "seed", "max_tokens", "reasoning_effort"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()

    cfg = load_config()
    out = {"ts": now_iso(), "base_url": cfg["base_url"], "model": cfg["model"],
           "provider_config": cfg["provider"], "decoding": cfg["decoding"], "checks": {}}
    errors = []

    try:
        key = load_api_key()
    except OpenRouterError as e:
        print(f"[preflight] {e}")
        sys.exit(EXIT_CONFIG_ERROR)
    headers = {"Authorization": f"Bearer {key}"}
    base = cfg["base_url"].rstrip("/")

    # 1. Authentication + account limits (the 'label' field may echo a masked key; drop it)
    r = requests.get(f"{base}/key", headers=headers, timeout=30)
    if r.status_code != 200:
        errors.append(f"auth check failed: HTTP {r.status_code}")
        out["checks"]["auth"] = {"ok": False, "status": r.status_code}
    else:
        d = r.json().get("data", {})
        out["checks"]["auth"] = {"ok": True, **{k: d.get(k) for k in
                                 ("limit", "limit_remaining", "usage", "is_free_tier", "rate_limit")}}

    # 2. Endpoint list for the model, pinned provider + parameters
    r = requests.get(f"{base}/models/{cfg['model']}/endpoints", headers=headers, timeout=30)
    eps = r.json().get("data", {}).get("endpoints", []) if r.status_code == 200 else []
    want = cfg["provider"]["expected_provider_name"]
    pinned = [e for e in eps if e.get("provider_name") == want]
    if not pinned:
        errors.append(f"provider {want} does not serve {cfg['model']}")
        out["checks"]["endpoint"] = {"ok": False, "available_providers": sorted({e.get('provider_name') for e in eps})}
    else:
        e = pinned[0]
        missing = [p for p in REQUIRED_PARAMS if p not in (e.get("supported_parameters") or [])]
        ok = not missing and e.get("status", -1) == 0
        if missing:
            errors.append(f"provider {want} lacks parameters {missing}")
        out["checks"]["endpoint"] = {
            "ok": ok, "tag": e.get("tag"), "quantization": e.get("quantization"), "status": e.get("status"),
            "context_length": e.get("context_length"), "max_completion_tokens": e.get("max_completion_tokens"),
            "pricing": e.get("pricing"), "supported_parameters": e.get("supported_parameters"),
            "missing_required_parameters": missing,
        }

    # 3. ZDR eligibility
    r = requests.get(f"{base}/endpoints/zdr", headers=headers, timeout=30)
    zdr = r.json().get("data", []) if r.status_code == 200 else []
    zdr_ok = any(z.get("model_id") == cfg["model"] and z.get("provider_name") == want for z in zdr)
    out["checks"]["zdr"] = {"ok": zdr_ok}
    if cfg["provider"]["zdr"] and not zdr_ok:
        errors.append(f"{want} endpoint for {cfg['model']} is not ZDR-eligible")

    # 4. One real completion through the production client
    if not errors:
        client = OpenRouterClient(cfg, api_key=key, context={"project": "__preflight__"})
        try:
            content = client.chat([
                {"role": "system", "content": "You are a test endpoint. Reply with JSON only."},
                # The nonce makes every preflight a live request (never served from the response cache)
                {"role": "user", "content": f'Preflight {now_iso()}. Return exactly this JSON list: [{{"ok": true}}]'},
            ], tag="preflight")
            with open(cfg["accounting"]["ledger_path"]) as f:
                last = [json.loads(l) for l in f if l.strip()][-1]
            out["checks"]["completion"] = {
                "ok": last.get("provider") == want and last.get("returned_model") in cfg["accepted_returned_model_ids"],
                "content": content[:200], **{k: last.get(k) for k in (
                    "returned_model", "provider", "finish_reason", "prompt_tokens", "completion_tokens",
                    "reasoning_tokens", "cost_usd", "latency_s", "json_valid", "http_retries", "cache_hit")}}
            if not out["checks"]["completion"]["ok"]:
                errors.append("completion served by unexpected provider/model")
        except OpenRouterError as e:
            errors.append(f"completion failed: {e}")
            out["checks"]["completion"] = {"ok": False, "error": str(e)}

    out["ok"] = not errors
    out["errors"] = errors
    dump_json(out, os.path.join(args.run_dir, "manifests", "api_preflight.json"))
    print(json.dumps({k: v for k, v in out.items() if k != "provider_config"}, indent=2))
    sys.exit(0 if not errors else EXIT_CONFIG_ERROR)


if __name__ == "__main__":
    main()
